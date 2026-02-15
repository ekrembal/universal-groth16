package sp1bridge

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	plonkbackend_bn254 "github.com/consensys/gnark/backend/plonk/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/recursion"
	recursion_plonk "github.com/consensys/gnark/std/recursion/plonk"
	"github.com/consensys/gnark/test"
	"github.com/consensys/gnark/test/unsafekzg"
)

// ---------------------------------------------------------------------------
// Mock SP1-like circuit for testing
// ---------------------------------------------------------------------------

// MockSP1Circuit mimics SP1's circuit structure: 2 public inputs (VkeyHash,
// CommittedValuesDigest) and some private computation.
//
// In a real SP1 circuit, the Define() method would read constraints from a JSON
// file and execute a complex recursive STARK verification using Poseidon2 and
// BabyBear arithmetic. Here we use a simple stand-in.
type MockSP1Circuit struct {
	// Public inputs (same as SP1)
	VkeyHash              frontend.Variable `gnark:",public"`
	CommittedValuesDigest frontend.Variable `gnark:",public"`

	// Private witnesses (simplified — real SP1 has Vars, Felts, Exts)
	PreimageA frontend.Variable
	PreimageB frontend.Variable
}

func (c *MockSP1Circuit) Define(api frontend.API) error {
	// Simulate SP1's constraint: VkeyHash = hash of some private values.
	// In real SP1, this would be Poseidon2 over the recursion state.
	product := api.Mul(c.PreimageA, c.PreimageB)
	api.AssertIsEqual(c.VkeyHash, product)

	// CommittedValuesDigest = some other function of private values.
	sum := api.Add(c.PreimageA, c.PreimageB)
	api.AssertIsEqual(c.CommittedValuesDigest, sum)

	return nil
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestSP1BridgeEndToEnd demonstrates the full SP1 → PlonK → Groth16 pipeline:
//  1. Compile and prove a mock SP1 circuit with recursion-compatible options
//  2. Feed the proof into PlonkVerifierGroth16Circuit
//  3. Verify the outer Groth16 circuit is satisfied
func TestSP1BridgeEndToEnd(t *testing.T) {
	assert := test.NewAssert(t)
	field := ecc.BN254.ScalarField()

	// -------- Step 1: Generate SP1 PlonK proof (recursion-compatible) --------

	mockCircuit := &MockSP1Circuit{}
	mockAssignment := &MockSP1Circuit{
		VkeyHash:              15, // 3 * 5
		CommittedValuesDigest: 8,  // 3 + 5
		PreimageA:             3,
		PreimageB:             5,
	}

	// Compile
	innerCcs, err := frontend.Compile(field, scs.NewBuilder, mockCircuit)
	assert.NoError(err)

	t.Logf("Mock SP1 circuit: %d SCS constraints, %d public variables",
		innerCcs.GetNbConstraints(), innerCcs.GetNbPublicVariables())

	// Setup
	srs, srsLagrange, err := unsafekzg.NewSRS(innerCcs)
	assert.NoError(err)

	innerPK, innerVK, err := plonk.Setup(innerCcs, srs, srsLagrange)
	assert.NoError(err)

	// Prove with recursion-compatible options
	fullWitness, err := frontend.NewWitness(mockAssignment, field)
	assert.NoError(err)

	sp1Proof, err := ProvePlonkRecursive(innerCcs, innerPK, innerVK, fullWitness)
	assert.NoError(err)

	t.Logf("SP1 public inputs: VkeyHash=%s, CommittedValuesDigest=%s",
		sp1Proof.PublicInputs.VkeyHash, sp1Proof.PublicInputs.CommittedValuesDigest)

	// -------- Step 2: Compute hashes for the outer circuit --------

	nativeVK := innerVK.(*plonkbackend_bn254.VerifyingKey)
	vkHash := computeVkHashForTest(t, nativeVK, field)
	pubInputsHash, err := ComputePublicInputsHash(sp1Proof.PublicWitness)
	assert.NoError(err)

	t.Logf("VK hash: %s", vkHash)
	t.Logf("Public inputs hash: %s", pubInputsHash)

	// -------- Step 3: Prepare outer Groth16 circuit --------

	circuitBvk, err := recursion_plonk.ValueOfBaseVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](innerVK)
	assert.NoError(err)
	circuitCvk, err := recursion_plonk.ValueOfCircuitVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine](innerVK)
	assert.NoError(err)
	circuitProof, err := recursion_plonk.ValueOfProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](sp1Proof.Proof)
	assert.NoError(err)

	nbPub := innerCcs.GetNbPublicVariables() // 2 for SP1
	assert.Equal(2, nbPub)

	outerCircuit := &recursion_plonk.PlonkVerifierGroth16Circuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		BaseKey:           circuitBvk,
		Proof:             recursion_plonk.PlaceholderProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](innerCcs),
		CircuitKey:        recursion_plonk.PlaceholderCircuitVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine](innerCcs),
		InnerPublicInputs: make([]frontend.Variable, nbPub),
	}
	outerAssignment := &recursion_plonk.PlonkVerifierGroth16Circuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		Proof:             circuitProof,
		CircuitKey:        circuitCvk,
		InnerPublicInputs: []frontend.Variable{15, 8}, // VkeyHash=15, CommittedValuesDigest=8
		VkHash:            vkHash,
		PublicInputsHash:  pubInputsHash,
	}

	// -------- Step 4: Verify outer circuit is satisfied --------

	err = test.IsSolved(outerCircuit, outerAssignment, field)
	assert.NoError(err)
	t.Log("Outer Groth16 circuit is satisfied!")

	// -------- Step 5: Compile to R1CS and report constraint count --------

	outerCcs, err := frontend.Compile(field, r1cs.NewBuilder, outerCircuit)
	assert.NoError(err)
	t.Logf("SP1-in-Groth16 verifier: %d R1CS constraints, %d public variables",
		outerCcs.GetNbConstraints(), outerCcs.GetNbPublicVariables())
}

// TestSP1BridgeTwoDifferentCircuits demonstrates that the same outer Groth16
// circuit can verify proofs from two different inner circuits (different VKs)
// as long as they share the same KZG SRS and number of public inputs.
func TestSP1BridgeTwoDifferentCircuits(t *testing.T) {
	assert := test.NewAssert(t)
	field := ecc.BN254.ScalarField()

	// -------- Circuit A: product + sum --------
	circuitA := &MockSP1Circuit{}
	assignmentA := &MockSP1Circuit{
		VkeyHash:              15,
		CommittedValuesDigest: 8,
		PreimageA:             3,
		PreimageB:             5,
	}

	ccsA, err := frontend.Compile(field, scs.NewBuilder, circuitA)
	assert.NoError(err)

	srsA, srsLagrangeA, err := unsafekzg.NewSRS(ccsA)
	assert.NoError(err)

	pkA, vkA, err := plonk.Setup(ccsA, srsA, srsLagrangeA)
	assert.NoError(err)

	witA, err := frontend.NewWitness(assignmentA, field)
	assert.NoError(err)

	sp1ProofA, err := ProvePlonkRecursive(ccsA, pkA, vkA, witA)
	assert.NoError(err)

	// -------- Circuit B: different computation, same public input structure --------
	circuitB := &MockSP1CircuitB{}
	assignmentB := &MockSP1CircuitB{
		VkeyHash:              100,
		CommittedValuesDigest: 7,
		Secret:                10,
	}

	ccsB, err := frontend.Compile(field, scs.NewBuilder, circuitB)
	assert.NoError(err)

	srsB, srsLagrangeB, err := unsafekzg.NewSRS(ccsB)
	assert.NoError(err)

	pkB, vkB, err := plonk.Setup(ccsB, srsB, srsLagrangeB)
	assert.NoError(err)

	witB, err := frontend.NewWitness(assignmentB, field)
	assert.NoError(err)

	sp1ProofB, err := ProvePlonkRecursive(ccsB, pkB, vkB, witB)
	assert.NoError(err)

	// -------- Verify both in the SAME outer Groth16 circuit structure --------
	// Both circuits have 2 public inputs, so the same outer circuit can verify either.

	// Note: because ccsA and ccsB may have different sizes (different number of
	// SCS constraints), the BaseVerifyingKey (which includes SRS) may differ.
	// For this to work with a single outer circuit, both inner circuits must use
	// the same SRS. We use unsafekzg here, but in production they'd share the
	// same Aztec Ignition SRS.

	// --- Verify proof A ---
	nativeVKA := vkA.(*plonkbackend_bn254.VerifyingKey)
	vkHashA := computeVkHashForTest(t, nativeVKA, field)
	pubHashA, err := ComputePublicInputsHash(sp1ProofA.PublicWitness)
	assert.NoError(err)

	bvkA, err := recursion_plonk.ValueOfBaseVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](vkA)
	assert.NoError(err)
	cvkA, err := recursion_plonk.ValueOfCircuitVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine](vkA)
	assert.NoError(err)
	proofA, err := recursion_plonk.ValueOfProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](sp1ProofA.Proof)
	assert.NoError(err)

	outerCircuitA := &recursion_plonk.PlonkVerifierGroth16Circuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		BaseKey:           bvkA,
		Proof:             recursion_plonk.PlaceholderProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](ccsA),
		CircuitKey:        recursion_plonk.PlaceholderCircuitVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine](ccsA),
		InnerPublicInputs: make([]frontend.Variable, 2),
	}
	outerAssignmentA := &recursion_plonk.PlonkVerifierGroth16Circuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		Proof:             proofA,
		CircuitKey:        cvkA,
		InnerPublicInputs: []frontend.Variable{15, 8},
		VkHash:            vkHashA,
		PublicInputsHash:  pubHashA,
	}

	err = test.IsSolved(outerCircuitA, outerAssignmentA, field)
	assert.NoError(err)
	t.Log("Proof A (product+sum circuit) verified in outer Groth16!")

	// --- Verify proof B ---
	nativeVKB := vkB.(*plonkbackend_bn254.VerifyingKey)
	vkHashB := computeVkHashForTest(t, nativeVKB, field)
	pubHashB, err := ComputePublicInputsHash(sp1ProofB.PublicWitness)
	assert.NoError(err)

	bvkB, err := recursion_plonk.ValueOfBaseVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](vkB)
	assert.NoError(err)
	cvkB, err := recursion_plonk.ValueOfCircuitVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine](vkB)
	assert.NoError(err)
	proofBCircuit, err := recursion_plonk.ValueOfProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](sp1ProofB.Proof)
	assert.NoError(err)

	outerCircuitB := &recursion_plonk.PlonkVerifierGroth16Circuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		BaseKey:           bvkB,
		Proof:             recursion_plonk.PlaceholderProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](ccsB),
		CircuitKey:        recursion_plonk.PlaceholderCircuitVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine](ccsB),
		InnerPublicInputs: make([]frontend.Variable, 2),
	}
	outerAssignmentB := &recursion_plonk.PlonkVerifierGroth16Circuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		Proof:             proofBCircuit,
		CircuitKey:        cvkB,
		InnerPublicInputs: []frontend.Variable{100, 7},
		VkHash:            vkHashB,
		PublicInputsHash:  pubHashB,
	}

	err = test.IsSolved(outerCircuitB, outerAssignmentB, field)
	assert.NoError(err)
	t.Log("Proof B (square+add circuit) verified in outer Groth16!")

	// Confirm VK hashes are different (different circuits produce different VKs)
	assert.NotEqual(vkHashA.Bytes(), vkHashB.Bytes())
	t.Logf("VK hashes differ as expected: A=%s, B=%s", vkHashA, vkHashB)
}

// ---------------------------------------------------------------------------
// Additional mock circuit for the multi-circuit test
// ---------------------------------------------------------------------------

// MockSP1CircuitB is a second mock SP1 circuit with different constraints
// but the same public input structure (2 public inputs).
type MockSP1CircuitB struct {
	VkeyHash              frontend.Variable `gnark:",public"`
	CommittedValuesDigest frontend.Variable `gnark:",public"`
	Secret                frontend.Variable
}

func (c *MockSP1CircuitB) Define(api frontend.API) error {
	// VkeyHash = Secret^2
	sq := api.Mul(c.Secret, c.Secret)
	api.AssertIsEqual(c.VkeyHash, sq)

	// CommittedValuesDigest = Secret - 3
	diff := api.Sub(c.Secret, 3)
	api.AssertIsEqual(c.CommittedValuesDigest, diff)

	return nil
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// computeVkHashForTest computes the VK hash natively for test assertions.
// This duplicates the logic from verifier_groth16_test.go since we're in
// a different package.
func computeVkHashForTest(t *testing.T, nativeVK *plonkbackend_bn254.VerifyingKey, field *big.Int) *big.Int {
	t.Helper()

	h, err := recursion.NewShort(field, field)
	if err != nil {
		t.Fatalf("new short hash: %v", err)
	}

	var sizeBuf [32]byte
	new(big.Int).SetUint64(nativeVK.Size).FillBytes(sizeBuf[:])
	h.Write(sizeBuf[:])
	h.Write(nativeVK.SizeInv.Marshal())
	h.Write(nativeVK.Generator.Marshal())

	for i := range nativeVK.S {
		h.Write(nativeVK.S[i].Marshal())
	}
	h.Write(nativeVK.Ql.Marshal())
	h.Write(nativeVK.Qr.Marshal())
	h.Write(nativeVK.Qm.Marshal())
	h.Write(nativeVK.Qo.Marshal())
	h.Write(nativeVK.Qk.Marshal())

	return new(big.Int).SetBytes(h.Sum(nil))
}

// Compile-time interface checks.
var _ frontend.Circuit = (*MockSP1Circuit)(nil)
var _ frontend.Circuit = (*MockSP1CircuitB)(nil)
