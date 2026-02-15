package risc0bridge

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	plonkbackend_bn254 "github.com/consensys/gnark/backend/plonk/bn254"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/recursion"
	recursion_groth16 "github.com/consensys/gnark/std/recursion/groth16"
	recursion_plonk "github.com/consensys/gnark/std/recursion/plonk"
	"github.com/consensys/gnark/test"
	"github.com/consensys/gnark/test/unsafekzg"
)

// ---------------------------------------------------------------------------
// Mock RISC0-like Groth16 circuit for testing
// ---------------------------------------------------------------------------

// MockRISC0Circuit simulates a RISC0 Circom Groth16 circuit.
// In reality, this would be the STARK verifier (~8M constraints).
// For testing, we use a simple circuit with 1 public input.
type MockRISC0Circuit struct {
	// Private
	Secret frontend.Variable
	// Public
	JournalHash frontend.Variable `gnark:",public"`
}

func (c *MockRISC0Circuit) Define(api frontend.API) error {
	// JournalHash = Secret^2 + 1
	sq := api.Mul(c.Secret, c.Secret)
	result := api.Add(sq, 1)
	api.AssertIsEqual(c.JournalHash, result)
	return nil
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestGroth16VerifierCircuit_IsSolved verifies that the Groth16VerifierCircuit
// correctly verifies a Groth16 proof using test.IsSolved.
func TestGroth16VerifierCircuit_IsSolved(t *testing.T) {
	assert := test.NewAssert(t)
	field := ecc.BN254.ScalarField()

	// -------- Step 1: Generate a Groth16 proof --------

	innerCircuit := &MockRISC0Circuit{}
	innerAssignment := &MockRISC0Circuit{
		Secret:      7,
		JournalHash: 50, // 7^2 + 1 = 50
	}

	innerCcs, err := frontend.Compile(field, r1cs.NewBuilder, innerCircuit)
	assert.NoError(err)
	t.Logf("Mock RISC0 Groth16 circuit: %d R1CS constraints, %d public variables",
		innerCcs.GetNbConstraints(), innerCcs.GetNbPublicVariables())

	innerPK, innerVK, err := groth16.Setup(innerCcs)
	assert.NoError(err)

	innerWitness, err := frontend.NewWitness(innerAssignment, field)
	assert.NoError(err)

	innerProof, err := groth16.Prove(innerCcs, innerPK, innerWitness)
	assert.NoError(err)

	innerPubWitness, err := innerWitness.Public()
	assert.NoError(err)

	err = groth16.Verify(innerProof, innerVK, innerPubWitness)
	assert.NoError(err)
	t.Log("Native Groth16 proof verified!")

	// -------- Step 2: Verify Groth16 proof inside PlonK circuit --------

	// Convert VK to circuit type (baked into circuit).
	circuitVK, err := recursion_groth16.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](innerVK)
	assert.NoError(err)

	// Convert proof.
	circuitProof, err := recursion_groth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](innerProof)
	assert.NoError(err)

	// Number of public inputs (excluding the "one" wire for Groth16).
	nbPub := innerCcs.GetNbPublicVariables() - 1 // 1 for our mock circuit
	assert.Equal(1, nbPub)

	// Build the outer PlonK circuit with baked-in VK.
	outerCircuit := &Groth16VerifierCircuit{
		InnerVK:           circuitVK,
		InnerProof:        recursion_groth16.PlaceholderProof[sw_bn254.G1Affine, sw_bn254.G2Affine](innerCcs),
		InnerPublicInputs: make([]frontend.Variable, nbPub),
	}

	outerAssignment := &Groth16VerifierCircuit{
		InnerProof:        circuitProof,
		InnerPublicInputs: []frontend.Variable{50}, // JournalHash = 50
	}

	err = test.IsSolved(outerCircuit, outerAssignment, field)
	assert.NoError(err)
	t.Log("Groth16VerifierCircuit is satisfied!")
}

// TestWrapGroth16InPlonk demonstrates the full pipeline: Groth16 → PlonK → Groth16.
// This is the core RISC0 integration flow.
func TestWrapGroth16InPlonk(t *testing.T) {
	assert := test.NewAssert(t)
	field := ecc.BN254.ScalarField()

	// -------- Step 1: Generate a Groth16 proof (simulating RISC0) --------

	innerCircuit := &MockRISC0Circuit{}
	innerAssignment := &MockRISC0Circuit{
		Secret:      7,
		JournalHash: 50,
	}

	innerCcs, err := frontend.Compile(field, r1cs.NewBuilder, innerCircuit)
	assert.NoError(err)

	innerPK, innerVK, err := groth16.Setup(innerCcs)
	assert.NoError(err)

	innerWitness, err := frontend.NewWitness(innerAssignment, field)
	assert.NoError(err)

	innerProof, err := groth16.Prove(innerCcs, innerPK, innerWitness)
	assert.NoError(err)

	innerPubWitness, err := innerWitness.Public()
	assert.NoError(err)

	err = groth16.Verify(innerProof, innerVK, innerPubWitness)
	assert.NoError(err)

	// -------- Step 2: Wrap Groth16 in PlonK --------

	// First compile to get the PlonK circuit size, then generate SRS.
	circuitVK, err := recursion_groth16.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](innerVK)
	assert.NoError(err)

	nbPub := innerCcs.GetNbPublicVariables() - 1
	placeholderCircuit := &Groth16VerifierCircuit{
		InnerVK:           circuitVK,
		InnerProof:        recursion_groth16.PlaceholderProof[sw_bn254.G1Affine, sw_bn254.G2Affine](innerCcs),
		InnerPublicInputs: make([]frontend.Variable, nbPub),
	}

	plonkCS, err := frontend.Compile(field, scs.NewBuilder, placeholderCircuit)
	assert.NoError(err)
	t.Logf("Groth16 verifier PlonK circuit: %d SCS constraints, %d public variables",
		plonkCS.GetNbConstraints(), plonkCS.GetNbPublicVariables())

	plonkSrs, plonkSrsLagrange, err := unsafekzg.NewSRS(plonkCS)
	assert.NoError(err)

	result, err := WrapGroth16InPlonk(innerCcs, innerVK, innerProof, innerPubWitness,
		plonkSrs, plonkSrsLagrange)
	assert.NoError(err)
	t.Log("Groth16 proof wrapped in PlonK successfully!")

	// -------- Step 3: Feed PlonK proof into the universal wrapper --------

	plonkNativeVK := result.PlonkVK.(*plonkbackend_bn254.VerifyingKey)
	vkHash := computeVkHashForTest(t, plonkNativeVK, field)
	pubInputsHash := computePubInputsHashForTest(t, result.PlonkPubWitness, field)

	bvk, err := recursion_plonk.ValueOfBaseVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](result.PlonkVK)
	assert.NoError(err)
	cvk, err := recursion_plonk.ValueOfCircuitVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine](result.PlonkVK)
	assert.NoError(err)
	plonkProof, err := recursion_plonk.ValueOfProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](result.PlonkProof)
	assert.NoError(err)

	plonkNbPub := result.PlonkCS.GetNbPublicVariables()

	outerCircuit := &recursion_plonk.PlonkVerifierGroth16Circuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		BaseKey:           bvk,
		Proof:             recursion_plonk.PlaceholderProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](result.PlonkCS),
		CircuitKey:        recursion_plonk.PlaceholderCircuitVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine](result.PlonkCS),
		InnerPublicInputs: make([]frontend.Variable, plonkNbPub),
	}

	outerAssignment := &recursion_plonk.PlonkVerifierGroth16Circuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		Proof:             plonkProof,
		CircuitKey:        cvk,
		InnerPublicInputs: []frontend.Variable{50}, // The Groth16 public input passes through
		VkHash:            vkHash,
		PublicInputsHash:  pubInputsHash,
	}

	err = test.IsSolved(outerCircuit, outerAssignment, field)
	assert.NoError(err)
	t.Log("Full RISC0 pipeline: Groth16 → PlonK → Groth16 wrapper verified!")
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

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

func computePubInputsHashForTest(t *testing.T, pubWitness witness.Witness, field *big.Int) *big.Int {
	t.Helper()

	vec := pubWitness.Vector()
	frVec, ok := vec.(fr_bn254.Vector)
	if !ok {
		t.Fatalf("expected fr_bn254.Vector, got %T", vec)
	}

	h, err := recursion.NewShort(field, field)
	if err != nil {
		t.Fatalf("new short hash: %v", err)
	}

	buf := make([]byte, (field.BitLen()+7)/8)
	for i := range frVec {
		bi := new(big.Int)
		frVec[i].BigInt(bi)
		bi.FillBytes(buf)
		h.Write(buf)
	}

	return new(big.Int).SetBytes(h.Sum(nil))
}

var _ frontend.Circuit = (*MockRISC0Circuit)(nil)
