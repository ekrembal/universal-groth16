//go:build integrations

package e2e

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
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

	"github.com/ekrembal/universal-groth16/groth16wrapper"
	"github.com/ekrembal/universal-groth16/risc0bridge"
)

// ===========================================================================
// End-to-End Test: RISC0 + SP1 → Same Groth16 Wrapper
// ===========================================================================

// TestE2E_RISC0andSP1_UnifiedGroth16 demonstrates the full pipeline:
//
//	RISC0 path:  Groth16 proof → Groth16VerifierCircuit (PlonK) → PlonkVerifierGroth16Circuit
//	SP1 path:    SP1 circuit (PlonK) → PlonkVerifierGroth16Circuit
//
// Both paths produce PlonK proofs that are verified by the same outer Groth16
// circuit structure (PlonkVerifierGroth16Circuit), identified by different
// VkHash values.
func TestE2E_RISC0andSP1_UnifiedGroth16(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}
	assert := test.NewAssert(t)
	field := ecc.BN254.ScalarField()

	// ====================================================================
	// Part 1: RISC0 Path (Groth16 → PlonK → Groth16)
	// ====================================================================
	t.Log("=== RISC0 PATH ===")

	// Step 1a: Create and prove a mock RISC0 Groth16 circuit
	risc0Circuit := &MockRISC0Groth16Circuit{}
	risc0Assignment := &MockRISC0Groth16Circuit{
		Secret:      7,
		JournalHash: 50, // 7^2 + 1 = 50
	}

	risc0Ccs, err := frontend.Compile(field, r1cs.NewBuilder, risc0Circuit)
	assert.NoError(err)

	risc0PK, risc0VK, err := groth16.Setup(risc0Ccs)
	assert.NoError(err)

	risc0Witness, err := frontend.NewWitness(risc0Assignment, field)
	assert.NoError(err)

	risc0Proof, err := groth16.Prove(risc0Ccs, risc0PK, risc0Witness)
	assert.NoError(err)

	risc0PubWit, err := risc0Witness.Public()
	assert.NoError(err)

	err = groth16.Verify(risc0Proof, risc0VK, risc0PubWit)
	assert.NoError(err)
	t.Log("RISC0: Groth16 proof verified natively")

	// Step 1b: Wrap Groth16 proof in PlonK
	circuitVK, err := recursion_groth16.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](risc0VK)
	assert.NoError(err)

	nbRisc0Pub := risc0Ccs.GetNbPublicVariables() - 1
	risc0PlonkCircuit := &risc0bridge.Groth16VerifierCircuit{
		InnerVK:           circuitVK,
		InnerProof:        recursion_groth16.PlaceholderProof[sw_bn254.G1Affine, sw_bn254.G2Affine](risc0Ccs),
		InnerPublicInputs: make([]frontend.Variable, nbRisc0Pub),
	}

	risc0PlonkCS, err := frontend.Compile(field, scs.NewBuilder, risc0PlonkCircuit)
	assert.NoError(err)
	t.Logf("RISC0: Groth16 verifier PlonK circuit = %d SCS constraints", risc0PlonkCS.GetNbConstraints())

	risc0PlonkSRS, risc0PlonkSRSLag, err := unsafekzg.NewSRS(risc0PlonkCS)
	assert.NoError(err)

	risc0Result, err := risc0bridge.WrapGroth16InPlonk(
		risc0Ccs, risc0VK, risc0Proof, risc0PubWit,
		risc0PlonkSRS, risc0PlonkSRSLag,
	)
	assert.NoError(err)
	t.Log("RISC0: Groth16 proof wrapped in PlonK")

	// ====================================================================
	// Part 2: SP1 Path (PlonK directly)
	// ====================================================================
	t.Log("=== SP1 PATH ===")

	sp1Circuit := &MockSP1PlonkCircuit{}
	sp1Assignment := &MockSP1PlonkCircuit{
		VkeyHash:              15,
		CommittedValuesDigest: 8,
		PreimageA:             3,
		PreimageB:             5,
	}

	sp1Ccs, err := frontend.Compile(field, scs.NewBuilder, sp1Circuit)
	assert.NoError(err)
	t.Logf("SP1: PlonK circuit = %d SCS constraints", sp1Ccs.GetNbConstraints())

	sp1SRS, sp1SRSLag, err := unsafekzg.NewSRS(sp1Ccs)
	assert.NoError(err)

	sp1PK, sp1VK, err := plonk.Setup(sp1Ccs, sp1SRS, sp1SRSLag)
	assert.NoError(err)

	sp1Witness, err := frontend.NewWitness(sp1Assignment, field)
	assert.NoError(err)

	sp1Proof, err := plonk.Prove(sp1Ccs, sp1PK, sp1Witness,
		recursion_plonk.GetNativeProverOptions(field, field))
	assert.NoError(err)

	sp1PubWit, err := sp1Witness.Public()
	assert.NoError(err)

	err = plonk.Verify(sp1Proof, sp1VK, sp1PubWit,
		recursion_plonk.GetNativeVerifierOptions(field, field))
	assert.NoError(err)
	t.Log("SP1: PlonK proof verified natively")

	// ====================================================================
	// Part 3: Verify RISC0 PlonK proof in outer Groth16
	// ====================================================================
	t.Log("=== OUTER GROTH16 VERIFICATION ===")

	// --- RISC0 ---
	risc0PlonkVK := risc0Result.PlonkVK.(*plonkbackend_bn254.VerifyingKey)
	risc0VkHash := computeVkHashE2E(t, risc0PlonkVK, field)
	risc0PubHash := computePubInputsHashE2E(t, risc0Result.PlonkPubWitness, field)

	risc0Bvk, err := recursion_plonk.ValueOfBaseVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](risc0Result.PlonkVK)
	assert.NoError(err)
	risc0Cvk, err := recursion_plonk.ValueOfCircuitVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine](risc0Result.PlonkVK)
	assert.NoError(err)
	risc0PlonkProof, err := recursion_plonk.ValueOfProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](risc0Result.PlonkProof)
	assert.NoError(err)

	risc0PlonkNbPub := risc0Result.PlonkCS.GetNbPublicVariables()
	risc0PubInputVals := extractPubValsE2E(t, risc0Result.PlonkPubWitness)

	risc0OuterCircuit := &groth16wrapper.Circuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		BaseKey:           risc0Bvk,
		Proof:             recursion_plonk.PlaceholderProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](risc0Result.PlonkCS),
		CircuitKey:        recursion_plonk.PlaceholderCircuitVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine](risc0Result.PlonkCS),
		InnerPublicInputs: make([]frontend.Variable, risc0PlonkNbPub),
	}
	risc0OuterAssignment := &groth16wrapper.Circuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		Proof:             risc0PlonkProof,
		CircuitKey:        risc0Cvk,
		InnerPublicInputs: risc0PubInputVals,
		VkHash:            risc0VkHash,
		PublicInputsHash:  risc0PubHash,
	}

	err = test.IsSolved(risc0OuterCircuit, risc0OuterAssignment, field)
	assert.NoError(err)
	t.Log("RISC0: PlonK proof verified in outer Groth16 circuit!")

	// --- SP1 ---
	sp1PlonkVK := sp1VK.(*plonkbackend_bn254.VerifyingKey)
	sp1VkHash := computeVkHashE2E(t, sp1PlonkVK, field)
	sp1PubHash := computePubInputsHashE2E(t, sp1PubWit, field)

	sp1Bvk, err := recursion_plonk.ValueOfBaseVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](sp1VK)
	assert.NoError(err)
	sp1Cvk, err := recursion_plonk.ValueOfCircuitVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine](sp1VK)
	assert.NoError(err)
	sp1PlonkProof, err := recursion_plonk.ValueOfProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](sp1Proof)
	assert.NoError(err)

	sp1PlonkNbPub := sp1Ccs.GetNbPublicVariables()
	sp1PubInputVals := extractPubValsE2E(t, sp1PubWit)

	sp1OuterCircuit := &groth16wrapper.Circuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		BaseKey:           sp1Bvk,
		Proof:             recursion_plonk.PlaceholderProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](sp1Ccs),
		CircuitKey:        recursion_plonk.PlaceholderCircuitVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine](sp1Ccs),
		InnerPublicInputs: make([]frontend.Variable, sp1PlonkNbPub),
	}
	sp1OuterAssignment := &groth16wrapper.Circuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		Proof:             sp1PlonkProof,
		CircuitKey:        sp1Cvk,
		InnerPublicInputs: sp1PubInputVals,
		VkHash:            sp1VkHash,
		PublicInputsHash:  sp1PubHash,
	}

	err = test.IsSolved(sp1OuterCircuit, sp1OuterAssignment, field)
	assert.NoError(err)
	t.Log("SP1: PlonK proof verified in outer Groth16 circuit!")

	// ====================================================================
	// Part 4: Confirm different VK hashes
	// ====================================================================
	assert.NotEqual(risc0VkHash.Bytes(), sp1VkHash.Bytes())
	t.Logf("RISC0 VK hash: %s", risc0VkHash)
	t.Logf("SP1   VK hash: %s", sp1VkHash)
	t.Log("VK hashes differ — each proof is bound to its inner circuit")

	t.Log("=== E2E TEST PASSED ===")
	t.Log("Both RISC0 and SP1 proofs verified by PlonkVerifierGroth16Circuit")
}

// ===========================================================================
// Mock circuits
// ===========================================================================

type MockRISC0Groth16Circuit struct {
	Secret      frontend.Variable
	JournalHash frontend.Variable `gnark:",public"`
}

func (c *MockRISC0Groth16Circuit) Define(api frontend.API) error {
	sq := api.Mul(c.Secret, c.Secret)
	result := api.Add(sq, 1)
	api.AssertIsEqual(c.JournalHash, result)
	return nil
}

type MockSP1PlonkCircuit struct {
	VkeyHash              frontend.Variable `gnark:",public"`
	CommittedValuesDigest frontend.Variable `gnark:",public"`
	PreimageA             frontend.Variable
	PreimageB             frontend.Variable
}

func (c *MockSP1PlonkCircuit) Define(api frontend.API) error {
	product := api.Mul(c.PreimageA, c.PreimageB)
	api.AssertIsEqual(c.VkeyHash, product)
	sum := api.Add(c.PreimageA, c.PreimageB)
	api.AssertIsEqual(c.CommittedValuesDigest, sum)
	return nil
}

// ===========================================================================
// Helpers
// ===========================================================================

func computeVkHashE2E(t *testing.T, nativeVK *plonkbackend_bn254.VerifyingKey, field *big.Int) *big.Int {
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

func computePubInputsHashE2E(t *testing.T, pubWitness witness.Witness, field *big.Int) *big.Int {
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

func extractPubValsE2E(t *testing.T, pubWitness witness.Witness) []frontend.Variable {
	t.Helper()
	vec := pubWitness.Vector()
	frVec, ok := vec.(fr_bn254.Vector)
	if !ok {
		t.Fatalf("expected fr_bn254.Vector, got %T", vec)
	}
	vals := make([]frontend.Variable, len(frVec))
	for i := range frVec {
		bi := new(big.Int)
		frVec[i].BigInt(bi)
		vals[i] = bi
	}
	return vals
}
