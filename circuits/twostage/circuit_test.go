//go:build integrations

package twostage

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	recursion_plonk "github.com/consensys/gnark/std/recursion/plonk"
	"github.com/consensys/gnark/test/unsafekzg"
)

// ---------------------------------------------------------------------------
// Mock inner circuits
// ---------------------------------------------------------------------------

// mockRISC0InnerCircuit simulates the RISC0 STARK verifier circuit.
type mockRISC0InnerCircuit struct {
	MethodID        frontend.Variable `gnark:",public"`
	AccumulatorHash frontend.Variable `gnark:",public"`
	PostStateDigest frontend.Variable `gnark:",public"`
	ExitCode        frontend.Variable `gnark:",public"`
	MemoryRoot      frontend.Variable `gnark:",public"`
	SecretWitness   frontend.Variable
}

func (c *mockRISC0InnerCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(api.Mul(c.SecretWitness, 1), c.SecretWitness)
	return nil
}

// mockSP1InnerCircuit simulates the SP1 PlonK circuit.
type mockSP1InnerCircuit struct {
	VkeyHash              frontend.Variable `gnark:",public"`
	CommittedValuesDigest frontend.Variable `gnark:",public"`
	SecretWitness         frontend.Variable
}

func (c *mockSP1InnerCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(api.Mul(c.SecretWitness, 1), c.SecretWitness)
	return nil
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestTwoStageCircuit(t *testing.T) {
	field := ecc.BN254.ScalarField()

	// Stage 1a: Mock RISC0 PlonK proof
	risc0Inner := &mockRISC0InnerCircuit{
		MethodID: 42, AccumulatorHash: 123456,
		PostStateDigest: 789, ExitCode: 0, MemoryRoot: 111,
		SecretWitness: 999,
	}

	risc0CCS, err := frontend.Compile(field, scs.NewBuilder, risc0Inner)
	if err != nil {
		t.Fatalf("compile mock RISC0: %v", err)
	}

	risc0SRS, risc0SRSLag, err := unsafekzg.NewSRS(risc0CCS)
	if err != nil {
		t.Fatalf("RISC0 SRS: %v", err)
	}

	risc0PK, risc0VKNative, err := plonk.Setup(risc0CCS, risc0SRS, risc0SRSLag)
	if err != nil {
		t.Fatalf("RISC0 setup: %v", err)
	}

	risc0Witness, err := frontend.NewWitness(&mockRISC0InnerCircuit{
		MethodID: 42, AccumulatorHash: 123456,
		PostStateDigest: 789, ExitCode: 0, MemoryRoot: 111,
		SecretWitness: 999,
	}, field)
	if err != nil {
		t.Fatalf("RISC0 witness: %v", err)
	}

	risc0Proof, err := plonk.Prove(risc0CCS, risc0PK, risc0Witness,
		recursion_plonk.GetNativeProverOptions(field, field))
	if err != nil {
		t.Fatalf("RISC0 prove: %v", err)
	}

	risc0PubWitness, _ := risc0Witness.Public()
	err = plonk.Verify(risc0Proof, risc0VKNative, risc0PubWitness,
		recursion_plonk.GetNativeVerifierOptions(field, field))
	if err != nil {
		t.Fatalf("RISC0 verify: %v", err)
	}

	// Stage 1b: Mock SP1 PlonK proof
	sp1Inner := &mockSP1InnerCircuit{
		VkeyHash: 77, CommittedValuesDigest: 123456, SecretWitness: 888,
	}

	sp1CCS, err := frontend.Compile(field, scs.NewBuilder, sp1Inner)
	if err != nil {
		t.Fatalf("compile mock SP1: %v", err)
	}

	sp1SRS, sp1SRSLag, err := unsafekzg.NewSRS(sp1CCS)
	if err != nil {
		t.Fatalf("SP1 SRS: %v", err)
	}

	sp1PK, sp1VKNative, err := plonk.Setup(sp1CCS, sp1SRS, sp1SRSLag)
	if err != nil {
		t.Fatalf("SP1 setup: %v", err)
	}

	sp1Witness, err := frontend.NewWitness(&mockSP1InnerCircuit{
		VkeyHash: 77, CommittedValuesDigest: 123456, SecretWitness: 888,
	}, field)
	if err != nil {
		t.Fatalf("SP1 witness: %v", err)
	}

	sp1Proof, err := plonk.Prove(sp1CCS, sp1PK, sp1Witness,
		recursion_plonk.GetNativeProverOptions(field, field))
	if err != nil {
		t.Fatalf("SP1 prove: %v", err)
	}

	sp1PubWitness, _ := sp1Witness.Public()
	err = plonk.Verify(sp1Proof, sp1VKNative, sp1PubWitness,
		recursion_plonk.GetNativeVerifierOptions(field, field))
	if err != nil {
		t.Fatalf("SP1 verify: %v", err)
	}

	// Stage 2: Build and compile the unified circuit
	risc0VKRec, err := recursion_plonk.ValueOfVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](risc0VKNative)
	if err != nil {
		t.Fatalf("RISC0 VK to recursion: %v", err)
	}

	sp1VKRec, err := recursion_plonk.ValueOfVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](sp1VKNative)
	if err != nil {
		t.Fatalf("SP1 VK to recursion: %v", err)
	}

	risc0ProofRec, err := recursion_plonk.ValueOfProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](risc0Proof)
	if err != nil {
		t.Fatalf("RISC0 proof to recursion: %v", err)
	}

	sp1ProofRec, err := recursion_plonk.ValueOfProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](sp1Proof)
	if err != nil {
		t.Fatalf("SP1 proof to recursion: %v", err)
	}

	placeholderCircuit := &Circuit{
		RISC0_BaseKey:    risc0VKRec.BaseVerifyingKey,
		SP1_BaseKey:      sp1VKRec.BaseVerifyingKey,
		RISC0_MethodID:   42,
		SP1_VkeyHash:     77,
		RISC0_Proof:      recursion_plonk.PlaceholderProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](risc0CCS),
		RISC0_CircuitKey: recursion_plonk.PlaceholderCircuitVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine](risc0CCS),
		RISC0_PubInputs:  make([]frontend.Variable, 5),
		SP1_Proof:        recursion_plonk.PlaceholderProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](sp1CCS),
		SP1_CircuitKey:   recursion_plonk.PlaceholderCircuitVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine](sp1CCS),
		SP1_PubInputs:    make([]frontend.Variable, 2),
	}

	t.Log("Compiling Stage 2 unified circuit...")
	unifiedCCS, err := frontend.Compile(field, scs.NewBuilder, placeholderCircuit)
	if err != nil {
		t.Fatalf("compile unified: %v", err)
	}
	t.Logf("Stage 2: %d SCS constraints, %d pub vars",
		unifiedCCS.GetNbConstraints(), unifiedCCS.GetNbPublicVariables())

	unifiedSRS, unifiedSRSLag, err := unsafekzg.NewSRS(unifiedCCS)
	if err != nil {
		t.Fatalf("unified SRS: %v", err)
	}

	unifiedPK, unifiedVK, err := plonk.Setup(unifiedCCS, unifiedSRS, unifiedSRSLag)
	if err != nil {
		t.Fatalf("unified setup: %v", err)
	}

	unifiedAssignment := &Circuit{
		RISC0_BaseKey:    risc0VKRec.BaseVerifyingKey,
		SP1_BaseKey:      sp1VKRec.BaseVerifyingKey,
		RISC0_MethodID:   42,
		SP1_VkeyHash:     77,
		RISC0_Proof:      risc0ProofRec,
		RISC0_CircuitKey: risc0VKRec.CircuitVerifyingKey,
		RISC0_PubInputs: []frontend.Variable{
			big.NewInt(42), big.NewInt(123456), big.NewInt(789), big.NewInt(0), big.NewInt(111),
		},
		SP1_Proof:       sp1ProofRec,
		SP1_CircuitKey:  sp1VKRec.CircuitVerifyingKey,
		SP1_PubInputs:   []frontend.Variable{big.NewInt(77), big.NewInt(123456)},
		AccumulatorHash: big.NewInt(123456),
	}

	unifiedWitness, err := frontend.NewWitness(unifiedAssignment, field)
	if err != nil {
		t.Fatalf("unified witness: %v", err)
	}

	t.Log("Proving Stage 2...")
	unifiedProof, err := plonk.Prove(unifiedCCS, unifiedPK, unifiedWitness)
	if err != nil {
		t.Fatalf("unified prove: %v", err)
	}

	unifiedPubWitness, _ := unifiedWitness.Public()
	err = plonk.Verify(unifiedProof, unifiedVK, unifiedPubWitness)
	if err != nil {
		t.Fatalf("unified verify: %v", err)
	}

	t.Log("Stage 2 unified PlonK proof verified!")
}
