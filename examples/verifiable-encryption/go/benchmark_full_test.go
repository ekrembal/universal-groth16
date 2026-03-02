//go:build integrations

package verencpipeline

import (
	"fmt"
	"math/big"
	"testing"
	"time"

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
	recursion_plonk "github.com/consensys/gnark/std/recursion/plonk"
	"github.com/consensys/gnark/test/unsafekzg"

	"github.com/ekrembal/universal-groth16/circuits/twostage"
	"github.com/ekrembal/universal-groth16/groth16wrapper"
)

// MockRISC0InnerCircuit simulates the RISC0 STARK verifier circuit with 5 public outputs.
type MockRISC0InnerCircuit struct {
	MethodID        frontend.Variable `gnark:",public"`
	AccumulatorHash frontend.Variable `gnark:",public"`
	PostStateDigest frontend.Variable `gnark:",public"`
	ExitCode        frontend.Variable `gnark:",public"`
	MemoryRoot      frontend.Variable `gnark:",public"`
	SecretWitness   frontend.Variable
}

func (c *MockRISC0InnerCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(api.Mul(c.SecretWitness, 1), c.SecretWitness)
	return nil
}

// MockSP1InnerCircuit simulates the SP1 PlonK circuit with 2 public inputs.
type MockSP1InnerCircuit struct {
	VkeyHash              frontend.Variable `gnark:",public"`
	CommittedValuesDigest frontend.Variable `gnark:",public"`
	SecretWitness         frontend.Variable
}

func (c *MockSP1InnerCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(api.Mul(c.SecretWitness, 1), c.SecretWitness)
	return nil
}

// BenchmarkResult holds timing and size information for a pipeline stage.
type BenchmarkResult struct {
	Stage          string
	SCSConstraints int
	R1CSConstraints int
	CompileTime    time.Duration
	SetupTime      time.Duration
	ProveTime      time.Duration
	VerifyTime     time.Duration
}

func (b BenchmarkResult) String() string {
	s := fmt.Sprintf("  Stage: %s\n", b.Stage)
	if b.SCSConstraints > 0 {
		s += fmt.Sprintf("    SCS constraints:  %d\n", b.SCSConstraints)
	}
	if b.R1CSConstraints > 0 {
		s += fmt.Sprintf("    R1CS constraints: %d\n", b.R1CSConstraints)
	}
	s += fmt.Sprintf("    Compile time:     %v\n", b.CompileTime)
	s += fmt.Sprintf("    Setup time:       %v\n", b.SetupTime)
	s += fmt.Sprintf("    Prove time:       %v\n", b.ProveTime)
	s += fmt.Sprintf("    Verify time:      %v\n", b.VerifyTime)
	return s
}

// TestBenchmarkFullTwoStagePipeline benchmarks the complete two-stage pipeline:
//
// Stage 1a: RISC0 STARK verifier → PlonK proof (mocked with a small circuit here)
// Stage 1b: SP1 → PlonK proof (mocked with a small circuit here)
// Stage 2: Unified PlonK verifier (verifies both Stage 1 proofs)
// Stage 3: Outer Groth16 wrapper
//
// This test uses mock inner circuits. For real benchmarks with the actual
// RISC0 stark_verify.r1cs circuit (34M SCS constraints), see the RISC0-specific tests.
func TestBenchmarkFullTwoStagePipeline(t *testing.T) {
	field := ecc.BN254.ScalarField()
	results := make([]BenchmarkResult, 0, 4)

	// ====================================================================
	// Stage 1a: Mock RISC0 STARK PlonK
	// ====================================================================

	t.Log("=== Stage 1a: RISC0 STARK PlonK (mock) ===")
	risc0Result := BenchmarkResult{Stage: "1a: RISC0 STARK PlonK (mock)"}

	risc0Inner := &MockRISC0InnerCircuit{
		MethodID: 42, AccumulatorHash: 123456,
		PostStateDigest: 789, ExitCode: 0, MemoryRoot: 111,
		SecretWitness: 999,
	}

	start := time.Now()
	risc0CCS, _ := frontend.Compile(field, scs.NewBuilder, risc0Inner)
	risc0Result.CompileTime = time.Since(start)
	risc0Result.SCSConstraints = risc0CCS.GetNbConstraints()

	start = time.Now()
	risc0SRS, risc0SRSLag, _ := unsafekzg.NewSRS(risc0CCS)
	risc0PK, risc0VK, _ := plonk.Setup(risc0CCS, risc0SRS, risc0SRSLag)
	risc0Result.SetupTime = time.Since(start)

	risc0Witness, _ := frontend.NewWitness(
		&MockRISC0InnerCircuit{MethodID: 42, AccumulatorHash: 123456, PostStateDigest: 789, ExitCode: 0, MemoryRoot: 111, SecretWitness: 999},
		field,
	)

	start = time.Now()
	risc0Proof, _ := plonk.Prove(risc0CCS, risc0PK, risc0Witness,
		recursion_plonk.GetNativeProverOptions(field, field))
	risc0Result.ProveTime = time.Since(start)

	risc0PubWitness, _ := risc0Witness.Public()
	start = time.Now()
	_ = plonk.Verify(risc0Proof, risc0VK, risc0PubWitness,
		recursion_plonk.GetNativeVerifierOptions(field, field))
	risc0Result.VerifyTime = time.Since(start)

	results = append(results, risc0Result)
	t.Logf("%s", risc0Result)

	// ====================================================================
	// Stage 1b: Mock SP1 PlonK
	// ====================================================================

	t.Log("=== Stage 1b: SP1 PlonK (mock) ===")
	sp1Result := BenchmarkResult{Stage: "1b: SP1 PlonK (mock)"}

	sp1Inner := &MockSP1InnerCircuit{VkeyHash: 77, CommittedValuesDigest: 123456, SecretWitness: 888}

	start = time.Now()
	sp1CCS, _ := frontend.Compile(field, scs.NewBuilder, sp1Inner)
	sp1Result.CompileTime = time.Since(start)
	sp1Result.SCSConstraints = sp1CCS.GetNbConstraints()

	start = time.Now()
	sp1SRS, sp1SRSLag, _ := unsafekzg.NewSRS(sp1CCS)
	sp1PK, sp1VK, _ := plonk.Setup(sp1CCS, sp1SRS, sp1SRSLag)
	sp1Result.SetupTime = time.Since(start)

	sp1Witness, _ := frontend.NewWitness(
		&MockSP1InnerCircuit{VkeyHash: 77, CommittedValuesDigest: 123456, SecretWitness: 888}, field)

	start = time.Now()
	sp1Proof, _ := plonk.Prove(sp1CCS, sp1PK, sp1Witness,
		recursion_plonk.GetNativeProverOptions(field, field))
	sp1Result.ProveTime = time.Since(start)

	sp1PubWitness, _ := sp1Witness.Public()
	start = time.Now()
	_ = plonk.Verify(sp1Proof, sp1VK, sp1PubWitness,
		recursion_plonk.GetNativeVerifierOptions(field, field))
	sp1Result.VerifyTime = time.Since(start)

	results = append(results, sp1Result)
	t.Logf("%s", sp1Result)

	// ====================================================================
	// Stage 2: Unified PlonK
	// ====================================================================

	t.Log("=== Stage 2: Unified PlonK (verify both Stage 1 proofs) ===")
	unifiedResult := BenchmarkResult{Stage: "2: Unified PlonK verifier"}

	risc0VKRec, _ := recursion_plonk.ValueOfVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](risc0VK)
	sp1VKRec, _ := recursion_plonk.ValueOfVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](sp1VK)

	start = time.Now()
	placeholderCircuit := &twostage.Circuit{
		RISC0_BaseKey:   risc0VKRec.BaseVerifyingKey,
		SP1_BaseKey:     sp1VKRec.BaseVerifyingKey,
		RISC0_MethodID:  42,
		SP1_VkeyHash:    77,
		RISC0_Proof:     recursion_plonk.PlaceholderProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](risc0CCS),
		RISC0_CircuitKey: recursion_plonk.PlaceholderCircuitVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine](risc0CCS),
		RISC0_PubInputs: make([]frontend.Variable, 5),
		SP1_Proof:       recursion_plonk.PlaceholderProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](sp1CCS),
		SP1_CircuitKey:  recursion_plonk.PlaceholderCircuitVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine](sp1CCS),
		SP1_PubInputs:   make([]frontend.Variable, 2),
	}
	unifiedCCS, err := frontend.Compile(field, scs.NewBuilder, placeholderCircuit)
	if err != nil {
		t.Fatalf("compile unified: %v", err)
	}
	unifiedResult.CompileTime = time.Since(start)
	unifiedResult.SCSConstraints = unifiedCCS.GetNbConstraints()

	start = time.Now()
	unifiedSRS, unifiedSRSLag, _ := unsafekzg.NewSRS(unifiedCCS)
	unifiedPK, unifiedVK, _ := plonk.Setup(unifiedCCS, unifiedSRS, unifiedSRSLag)
	unifiedResult.SetupTime = time.Since(start)

	risc0ProofRec, _ := recursion_plonk.ValueOfProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](risc0Proof)
	sp1ProofRec, _ := recursion_plonk.ValueOfProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](sp1Proof)

	unifiedAssignment := &twostage.Circuit{
		RISC0_BaseKey:   risc0VKRec.BaseVerifyingKey,
		SP1_BaseKey:     sp1VKRec.BaseVerifyingKey,
		RISC0_MethodID:  42,
		SP1_VkeyHash:    77,
		RISC0_Proof:     risc0ProofRec,
		RISC0_CircuitKey: risc0VKRec.CircuitVerifyingKey,
		RISC0_PubInputs: []frontend.Variable{
			big.NewInt(42), big.NewInt(123456), big.NewInt(789), big.NewInt(0), big.NewInt(111),
		},
		SP1_Proof:      sp1ProofRec,
		SP1_CircuitKey: sp1VKRec.CircuitVerifyingKey,
		SP1_PubInputs:  []frontend.Variable{big.NewInt(77), big.NewInt(123456)},
		AccumulatorHash: big.NewInt(123456),
	}

	unifiedWitness, _ := frontend.NewWitness(unifiedAssignment, field)
	start = time.Now()
	// Use recursion-compatible prover options so the proof can be verified in the outer Groth16 circuit.
	unifiedProof, err := plonk.Prove(unifiedCCS, unifiedPK, unifiedWitness,
		recursion_plonk.GetNativeProverOptions(field, field))
	if err != nil {
		t.Fatalf("unified prove: %v", err)
	}
	unifiedResult.ProveTime = time.Since(start)

	unifiedPubWitness, _ := unifiedWitness.Public()
	start = time.Now()
	err = plonk.Verify(unifiedProof, unifiedVK, unifiedPubWitness,
		recursion_plonk.GetNativeVerifierOptions(field, field))
	if err != nil {
		t.Fatalf("unified verify: %v", err)
	}
	unifiedResult.VerifyTime = time.Since(start)

	results = append(results, unifiedResult)
	t.Logf("%s", unifiedResult)

	// ====================================================================
	// Stage 3: Outer Groth16
	// ====================================================================

	t.Log("=== Stage 3: Outer Groth16 (wrap Stage 2 PlonK proof) ===")
	groth16Result := BenchmarkResult{Stage: "3: Outer Groth16 wrapper"}

	unifiedVKBvk, _ := recursion_plonk.ValueOfBaseVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](unifiedVK)

	start = time.Now()
	outerCircuit := &groth16wrapper.Circuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		BaseKey:           unifiedVKBvk,
		Proof:             recursion_plonk.PlaceholderProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](unifiedCCS),
		CircuitKey:        recursion_plonk.PlaceholderCircuitVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine](unifiedCCS),
		InnerPublicInputs: make([]frontend.Variable, unifiedCCS.GetNbPublicVariables()),
	}
	outerCCS, err := frontend.Compile(field, r1cs.NewBuilder, outerCircuit)
	if err != nil {
		t.Fatalf("compile outer: %v", err)
	}
	groth16Result.CompileTime = time.Since(start)
	groth16Result.R1CSConstraints = outerCCS.GetNbConstraints()

	start = time.Now()
	outerPK, outerVK, err := groth16.Setup(outerCCS)
	if err != nil {
		t.Fatalf("groth16 setup: %v", err)
	}
	groth16Result.SetupTime = time.Since(start)

	// Create outer assignment.
	unifiedProofRec, _ := recursion_plonk.ValueOfProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](unifiedProof)
	unifiedVKRec, _ := recursion_plonk.ValueOfVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](unifiedVK)

	nativeUnifiedVK := unifiedVK.(*plonkbackend_bn254.VerifyingKey)
	vkHash := nativeComputeVkHash(nativeUnifiedVK, field)
	pubInputsHash := nativeComputePubInputsHash(unifiedPubWitness, field)

	outerAssignment := &groth16wrapper.Circuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		BaseKey:           unifiedVKBvk,
		Proof:             unifiedProofRec,
		CircuitKey:        unifiedVKRec.CircuitVerifyingKey,
		InnerPublicInputs: []frontend.Variable{big.NewInt(123456)}, // AccumulatorHash
		VkHash:            vkHash,
		PublicInputsHash:  pubInputsHash,
	}

	outerWitness, _ := frontend.NewWitness(outerAssignment, field)
	start = time.Now()
	outerProof, err := groth16.Prove(outerCCS, outerPK, outerWitness)
	if err != nil {
		t.Fatalf("groth16 prove: %v", err)
	}
	groth16Result.ProveTime = time.Since(start)

	outerPubWitness, _ := outerWitness.Public()
	start = time.Now()
	err = groth16.Verify(outerProof, outerVK, outerPubWitness)
	if err != nil {
		t.Fatalf("groth16 verify: %v", err)
	}
	groth16Result.VerifyTime = time.Since(start)

	results = append(results, groth16Result)
	t.Logf("%s", groth16Result)

	// ====================================================================
	// Summary
	// ====================================================================

	t.Log("\n========== FULL PIPELINE BENCHMARK SUMMARY ==========")
	totalProveTime := time.Duration(0)
	for _, r := range results {
		t.Logf("\n%s", r)
		totalProveTime += r.ProveTime
	}
	t.Logf("\nTotal prove time (all stages): %v", totalProveTime)
	t.Logf("Final Groth16 proof verify time: %v", groth16Result.VerifyTime)
	t.Log("\nNote: Stage 1a/1b use mock circuits. Real RISC0 STARK verifier has ~34M SCS constraints.")
	t.Log("Estimated real Stage 1a prove time: 15-45 minutes (with 34M SCS)")
}

// nativeComputeVkHash computes the VK hash natively.
func nativeComputeVkHash(nativeVK *plonkbackend_bn254.VerifyingKey, field *big.Int) *big.Int {
	h, _ := recursion.NewShort(field, field)
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

// nativeComputePubInputsHash hashes public inputs natively.
func nativeComputePubInputsHash(pubWitness witness.Witness, field *big.Int) *big.Int {
	vec := pubWitness.Vector()
	vect := vec.(fr_bn254.Vector)
	h, _ := recursion.NewShort(field, field)
	buf := make([]byte, (field.BitLen()+7)/8)
	for i := range vect {
		bi := new(big.Int)
		vect[i].BigInt(bi)
		bi.FillBytes(buf)
		h.Write(buf)
	}
	return new(big.Int).SetBytes(h.Sum(nil))
}
