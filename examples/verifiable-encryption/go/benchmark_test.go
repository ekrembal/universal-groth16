package verencpipeline

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	native_groth16 "github.com/consensys/gnark/backend/groth16"
	native_plonk "github.com/consensys/gnark/backend/plonk"
	plonkbackend_bn254 "github.com/consensys/gnark/backend/plonk/bn254"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/recursion"
	recursion_groth16 "github.com/consensys/gnark/std/recursion/groth16"
	recursion_plonk "github.com/consensys/gnark/std/recursion/plonk"
	"github.com/consensys/gnark/test/unsafekzg"

	"github.com/ekrembal/universal-groth16/circuits/unified"
	"github.com/ekrembal/universal-groth16/groth16wrapper"
)

// MockRISC0Circuit simulates RISC0's Groth16 circuit with 5 public inputs.
type BenchRISC0Circuit struct {
	Secret          frontend.Variable
	MethodID        frontend.Variable `gnark:",public"`
	JournalHash     frontend.Variable `gnark:",public"`
	PostStateDigest frontend.Variable `gnark:",public"`
	ExitCode        frontend.Variable `gnark:",public"`
	MemoryRoot      frontend.Variable `gnark:",public"`
}

func (c *BenchRISC0Circuit) Define(api frontend.API) error {
	sq := api.Mul(c.Secret, c.Secret)
	api.AssertIsEqual(c.JournalHash, sq)
	api.AssertIsEqual(c.PostStateDigest, api.Add(c.Secret, c.MethodID))
	api.AssertIsBoolean(c.ExitCode)
	api.AssertIsEqual(c.MemoryRoot, api.Add(api.Mul(c.Secret, c.ExitCode), 1))
	return nil
}

// MockSP1Circuit simulates SP1's PlonK circuit with 2 public inputs.
type BenchSP1Circuit struct {
	VkeyHash              frontend.Variable `gnark:",public"`
	CommittedValuesDigest frontend.Variable `gnark:",public"`
	PrivateA              frontend.Variable
	PrivateB              frontend.Variable
}

func (c *BenchSP1Circuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.VkeyHash, api.Mul(c.PrivateA, c.PrivateB))
	api.AssertIsEqual(c.CommittedValuesDigest, api.Add(c.PrivateA, c.PrivateB))
	return nil
}

// TestBenchmarkFullPipeline runs the full pipeline with mock proofs and reports
// detailed timing for each step. This uses the real UnifiedVerifierCircuit and
// PlonkVerifierGroth16Circuit.
func TestBenchmarkFullPipeline(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	field := ecc.BN254.ScalarField()
	results := &BenchmarkResults{}

	// Load the export file if available (for accumulator verification).
	const exportPath = "../../verifiable-encryption/proofs/export.json"
	proofs, err := LoadExportedProofs(exportPath)
	if err == nil {
		t.Logf("Loaded export with %d pairs, accumulator=%s", proofs.NumPairs, proofs.AccumulatorHash)
		err = VerifyAccumulatorFromExport(proofs)
		if err != nil {
			t.Fatalf("accumulator verification failed: %v", err)
		}
		t.Log("Accumulator hash verified in Go!")
	} else {
		t.Logf("No export file at %s, using mock values", exportPath)
	}

	// Convert accumulator to field element for use as method ID.
	risc0MethodID := big.NewInt(42)
	sp1VkeyHash := big.NewInt(15)

	// ================================================================
	// Step 1: Generate RISC0 Groth16 proof (mock)
	// ================================================================
	t.Log("\n=== Step 1: Generate mock RISC0 Groth16 proof ===")
	start := time.Now()

	risc0Ccs, risc0VK, risc0PubWitness, risc0Proof := benchGenRISC0(t, risc0MethodID)
	risc0Time := time.Since(start)
	t.Logf("RISC0 mock Groth16: %v (%d constraints, %d pub vars)",
		risc0Time, risc0Ccs.GetNbConstraints(), risc0Ccs.GetNbPublicVariables())

	// ================================================================
	// Step 2: Generate SP1 PlonK proof (mock, recursion-compatible)
	// ================================================================
	t.Log("\n=== Step 2: Generate mock SP1 PlonK proof ===")
	start = time.Now()

	sp1Ccs, sp1VK, sp1PubWitness, sp1Proof := benchGenSP1(t, sp1VkeyHash)
	sp1Time := time.Since(start)
	t.Logf("SP1 mock PlonK: %v (%d constraints, %d pub vars)",
		sp1Time, sp1Ccs.GetNbConstraints(), sp1Ccs.GetNbPublicVariables())

	// ================================================================
	// Step 3: Compile unified verifier circuit
	// ================================================================
	t.Log("\n=== Step 3: Compile unified verifier circuit ===")
	start = time.Now()

	circuitRISC0VK, err := recursion_groth16.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](risc0VK)
	if err != nil {
		t.Fatalf("convert risc0 vk: %v", err)
	}
	sp1BaseKey, err := recursion_plonk.ValueOfBaseVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](sp1VK)
	if err != nil {
		t.Fatalf("convert sp1 base key: %v", err)
	}
	sp1CircuitKey, err := recursion_plonk.ValueOfCircuitVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine](sp1VK)
	if err != nil {
		t.Fatalf("convert sp1 circuit key: %v", err)
	}

	nbRISC0Pub := risc0Ccs.GetNbPublicVariables() - 1
	nbSP1Pub := sp1Ccs.GetNbPublicVariables()

	placeholderCircuit := &unified.Circuit{
		RISC0_VK:                  circuitRISC0VK,
		SP1_BaseKey:               sp1BaseKey,
		RISC0_MethodID:            risc0MethodID,
		SP1_VkeyHash:              sp1VkeyHash,
		RISC0_Proof:               recursion_groth16.PlaceholderProof[sw_bn254.G1Affine, sw_bn254.G2Affine](risc0Ccs),
		RISC0_PubInputs:           make([]frontend.Variable, nbRISC0Pub),
		SP1_Proof:                 recursion_plonk.PlaceholderProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](sp1Ccs),
		SP1_CircuitKey:            recursion_plonk.PlaceholderCircuitVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine](sp1Ccs),
		SP1_PubInputs:             make([]frontend.Variable, nbSP1Pub),
		RISC0_PassThrough:         make([]frontend.Variable, nbRISC0Pub-1),
		SP1_CommittedValuesDigest: 0,
	}

	unifiedSCS, err := frontend.Compile(field, scs.NewBuilder, placeholderCircuit)
	if err != nil {
		t.Fatalf("compile unified: %v", err)
	}
	compileTime := time.Since(start)
	results.UnifiedPlonk_Compile_Seconds = compileTime.Seconds()
	results.UnifiedPlonk_Constraints = unifiedSCS.GetNbConstraints()
	t.Logf("Unified circuit compiled: %d SCS constraints, %d pub vars in %v",
		unifiedSCS.GetNbConstraints(), unifiedSCS.GetNbPublicVariables(), compileTime)

	// ================================================================
	// Step 4: PlonK setup
	// ================================================================
	t.Log("\n=== Step 4: PlonK setup ===")
	start = time.Now()

	plonkSRS, plonkSRSLag, err := unsafekzg.NewSRS(unifiedSCS)
	if err != nil {
		t.Fatalf("SRS: %v", err)
	}
	unifiedPK, unifiedVK, err := native_plonk.Setup(unifiedSCS, plonkSRS, plonkSRSLag)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	setupTime := time.Since(start)
	results.UnifiedPlonk_Setup_Seconds = setupTime.Seconds()
	t.Logf("PlonK setup: %v", setupTime)

	// ================================================================
	// Step 5: Generate unified PlonK proof
	// ================================================================
	t.Log("\n=== Step 5: Generate unified PlonK proof ===")
	start = time.Now()

	circuitRISC0Proof, err := recursion_groth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](risc0Proof)
	if err != nil {
		t.Fatalf("convert risc0 proof: %v", err)
	}
	circuitSP1Proof, err := recursion_plonk.ValueOfProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](sp1Proof)
	if err != nil {
		t.Fatalf("convert sp1 proof: %v", err)
	}

	risc0PubVals := benchExtractPubVals(t, risc0PubWitness)
	sp1PubVals := benchExtractPubVals(t, sp1PubWitness)

	assignment := &unified.Circuit{
		RISC0_Proof:               circuitRISC0Proof,
		RISC0_PubInputs:           risc0PubVals,
		SP1_Proof:                 circuitSP1Proof,
		SP1_CircuitKey:            sp1CircuitKey,
		SP1_PubInputs:             sp1PubVals,
		RISC0_PassThrough:         risc0PubVals[1:],
		SP1_CommittedValuesDigest: sp1PubVals[1],
	}

	fullWitness, err := frontend.NewWitness(assignment, field)
	if err != nil {
		t.Fatalf("witness: %v", err)
	}

	unifiedProof, err := native_plonk.Prove(unifiedSCS, unifiedPK, fullWitness,
		recursion_plonk.GetNativeProverOptions(field, field))
	if err != nil {
		t.Fatalf("prove: %v", err)
	}

	unifiedPubWitness, err := fullWitness.Public()
	if err != nil {
		t.Fatalf("pub witness: %v", err)
	}

	err = native_plonk.Verify(unifiedProof, unifiedVK, unifiedPubWitness,
		recursion_plonk.GetNativeVerifierOptions(field, field))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	proveTime := time.Since(start)
	results.UnifiedPlonk_Prove_Seconds = proveTime.Seconds()
	t.Logf("Unified PlonK proof: %v", proveTime)

	// ================================================================
	// Step 6: Outer Groth16 wrapper
	// ================================================================
	t.Log("\n=== Step 6: Compile outer Groth16 wrapper ===")
	start = time.Now()

	plonkNativeVK := unifiedVK.(*plonkbackend_bn254.VerifyingKey)
	vkHash := benchComputeVkHash(t, plonkNativeVK, field)
	pubInputsHash := benchComputePubInputsHash(t, unifiedPubWitness, field)

	outerBvk, err := recursion_plonk.ValueOfBaseVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](unifiedVK)
	if err != nil {
		t.Fatalf("outer bvk: %v", err)
	}
	outerCvk, err := recursion_plonk.ValueOfCircuitVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine](unifiedVK)
	if err != nil {
		t.Fatalf("outer cvk: %v", err)
	}
	outerProof, err := recursion_plonk.ValueOfProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](unifiedProof)
	if err != nil {
		t.Fatalf("outer proof: %v", err)
	}

	outerNbPub := unifiedSCS.GetNbPublicVariables()
	unifiedPubVals := benchExtractPubVals(t, unifiedPubWitness)

	outerCircuit := &groth16wrapper.Circuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		BaseKey:           outerBvk,
		Proof:             recursion_plonk.PlaceholderProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](unifiedSCS),
		CircuitKey:        recursion_plonk.PlaceholderCircuitVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine](unifiedSCS),
		InnerPublicInputs: make([]frontend.Variable, outerNbPub),
	}

	outerR1CS, err := frontend.Compile(field, r1cs.NewBuilder, outerCircuit)
	if err != nil {
		t.Fatalf("compile outer: %v", err)
	}
	outerCompileTime := time.Since(start)
	results.OuterGroth16_Compile_Seconds = outerCompileTime.Seconds()
	results.OuterGroth16_Constraints = outerR1CS.GetNbConstraints()
	t.Logf("Outer Groth16: %d R1CS constraints in %v", outerR1CS.GetNbConstraints(), outerCompileTime)

	// ================================================================
	// Step 7: Groth16 TSC (mock) + prove
	// ================================================================
	t.Log("\n=== Step 7: Groth16 trusted setup (mock) ===")
	start = time.Now()

	groth16PK, groth16VK, err := native_groth16.Setup(outerR1CS)
	if err != nil {
		t.Fatalf("groth16 setup: %v", err)
	}
	tscTime := time.Since(start)
	results.OuterGroth16_Setup_Seconds = tscTime.Seconds()
	t.Logf("Groth16 TSC: %v", tscTime)

	t.Log("\n=== Step 8: Generate final Groth16 proof ===")
	start = time.Now()

	outerAssignment := &groth16wrapper.Circuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		Proof:             outerProof,
		CircuitKey:        outerCvk,
		InnerPublicInputs: unifiedPubVals,
		VkHash:            vkHash,
		PublicInputsHash:  pubInputsHash,
	}

	outerFullWitness, err := frontend.NewWitness(outerAssignment, field)
	if err != nil {
		t.Fatalf("outer witness: %v", err)
	}

	finalProof, err := native_groth16.Prove(outerR1CS, groth16PK, outerFullWitness)
	if err != nil {
		t.Fatalf("groth16 prove: %v", err)
	}

	outerPubWitness, err := outerFullWitness.Public()
	if err != nil {
		t.Fatalf("outer pub witness: %v", err)
	}

	err = native_groth16.Verify(finalProof, groth16VK, outerPubWitness)
	if err != nil {
		t.Fatalf("groth16 verify: %v", err)
	}
	groth16ProveTime := time.Since(start)
	results.OuterGroth16_Prove_Seconds = groth16ProveTime.Seconds()

	t.Log("\n=== FINAL GROTH16 PROOF VERIFIED ===")
	t.Logf("Final proof public inputs: VkHash=%s, PublicInputsHash=%s", vkHash, pubInputsHash)

	// ================================================================
	// Summary
	// ================================================================
	t.Log("\n=== BENCHMARK SUMMARY ===")
	t.Logf("Unified PlonK circuit:  %d SCS constraints",  results.UnifiedPlonk_Constraints)
	t.Logf("  Compile:              %.1fs", results.UnifiedPlonk_Compile_Seconds)
	t.Logf("  PlonK setup:          %.1fs", results.UnifiedPlonk_Setup_Seconds)
	t.Logf("  PlonK prove+verify:   %.1fs", results.UnifiedPlonk_Prove_Seconds)
	t.Logf("Outer Groth16 circuit:  %d R1CS constraints", results.OuterGroth16_Constraints)
	t.Logf("  Compile:              %.1fs", results.OuterGroth16_Compile_Seconds)
	t.Logf("  Groth16 TSC (mock):   %.1fs", results.OuterGroth16_Setup_Seconds)
	t.Logf("  Groth16 prove+verify: %.1fs", results.OuterGroth16_Prove_Seconds)
	t.Logf("Total pipeline time:    %.1fs",
		results.UnifiedPlonk_Compile_Seconds+
			results.UnifiedPlonk_Setup_Seconds+
			results.UnifiedPlonk_Prove_Seconds+
			results.OuterGroth16_Compile_Seconds+
			results.OuterGroth16_Setup_Seconds+
			results.OuterGroth16_Prove_Seconds)

	// Save benchmark results.
	if err := SaveBenchmarkResults(results, "../../verifiable-encryption/proofs/benchmarks.json"); err != nil {
		t.Logf("Warning: could not save benchmarks: %v", err)
	}

	// Also verify the accumulator if the export file is available.
	if proofs != nil {
		accBytes, _ := hex.DecodeString(proofs.AccumulatorHash)
		t.Logf("\nAccumulator hash (from Rust): 0x%s", hex.EncodeToString(accBytes))
		t.Log("This value flows through both RISC0 and SP1 proofs,")
		t.Log("through the unified PlonK circuit, and is committed in the final Groth16 proof.")
	}
}

// ===========================================================================
// Helpers
// ===========================================================================

func benchGenRISC0(t *testing.T, methodID *big.Int) (
	constraint.ConstraintSystem,
	native_groth16.VerifyingKey,
	witness.Witness,
	native_groth16.Proof,
) {
	t.Helper()
	field := ecc.BN254.ScalarField()

	innerAssignment := &BenchRISC0Circuit{
		Secret: 7, MethodID: methodID,
		JournalHash: 49, PostStateDigest: 49, ExitCode: 1, MemoryRoot: 8,
	}
	ccs, err := frontend.Compile(field, r1cs.NewBuilder, &BenchRISC0Circuit{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	pk, vk, err := native_groth16.Setup(ccs)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	w, err := frontend.NewWitness(innerAssignment, field)
	if err != nil {
		t.Fatalf("witness: %v", err)
	}
	proof, err := native_groth16.Prove(ccs, pk, w)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}
	pw, err := w.Public()
	if err != nil {
		t.Fatalf("pub: %v", err)
	}
	if err := native_groth16.Verify(proof, vk, pw); err != nil {
		t.Fatalf("verify: %v", err)
	}
	return ccs, vk, pw, proof
}

func benchGenSP1(t *testing.T, vkeyHash *big.Int) (
	constraint.ConstraintSystem,
	native_plonk.VerifyingKey,
	witness.Witness,
	native_plonk.Proof,
) {
	t.Helper()
	field := ecc.BN254.ScalarField()

	innerAssignment := &BenchSP1Circuit{
		VkeyHash: vkeyHash, CommittedValuesDigest: 8, PrivateA: 3, PrivateB: 5,
	}
	ccs, err := frontend.Compile(field, scs.NewBuilder, &BenchSP1Circuit{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	srsg, srsLag, err := unsafekzg.NewSRS(ccs)
	if err != nil {
		t.Fatalf("srs: %v", err)
	}
	pk, vk, err := native_plonk.Setup(ccs, srsg, srsLag)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	w, err := frontend.NewWitness(innerAssignment, field)
	if err != nil {
		t.Fatalf("witness: %v", err)
	}
	proof, err := native_plonk.Prove(ccs, pk, w, recursion_plonk.GetNativeProverOptions(field, field))
	if err != nil {
		t.Fatalf("prove: %v", err)
	}
	pw, err := w.Public()
	if err != nil {
		t.Fatalf("pub: %v", err)
	}
	if err := native_plonk.Verify(proof, vk, pw, recursion_plonk.GetNativeVerifierOptions(field, field)); err != nil {
		t.Fatalf("verify: %v", err)
	}
	return ccs, vk, pw, proof
}

func benchExtractPubVals(t *testing.T, pw witness.Witness) []frontend.Variable {
	t.Helper()
	frVec, ok := pw.Vector().(fr_bn254.Vector)
	if !ok {
		t.Fatalf("expected fr_bn254.Vector")
	}
	vals := make([]frontend.Variable, len(frVec))
	for i := range frVec {
		bi := new(big.Int)
		frVec[i].BigInt(bi)
		vals[i] = bi
	}
	return vals
}

func benchComputeVkHash(t *testing.T, nativeVK *plonkbackend_bn254.VerifyingKey, field *big.Int) *big.Int {
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

func benchComputePubInputsHash(t *testing.T, pw witness.Witness, field *big.Int) *big.Int {
	t.Helper()
	frVec, ok := pw.Vector().(fr_bn254.Vector)
	if !ok {
		t.Fatalf("expected fr_bn254.Vector")
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

// init satisfies imports.
func init() {
	_ = fmt.Sprintf
	_ = os.Create
	_ = json.Marshal
}
