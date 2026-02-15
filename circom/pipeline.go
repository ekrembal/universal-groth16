// pipeline.go provides the end-to-end pipeline for converting a Circom R1CS
// circuit into a gnark PlonK proof.
//
// The pipeline is:
// 1. Parse Circom R1CS binary file
// 2. Create gnark circuit from R1CS constraints
// 3. Compile to SCS (Sparse Constraint System) for PlonK
// 4. Load witness (from .wtns or .json)
// 5. Generate PlonK proof
// 6. Verify PlonK proof

package circom

import (
	"fmt"
	"math/big"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	kzg_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/kzg"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
)

// PipelineConfig configures the Circom-to-PlonK pipeline.
type PipelineConfig struct {
	// R1CSPath is the path to the Circom R1CS binary file.
	R1CSPath string

	// WitnessPath is the path to the witness file (.wtns or .json).
	WitnessPath string

	// WitnessFormat is "wtns", "json", or "bin".
	WitnessFormat string

	// SRS is the KZG SRS for PlonK.
	SRS *kzg_bn254.SRS

	// SRSLagrange is the Lagrange form of the SRS.
	SRSLagrange *kzg_bn254.SRS
}

// PipelineResult contains the outputs of the pipeline.
type PipelineResult struct {
	// R1CS is the parsed Circom R1CS.
	R1CS *R1CSFile

	// CCS is the compiled gnark constraint system (SCS).
	CCS constraint.ConstraintSystem

	// Proof is the PlonK proof.
	Proof plonk.Proof

	// ProvingKey is the PlonK proving key.
	ProvingKey plonk.ProvingKey

	// VerifyingKey is the PlonK verifying key.
	VerifyingKey plonk.VerifyingKey

	// PublicWitness is the public witness for verification.
	PublicWitness []*big.Int

	// Timings.
	ParseTime   time.Duration
	CompileTime time.Duration
	SetupTime   time.Duration
	ProveTime   time.Duration
	VerifyTime  time.Duration

	// Stats.
	NR1CSConstraints uint32
	NSCSConstraints  int
	NWires           uint32
	NPublicInputs    uint32
}

// RunPipeline runs the full Circom-to-PlonK pipeline.
func RunPipeline(cfg *PipelineConfig) (*PipelineResult, error) {
	result := &PipelineResult{}

	// Step 1: Parse R1CS.
	fmt.Println("Step 1: Parsing Circom R1CS...")
	t := time.Now()
	r1cs, err := ParseR1CSFile(cfg.R1CSPath)
	if err != nil {
		return nil, fmt.Errorf("parse R1CS: %w", err)
	}
	result.ParseTime = time.Since(t)
	result.R1CS = r1cs
	result.NR1CSConstraints = r1cs.Header.NConstraints
	result.NWires = r1cs.Header.NWires
	result.NPublicInputs = r1cs.Header.NPublicInputs()
	fmt.Printf("  Parsed: %d R1CS constraints, %d wires, %d public inputs\n",
		r1cs.Header.NConstraints, r1cs.Header.NWires, result.NPublicInputs)
	fmt.Printf("  Parse time: %v\n", result.ParseTime)

	// Step 2: Compile to SCS.
	fmt.Println("Step 2: Compiling to SCS (PlonK)...")
	t = time.Now()
	circuit := NewCircomCircuit(r1cs)
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, circuit)
	if err != nil {
		return nil, fmt.Errorf("compile: %w", err)
	}
	result.CompileTime = time.Since(t)
	result.CCS = ccs
	result.NSCSConstraints = ccs.GetNbConstraints()
	fmt.Printf("  Compiled: %d SCS constraints (%.1fx R1CS)\n",
		result.NSCSConstraints, float64(result.NSCSConstraints)/float64(result.NR1CSConstraints))
	fmt.Printf("  Compile time: %v\n", result.CompileTime)

	// Step 3: Load witness.
	fmt.Println("Step 3: Loading witness...")
	var witness []*big.Int
	switch cfg.WitnessFormat {
	case "wtns":
		witness, err = LoadWitnessWtns(cfg.WitnessPath)
	case "json":
		witness, err = LoadWitnessJSON(cfg.WitnessPath)
	case "bin":
		witness, err = LoadWitnessBin(cfg.WitnessPath, r1cs.Header.FieldSize)
	default:
		return nil, fmt.Errorf("unknown witness format: %s", cfg.WitnessFormat)
	}
	if err != nil {
		return nil, fmt.Errorf("load witness: %w", err)
	}
	fmt.Printf("  Loaded %d witness values\n", len(witness))

	// Create gnark assignment from witness.
	assignment, err := NewCircomAssignment(r1cs, witness)
	if err != nil {
		return nil, fmt.Errorf("create assignment: %w", err)
	}

	fullWitness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("create full witness: %w", err)
	}

	// Step 4: Setup.
	fmt.Println("Step 4: PlonK setup...")
	t = time.Now()
	pk, vk, err := plonk.Setup(ccs, cfg.SRS, cfg.SRSLagrange)
	if err != nil {
		return nil, fmt.Errorf("setup: %w", err)
	}
	result.SetupTime = time.Since(t)
	result.ProvingKey = pk
	result.VerifyingKey = vk
	fmt.Printf("  Setup time: %v\n", result.SetupTime)

	// Step 5: Prove.
	fmt.Println("Step 5: Generating PlonK proof...")
	t = time.Now()
	proof, err := plonk.Prove(ccs, pk, fullWitness)
	if err != nil {
		return nil, fmt.Errorf("prove: %w", err)
	}
	result.ProveTime = time.Since(t)
	result.Proof = proof
	fmt.Printf("  Prove time: %v\n", result.ProveTime)

	// Step 6: Verify.
	fmt.Println("Step 6: Verifying PlonK proof...")
	t = time.Now()
	pubWitness, err := fullWitness.Public()
	if err != nil {
		return nil, fmt.Errorf("extract public witness: %w", err)
	}
	err = plonk.Verify(proof, vk, pubWitness)
	if err != nil {
		return nil, fmt.Errorf("verify: %w", err)
	}
	result.VerifyTime = time.Since(t)
	result.PublicWitness = ExtractPublicInputs(r1cs, witness)
	fmt.Printf("  Verify time: %v\n", result.VerifyTime)

	fmt.Println("Pipeline complete! PlonK proof verified successfully.")
	return result, nil
}
