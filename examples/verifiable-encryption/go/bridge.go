package verencpipeline

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	native_groth16 "github.com/consensys/gnark/backend/groth16"
	native_plonk "github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
)

// LoadRISC0Groth16Proof loads RISC0's Groth16 proof artifacts from a directory
// containing proof.json, vk.json, and public_inputs.json.
//
// NOTE: For the real pipeline, this would parse the Arkworks-format proof
// points and convert them to gnark format. For now, it returns an error
// since the format conversion is pending integration with actual RISC0 proofs.
func LoadRISC0Groth16Proof(dir string) (
	ccs constraint.ConstraintSystem,
	vk native_groth16.VerifyingKey,
	proof native_groth16.Proof,
	publicInputs []interface{},
	err error,
) {
	return nil, nil, nil, nil, fmt.Errorf("RISC0 Groth16 proof loading not yet implemented (requires Arkworks→gnark format conversion)")
}

// LoadSP1PlonkProof loads SP1's PlonK proof artifacts from binary files.
// SP1 uses gnark internally, so the proof/VK are in gnark's native format.
func LoadSP1PlonkProof(proofPath, vkPath, csPath string) (
	ccs constraint.ConstraintSystem,
	vk native_plonk.VerifyingKey,
	proof native_plonk.Proof,
	err error,
) {
	// Load constraint system.
	csFile, err := os.Open(csPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("open CS: %w", err)
	}
	defer csFile.Close()
	ccs = native_plonk.NewCS(ecc.BN254)
	if _, err := ccs.ReadFrom(bufio.NewReader(csFile)); err != nil {
		return nil, nil, nil, fmt.Errorf("read CS: %w", err)
	}

	// Load VK.
	vk = native_plonk.NewVerifyingKey(ecc.BN254)
	vkFile, err := os.Open(vkPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("open VK: %w", err)
	}
	defer vkFile.Close()
	if _, err := vk.ReadFrom(vkFile); err != nil {
		return nil, nil, nil, fmt.Errorf("read VK: %w", err)
	}

	// Load proof.
	proof = native_plonk.NewProof(ecc.BN254)
	proofFile, err := os.Open(proofPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("open proof: %w", err)
	}
	defer proofFile.Close()
	if _, err := proof.ReadFrom(proofFile); err != nil {
		return nil, nil, nil, fmt.Errorf("read proof: %w", err)
	}

	return ccs, vk, proof, nil
}

// SaveExportedProofs writes an ExportedProofs struct to a JSON file.
func SaveExportedProofs(proofs *ExportedProofs, path string) error {
	data, err := json.MarshalIndent(proofs, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	return os.WriteFile(path, data, 0o644)
}

// BenchmarkResults holds timing information for each pipeline stage.
type BenchmarkResults struct {
	// RISC0 standard flow.
	RISC0_STARK_Seconds   float64 `json:"risc0_stark_seconds"`
	RISC0_Groth16_Seconds float64 `json:"risc0_groth16_seconds"`
	// SP1 standard flow.
	SP1_STARK_Seconds   float64 `json:"sp1_stark_seconds"`
	SP1_Groth16_Seconds float64 `json:"sp1_groth16_seconds"`
	// Our pipeline.
	UnifiedPlonk_Compile_Seconds float64 `json:"unified_plonk_compile_seconds"`
	UnifiedPlonk_Setup_Seconds   float64 `json:"unified_plonk_setup_seconds"`
	UnifiedPlonk_Prove_Seconds   float64 `json:"unified_plonk_prove_seconds"`
	OuterGroth16_Compile_Seconds float64 `json:"outer_groth16_compile_seconds"`
	OuterGroth16_Setup_Seconds   float64 `json:"outer_groth16_setup_seconds"`
	OuterGroth16_Prove_Seconds   float64 `json:"outer_groth16_prove_seconds"`
	// Constraint counts.
	UnifiedPlonk_Constraints int `json:"unified_plonk_constraints"`
	OuterGroth16_Constraints int `json:"outer_groth16_constraints"`
}

// SaveBenchmarkResults writes benchmark results to a JSON file.
func SaveBenchmarkResults(results *BenchmarkResults, path string) error {
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	return os.WriteFile(path, data, 0o644)
}
