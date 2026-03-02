//go:build integrations

// Package unified implements a PlonK (SCS) circuit that simultaneously verifies
// a RISC0 Groth16 proof and an SP1 PlonK proof.
//
// This is "Approach A": it trusts RISC0's Groth16 trusted setup ceremony.
//
// # Data Flow
//
//	RISC0 Groth16 proof (5 pub inputs) --+
//	                                      +--> UnifiedVerifierCircuit (PlonK)
//	SP1 PlonK proof (2 pub inputs)   ----+       |
//	                                             +--> PlonK proof (N pub inputs)
//	                                             |
//	                                             +--> groth16wrapper.Circuit (Groth16)
//	                                                   |
//	                                                   +--> Final Groth16 proof
//	                                                        (2 pub inputs: VkHash + PublicInputsHash)
package unified

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	recursion_groth16 "github.com/consensys/gnark/std/recursion/groth16"
	recursion_plonk "github.com/consensys/gnark/std/recursion/plonk"
)

// Circuit is a PlonK (SCS) circuit that verifies both a RISC0 Groth16 proof
// and an SP1 PlonK proof in a single circuit.
//
// Constants baked into the circuit (gnark:"-"):
//   - RISC0 Groth16 VK (ties to a specific RISC0 Circom circuit version)
//   - SP1 PlonK BaseVerifyingKey (ties to a specific KZG SRS)
//   - RISC0_MethodID: expected value of RISC0's first public input
//   - SP1_VkeyHash: expected value of SP1's first public input
//
// Private witnesses:
//   - Both proofs, SP1's CircuitVerifyingKey, and all inner public inputs
//
// Public inputs (pass-through values):
//   - RISC0_PassThrough: RISC0 public inputs [1..4]
//   - SP1_CommittedValuesDigest: SP1's second public input
type Circuit struct {
	// ---- Constants (baked into circuit) ----

	// RISC0: Groth16 verifying key
	RISC0_VK recursion_groth16.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl] `gnark:"-"`

	// SP1: PlonK base verifying key (KZG SRS portion)
	SP1_BaseKey recursion_plonk.BaseVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine] `gnark:"-"`

	// Hardcoded method identifiers
	RISC0_MethodID frontend.Variable `gnark:"-"` // expected RISC0 public input [0]
	SP1_VkeyHash   frontend.Variable `gnark:"-"` // expected SP1 public input [0]

	// ---- Private witnesses ----

	// RISC0 Groth16 proof + public inputs
	RISC0_Proof     recursion_groth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]
	RISC0_PubInputs []frontend.Variable // all 5 RISC0 public inputs

	// SP1 PlonK proof + circuit key + public inputs
	SP1_Proof      recursion_plonk.Proof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine]
	SP1_CircuitKey recursion_plonk.CircuitVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine]
	SP1_PubInputs  []frontend.Variable // all 2 SP1 public inputs

	// ---- Public inputs (pass-through) ----

	// RISC0 public inputs excluding method_id (indices 1..4)
	RISC0_PassThrough []frontend.Variable `gnark:",public"`

	// SP1 CommittedValuesDigest (index 1)
	SP1_CommittedValuesDigest frontend.Variable `gnark:",public"`
}

// Define implements frontend.Circuit.
func (c *Circuit) Define(api frontend.API) error {
	var fp sw_bn254.ScalarField

	// ================================================================
	// Part 1: Verify RISC0 Groth16 Proof
	// ================================================================

	groth16Verifier, err := recursion_groth16.NewVerifier[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](api)
	if err != nil {
		return fmt.Errorf("new groth16 verifier: %w", err)
	}

	scalarApi, err := emulated.NewField[sw_bn254.ScalarField](api)
	if err != nil {
		return fmt.Errorf("new scalar field: %w", err)
	}

	risc0Emulated := make([]emulated.Element[sw_bn254.ScalarField], len(c.RISC0_PubInputs))
	for i := range c.RISC0_PubInputs {
		bits := api.ToBinary(c.RISC0_PubInputs[i], fp.Modulus().BitLen())
		e := scalarApi.FromBits(bits...)
		risc0Emulated[i] = *e
	}

	risc0Witness := recursion_groth16.Witness[sw_bn254.ScalarField]{
		Public: risc0Emulated,
	}

	if err := groth16Verifier.AssertProof(c.RISC0_VK, c.RISC0_Proof, risc0Witness); err != nil {
		return fmt.Errorf("risc0 groth16 assert proof: %w", err)
	}

	// Assert RISC0 method_id matches hardcoded constant.
	api.AssertIsEqual(c.RISC0_PubInputs[0], c.RISC0_MethodID)

	// Assert RISC0 pass-through values match the public outputs.
	for i := range c.RISC0_PassThrough {
		api.AssertIsEqual(c.RISC0_PubInputs[i+1], c.RISC0_PassThrough[i])
	}

	// ================================================================
	// Part 2: Verify SP1 PlonK Proof
	// ================================================================

	plonkVerifier, err := recursion_plonk.NewVerifier[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](api)
	if err != nil {
		return fmt.Errorf("new plonk verifier: %w", err)
	}

	sp1VK := recursion_plonk.VerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine]{
		BaseVerifyingKey:    c.SP1_BaseKey,
		CircuitVerifyingKey: c.SP1_CircuitKey,
	}

	sp1Emulated := make([]emulated.Element[sw_bn254.ScalarField], len(c.SP1_PubInputs))
	for i := range c.SP1_PubInputs {
		bits := api.ToBinary(c.SP1_PubInputs[i], fp.Modulus().BitLen())
		e := scalarApi.FromBits(bits...)
		sp1Emulated[i] = *e
	}

	sp1Witness := recursion_plonk.Witness[sw_bn254.ScalarField]{
		Public: sp1Emulated,
	}

	if err := plonkVerifier.AssertProof(sp1VK, c.SP1_Proof, sp1Witness, recursion_plonk.WithCompleteArithmetic()); err != nil {
		return fmt.Errorf("sp1 plonk assert proof: %w", err)
	}

	// Assert SP1 VkeyHash matches hardcoded constant.
	api.AssertIsEqual(c.SP1_PubInputs[0], c.SP1_VkeyHash)

	// Assert SP1 CommittedValuesDigest matches the public output.
	api.AssertIsEqual(c.SP1_PubInputs[1], c.SP1_CommittedValuesDigest)

	return nil
}
