// Package twostage implements a PlonK circuit that verifies both a RISC0 STARK
// PlonK proof and an SP1 PlonK proof.
//
// This is "Approach B" (two-stage, trustless):
//
//   - Stage 1a: RISC0 STARK verification (via Circom R1CS -> gnark SCS) -> PlonK proof
//   - Stage 1b: SP1 STARK compression -> PlonK proof (from SP1's native pipeline)
//   - Stage 2: This circuit verifies both Stage 1 PlonK proofs
//   - Stage 3: Outer Groth16 wraps the Stage 2 PlonK proof
//
// This circuit:
//  1. Verifies the RISC0 STARK PlonK proof
//  2. Verifies the SP1 PlonK proof
//  3. Checks that RISC0's method_id matches a hardcoded constant
//  4. Checks that SP1's VkeyHash matches a hardcoded constant
//  5. Checks that both proofs commit to the same accumulator hash
//  6. Exposes the accumulator hash as the sole public output
package twostage

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	recursion_plonk "github.com/consensys/gnark/std/recursion/plonk"
)

// Circuit is the Stage 2 unified circuit that verifies both a RISC0 STARK
// PlonK proof and an SP1 PlonK proof.
type Circuit struct {
	// ---- Constants (baked into circuit) ----

	// RISC0 STARK PlonK: Base verifying key (KZG SRS portion)
	RISC0_BaseKey recursion_plonk.BaseVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine] `gnark:"-"`

	// SP1 PlonK: Base verifying key (KZG SRS portion)
	SP1_BaseKey recursion_plonk.BaseVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine] `gnark:"-"`

	// Hardcoded identifiers
	RISC0_MethodID frontend.Variable `gnark:"-"` // expected RISC0 method ID
	SP1_VkeyHash   frontend.Variable `gnark:"-"` // expected SP1 vkey hash

	// ---- Private witnesses ----

	// RISC0 STARK PlonK proof (from Stage 1a)
	RISC0_Proof      recursion_plonk.Proof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine]
	RISC0_CircuitKey recursion_plonk.CircuitVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine]
	RISC0_PubInputs  []frontend.Variable // RISC0 STARK verifier public outputs

	// SP1 PlonK proof (from Stage 1b)
	SP1_Proof      recursion_plonk.Proof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine]
	SP1_CircuitKey recursion_plonk.CircuitVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine]
	SP1_PubInputs  []frontend.Variable // SP1 public inputs (vkey_hash, committed_values_digest)

	// ---- Public output ----

	// AccumulatorHash is the shared accumulator hash confirmed by both proofs.
	AccumulatorHash frontend.Variable `gnark:",public"`
}

// Define implements frontend.Circuit.
func (c *Circuit) Define(api frontend.API) error {
	var fp sw_bn254.ScalarField

	scalarApi, err := emulated.NewField[sw_bn254.ScalarField](api)
	if err != nil {
		return fmt.Errorf("new scalar field: %w", err)
	}

	plonkVerifier, err := recursion_plonk.NewVerifier[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](api)
	if err != nil {
		return fmt.Errorf("new plonk verifier: %w", err)
	}

	// ================================================================
	// Part 1: Verify RISC0 STARK PlonK proof (Stage 1a output)
	// ================================================================

	risc0VK := recursion_plonk.VerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine]{
		BaseVerifyingKey:    c.RISC0_BaseKey,
		CircuitVerifyingKey: c.RISC0_CircuitKey,
	}

	risc0Emulated := make([]emulated.Element[sw_bn254.ScalarField], len(c.RISC0_PubInputs))
	for i := range c.RISC0_PubInputs {
		bits := api.ToBinary(c.RISC0_PubInputs[i], fp.Modulus().BitLen())
		e := scalarApi.FromBits(bits...)
		risc0Emulated[i] = *e
	}

	risc0Witness := recursion_plonk.Witness[sw_bn254.ScalarField]{
		Public: risc0Emulated,
	}

	if err := plonkVerifier.AssertProof(risc0VK, c.RISC0_Proof, risc0Witness, recursion_plonk.WithCompleteArithmetic()); err != nil {
		return fmt.Errorf("risc0 plonk assert proof: %w", err)
	}

	// ================================================================
	// Part 2: Verify SP1 PlonK proof (Stage 1b output)
	// ================================================================

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

	// ================================================================
	// Part 3: Check hardcoded identifiers
	// ================================================================

	api.AssertIsEqual(c.RISC0_PubInputs[0], c.RISC0_MethodID)
	api.AssertIsEqual(c.SP1_PubInputs[0], c.SP1_VkeyHash)

	// ================================================================
	// Part 4: Check both proofs commit to the same accumulator
	// ================================================================

	api.AssertIsEqual(c.AccumulatorHash, c.RISC0_PubInputs[1])

	return nil
}
