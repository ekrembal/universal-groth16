//go:build integrations

// Package risc0bridge provides a gnark PlonK circuit that verifies BN254 Groth16
// proofs, designed for integrating RISC0's Circom-based STARK-to-SNARK pipeline
// into the universal PlonK-in-Groth16 wrapper.
//
// # Pipeline
//
//  1. RISC0 produces a STARK proof
//  2. RISC0's existing Circom/snarkjs pipeline verifies the STARK and produces
//     a BN254 Groth16 proof (this step is unchanged)
//  3. The Groth16 proof/VK are converted to gnark format (via circom2gnark or
//     native gnark Groth16 for testing)
//  4. Groth16VerifierCircuit (this package) verifies the Groth16 proof inside
//     a PlonK circuit, producing a PlonK proof
//  5. The PlonK proof is fed into PlonkVerifierGroth16Circuit for the final
//     Groth16 wrapping
//
// # Design Choices
//
// The Groth16 VK is **baked into** the circuit (gnark:"-") rather than being
// a private witness. This is appropriate because:
//   - RISC0's Circom circuit is fixed (one VK per RISC0 version)
//   - It avoids the complexity of hashing G2/GT elements in-circuit
//   - The PlonK VK hash from the outer wrapper already identifies which
//     Groth16 VK was used (changing the baked-in VK = new PlonK circuit = new VK hash)
//
// The Groth16 proof's public inputs are exposed as the PlonK circuit's public
// inputs, allowing the outer wrapper to commit to them via PublicInputsHash.
package risc0bridge

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/kzg"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	recursion_groth16 "github.com/consensys/gnark/std/recursion/groth16"
	recursion_plonk "github.com/consensys/gnark/std/recursion/plonk"
)

// ---------------------------------------------------------------------------
// Groth16 Verifier PlonK Circuit
// ---------------------------------------------------------------------------

// Groth16VerifierCircuit is a PlonK (SCS) circuit that verifies a BN254 Groth16
// proof in-circuit. When compiled and proven with PlonK, it produces a PlonK
// proof that can be fed into PlonkVerifierGroth16Circuit.
//
// The Groth16 VerifyingKey is baked into the circuit as a constant. Changing
// the Groth16 VK requires recompiling this circuit and regenerating the PlonK
// setup.
//
// The Groth16 proof's public inputs are exposed as this circuit's public inputs.
// For RISC0, these typically include the journal hash and image ID.
type Groth16VerifierCircuit struct {
	// Constant — baked into the circuit.
	InnerVK recursion_groth16.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl] `gnark:"-"`

	// Private witnesses
	InnerProof recursion_groth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]

	// Public inputs — these are the Groth16 proof's public inputs, passed through.
	// The outer PlonkVerifierGroth16Circuit will hash them via PublicInputsHash.
	InnerPublicInputs []frontend.Variable `gnark:",public"`
}

// Define implements frontend.Circuit.
func (c *Groth16VerifierCircuit) Define(api frontend.API) error {
	// 1. Verify the Groth16 proof
	verifier, err := recursion_groth16.NewVerifier[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](api)
	if err != nil {
		return fmt.Errorf("new groth16 verifier: %w", err)
	}

	// 2. Convert native public inputs to emulated field elements for the
	//    inner Groth16 witness.
	var fp sw_bn254.ScalarField
	scalarApi, err := emulated.NewField[sw_bn254.ScalarField](api)
	if err != nil {
		return fmt.Errorf("new scalar field: %w", err)
	}

	pubEmulated := make([]emulated.Element[sw_bn254.ScalarField], len(c.InnerPublicInputs))
	for i := range c.InnerPublicInputs {
		bits := api.ToBinary(c.InnerPublicInputs[i], fp.Modulus().BitLen())
		e := scalarApi.FromBits(bits...)
		pubEmulated[i] = *e
	}

	innerWitness := recursion_groth16.Witness[sw_bn254.ScalarField]{
		Public: pubEmulated,
	}

	// 3. Assert the Groth16 proof
	if err := verifier.AssertProof(c.InnerVK, c.InnerProof, innerWitness); err != nil {
		return fmt.Errorf("groth16 assert proof: %w", err)
	}

	return nil
}

// ---------------------------------------------------------------------------
// Wrapper: Groth16 → PlonK (recursion-compatible)
// ---------------------------------------------------------------------------

// Groth16RecursiveProof holds everything needed to feed a RISC0 Groth16 proof
// into the PlonK-in-Groth16 pipeline.
type Groth16RecursiveProof struct {
	PlonkCS         constraint.ConstraintSystem
	PlonkVK         plonk.VerifyingKey
	PlonkProof      plonk.Proof
	PlonkPubWitness witness.Witness
}

// WrapGroth16InPlonk takes a BN254 Groth16 proof and wraps it in a
// recursion-compatible PlonK proof by verifying the Groth16 proof inside
// the Groth16VerifierCircuit.
//
// Parameters:
//   - groth16Ccs:        the inner Groth16 constraint system (for placeholder sizing)
//   - groth16VK:         the inner Groth16 verifying key (baked into the circuit)
//   - groth16Proof:      the Groth16 proof to wrap
//   - groth16PubWitness: the Groth16 public witness
//   - plonkSrs:          KZG SRS for the PlonK circuit (must be large enough)
//   - plonkSrsLagrange:  KZG SRS in Lagrange form
func WrapGroth16InPlonk(
	groth16Ccs constraint.ConstraintSystem,
	groth16VK groth16.VerifyingKey,
	groth16Proof groth16.Proof,
	groth16PubWitness witness.Witness,
	plonkSrs kzg.SRS,
	plonkSrsLagrange kzg.SRS,
) (*Groth16RecursiveProof, error) {
	field := ecc.BN254.ScalarField()

	// Convert Groth16 VK to circuit type (baked into circuit).
	circuitVK, err := recursion_groth16.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](groth16VK)
	if err != nil {
		return nil, fmt.Errorf("convert VK: %w", err)
	}

	// Convert proof.
	circuitProof, err := recursion_groth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](groth16Proof)
	if err != nil {
		return nil, fmt.Errorf("convert proof: %w", err)
	}

	// Extract public input values from the witness.
	pubInputValues, err := extractPublicInputValues(groth16PubWitness, field)
	if err != nil {
		return nil, fmt.Errorf("extract public inputs: %w", err)
	}

	nbPub := groth16Ccs.GetNbPublicVariables() - 1 // subtract the "one" wire

	// Compile the Groth16 verifier circuit with baked-in VK.
	placeholderCircuit := &Groth16VerifierCircuit{
		InnerVK:           circuitVK,
		InnerProof:        recursion_groth16.PlaceholderProof[sw_bn254.G1Affine, sw_bn254.G2Affine](groth16Ccs),
		InnerPublicInputs: make([]frontend.Variable, nbPub),
	}

	plonkCS, err := frontend.Compile(field, scs.NewBuilder, placeholderCircuit)
	if err != nil {
		return nil, fmt.Errorf("compile groth16 verifier: %w", err)
	}

	// Setup PlonK keys.
	plonkPK, plonkVK, err := plonk.Setup(plonkCS, plonkSrs, plonkSrsLagrange)
	if err != nil {
		return nil, fmt.Errorf("plonk setup: %w", err)
	}

	// Create assignment.
	assignment := &Groth16VerifierCircuit{
		InnerProof:        circuitProof,
		InnerPublicInputs: pubInputValues,
	}

	fullWitness, err := frontend.NewWitness(assignment, field)
	if err != nil {
		return nil, fmt.Errorf("new witness: %w", err)
	}

	// Prove with recursion-compatible options.
	plonkProof, err := plonk.Prove(plonkCS, plonkPK, fullWitness,
		recursion_plonk.GetNativeProverOptions(field, field))
	if err != nil {
		return nil, fmt.Errorf("plonk prove: %w", err)
	}

	// Verify natively.
	pubWitness, err := fullWitness.Public()
	if err != nil {
		return nil, fmt.Errorf("public witness: %w", err)
	}

	err = plonk.Verify(plonkProof, plonkVK, pubWitness,
		recursion_plonk.GetNativeVerifierOptions(field, field))
	if err != nil {
		return nil, fmt.Errorf("plonk verify: %w", err)
	}

	return &Groth16RecursiveProof{
		PlonkCS:         plonkCS,
		PlonkVK:         plonkVK,
		PlonkProof:      plonkProof,
		PlonkPubWitness: pubWitness,
	}, nil
}

// extractPublicInputValues extracts the public input values from a BN254 witness
// as frontend.Variable values suitable for circuit assignment.
func extractPublicInputValues(pubWitness witness.Witness, field *big.Int) ([]frontend.Variable, error) {
	vec := pubWitness.Vector()
	frVec, ok := vec.(fr_bn254.Vector)
	if !ok {
		return nil, fmt.Errorf("expected fr_bn254.Vector, got %T", vec)
	}

	values := make([]frontend.Variable, len(frVec))
	for i := range frVec {
		bi := new(big.Int)
		frVec[i].BigInt(bi)
		values[i] = bi
	}
	return values, nil
}
