// Package groth16wrapper provides a Groth16 (R1CS) outer circuit that verifies
// a gnark BN254 PlonK proof in-circuit.
//
// This is the core auditable circuit of the Universal Groth16 project.
//
// # Scope of Universality
//
// The circuit can verify a PlonK proof from any inner circuit that satisfies
// ALL of the following:
//
//   - Same curve (BN254)
//   - Same KZG SRS (baked into BaseKey)
//   - Same PlonK flavour and Fiat-Shamir transcript config (gnark's default
//     with recursion-compatible MiMC hash, i.e. proofs must be produced with
//     recursion_plonk.GetNativeProverOptions / GetNativeVerifierOptions)
//   - Same number of public inputs (N, fixed at compile time via placeholder)
//   - 0 Bsb22 commitments (no api.Commit in the inner circuit)
//
// # Architecture
//
// The BaseVerifyingKey (KZG SRS, coset shift, NbPublicVariables) is baked into
// the circuit as a constant (gnark:"-"). Changing the SRS or the number of
// inner public inputs requires recompiling the outer circuit and running a new
// Groth16 trusted setup ceremony.
//
// The CircuitVerifyingKey (selector commitments S/Ql/Qr/Qm/Qo/Qk, domain
// size, generator, sizeInv) is provided as a private witness -- this is what
// makes different inner circuits verifiable with the same outer circuit.
//
// The inner circuit's public inputs are provided as private witnesses in the
// outer circuit. They are hashed together (MiMC) so that the verifier can
// check them against a single public commitment.
//
// # Public Inputs
//
// The circuit exposes exactly 2 public inputs (plus gnark's implicit "one" wire):
//
//   - VkHash:           MiMC hash over the full CircuitVerifyingKey.
//   - PublicInputsHash: MiMC hash over the N inner public inputs.
//
// # VkHash Coverage
//
// The VkHash binds ALL circuit-specific VK fields that affect verification:
//
//   - Size (domain size)
//   - SizeInv (inverse of domain size)
//   - Generator (root of unity)
//   - S[0], S[1], S[2] (permutation commitments)
//   - Ql, Qr, Qm, Qo, Qk (selector commitments)
//
// The BaseVerifyingKey fields (KZG SRS points, coset shift, NbPublicVariables)
// are NOT hashed because they are baked into the circuit as constants.
//
// NOTE: Qcp and CommitmentConstraintIndexes are empty for the 0-commitment
// configuration this circuit targets. If you extend to support commitments,
// hash those fields as well.
package groth16wrapper

import (
	"fmt"
	"slices"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/recursion"
	recursion_plonk "github.com/consensys/gnark/std/recursion/plonk"
)

// Circuit is a Groth16 (R1CS) outer circuit that verifies a gnark BN254 PlonK
// proof in-circuit. It is generic over the field and curve parameters to
// support any gnark-supported curve, though in practice it is used with BN254.
//
// See package documentation for the full specification.
type Circuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	// Constant -- baked into the circuit. All inner circuits must share
	// this KZG SRS and the same number of public inputs.
	// Changing it requires recompilation + new Groth16 setup.
	BaseKey recursion_plonk.BaseVerifyingKey[FR, G1El, G2El] `gnark:"-"`

	// Private witnesses
	Proof             recursion_plonk.Proof[FR, G1El, G2El]
	CircuitKey        recursion_plonk.CircuitVerifyingKey[FR, G1El]
	InnerPublicInputs []frontend.Variable // N inner public inputs (private in outer)

	// Public inputs (exactly 2)
	VkHash           frontend.Variable `gnark:",public"`
	PublicInputsHash frontend.Variable `gnark:",public"`
}

// Define implements frontend.Circuit.
func (c *Circuit[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	var fr FR

	// 1. Create PlonK verifier
	verifier, err := recursion_plonk.NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}

	// 2. Reconstruct full verification key from constant base + witness circuit key
	vk := recursion_plonk.VerifyingKey[FR, G1El, G2El]{
		BaseVerifyingKey:    c.BaseKey,
		CircuitVerifyingKey: c.CircuitKey,
	}

	// 3. Convert each native inner public input to an emulated scalar and
	//    build the inner witness.
	scalarApi, err := emulated.NewField[FR](api)
	if err != nil {
		return fmt.Errorf("new scalar field: %w", err)
	}

	pubEmulated := make([]emulated.Element[FR], len(c.InnerPublicInputs))
	for i := range c.InnerPublicInputs {
		pubBits := bits.ToBinary(api, c.InnerPublicInputs[i], bits.WithNbDigits(fr.Modulus().BitLen()))
		e := scalarApi.FromBits(pubBits...)
		pubEmulated[i] = *e
	}

	innerWitness := recursion_plonk.Witness[FR]{
		Public: pubEmulated,
	}

	// 4. Verify PlonK proof
	if err := verifier.AssertProof(vk, c.Proof, innerWitness, recursion_plonk.WithCompleteArithmetic()); err != nil {
		return fmt.Errorf("assert proof: %w", err)
	}

	// 5. Hash the inner public inputs (non-bitmode MiMC, directly on native
	//    field elements). The native counterpart uses recursion.NewShort with
	//    field-element-sized writes.
	pubHasher, err := recursion.NewHash(api, fr.Modulus(), false)
	if err != nil {
		return fmt.Errorf("new pub hash: %w", err)
	}
	for i := range c.InnerPublicInputs {
		pubHasher.Write(c.InnerPublicInputs[i])
	}
	api.AssertIsEqual(pubHasher.Sum(), c.PublicInputsHash)

	// 6. Hash the FULL circuit-specific verification key.
	//    Uses bitmode MiMC so that G1 points and scalars are serialised
	//    identically to gnark-crypto's Marshal().
	curve, err := algebra.GetCurve[FR, G1El](api)
	if err != nil {
		return fmt.Errorf("get curve: %w", err)
	}
	vkHasher, err := recursion.NewHash(api, fr.Modulus(), true)
	if err != nil {
		return fmt.Errorf("new vk hash: %w", err)
	}

	nbScalarBits := 8 * ((fr.Modulus().BitLen() + 7) / 8)

	sizeBits := bits.ToBinary(api, c.CircuitKey.Size, bits.WithNbDigits(nbScalarBits))
	slices.Reverse(sizeBits)
	vkHasher.Write(sizeBits...)

	vkHasher.Write(curve.MarshalScalar(c.CircuitKey.SizeInv)...)
	vkHasher.Write(curve.MarshalScalar(c.CircuitKey.Generator)...)

	for i := range c.CircuitKey.S {
		vkHasher.Write(curve.MarshalG1(c.CircuitKey.S[i].G1El)...)
	}
	vkHasher.Write(curve.MarshalG1(c.CircuitKey.Ql.G1El)...)
	vkHasher.Write(curve.MarshalG1(c.CircuitKey.Qr.G1El)...)
	vkHasher.Write(curve.MarshalG1(c.CircuitKey.Qm.G1El)...)
	vkHasher.Write(curve.MarshalG1(c.CircuitKey.Qo.G1El)...)
	vkHasher.Write(curve.MarshalG1(c.CircuitKey.Qk.G1El)...)

	api.AssertIsEqual(vkHasher.Sum(), c.VkHash)

	return nil
}
