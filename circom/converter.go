package circom

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
)

// CircomCircuit is a gnark circuit that replays Circom R1CS constraints.
//
// Circom wire layout:
//   - Wire 0: constant "1" (implicit in gnark)
//   - Wires 1..NPubOut: public outputs
//   - Wires NPubOut+1..NPubOut+NPubIn: public inputs
//   - Remaining wires: private (intermediate + private inputs)
//
// In gnark, we map:
//   - Circom public wires -> gnark public variables (PublicWires slice)
//   - Circom private wires -> gnark secret variables (PrivateWires slice)
//   - Circom wire 0 -> implicitly 1 (handled during constraint evaluation)
type CircomCircuit struct {
	// PublicWires holds the public inputs/outputs (Circom wires 1..nPubOut+nPubIn).
	PublicWires []frontend.Variable `gnark:",public"`

	// PrivateWires holds all private/intermediate wires.
	PrivateWires []frontend.Variable

	// R1CS constraints (baked into the circuit definition).
	R1CS *R1CSFile `gnark:"-"`
}

// NewCircomCircuit creates a new CircomCircuit from a parsed R1CS file.
// This returns a circuit suitable for use as a gnark placeholder.
func NewCircomCircuit(r1cs *R1CSFile) *CircomCircuit {
	nPub := r1cs.Header.NPublicInputs()
	nPriv := r1cs.Header.NWires - 1 - nPub // -1 for wire 0 (constant 1)

	return &CircomCircuit{
		PublicWires:  make([]frontend.Variable, nPub),
		PrivateWires: make([]frontend.Variable, nPriv),
		R1CS:         r1cs,
	}
}

// Define implements frontend.Circuit by replaying the Circom R1CS constraints.
//
// For each constraint A * B = C, we:
// 1. Evaluate A, B, C as linear combinations of wires
// 2. Compute product = A * B
// 3. Assert product == C
func (c *CircomCircuit) Define(api frontend.API) error {
	if c.R1CS == nil {
		return fmt.Errorf("R1CS not set")
	}

	nPub := c.R1CS.Header.NPublicInputs()

	// Wire accessor: maps Circom wire IDs to gnark variables.
	// Wire 0 = constant 1
	// Wire 1..nPub = PublicWires[0..nPub-1]
	// Wire nPub+1..nWires-1 = PrivateWires[0..nPriv-1]
	getWire := func(wireID uint32) frontend.Variable {
		if wireID == 0 {
			return 1 // constant "one" wire
		}
		if wireID <= nPub {
			return c.PublicWires[wireID-1]
		}
		return c.PrivateWires[wireID-1-nPub]
	}

	// Evaluate a linear combination: sum(coeff_i * wire_i).
	evalLC := func(terms []R1CSTerm) frontend.Variable {
		if len(terms) == 0 {
			return 0
		}

		// Start with the first term.
		result := api.Mul(terms[0].Coefficient, getWire(terms[0].WireID))

		// Add remaining terms.
		for _, term := range terms[1:] {
			t := api.Mul(term.Coefficient, getWire(term.WireID))
			result = api.Add(result, t)
		}

		return result
	}

	// Replay each R1CS constraint: A * B = C.
	for i, constraint := range c.R1CS.Constraints {
		a := evalLC(constraint.A)
		b := evalLC(constraint.B)
		c_val := evalLC(constraint.C)

		product := api.Mul(a, b)
		api.AssertIsEqual(product, c_val)

		// Progress logging for large circuits.
		if i > 0 && i%1000000 == 0 {
			_ = i // Can't log during Define; just keep going.
		}
	}

	return nil
}

// NewCircomAssignment creates a witness assignment from a full Circom witness.
//
// The Circom witness is an array of field elements indexed by wire ID:
//   - witness[0] = 1 (constant)
//   - witness[1..nPubOut+nPubIn] = public values
//   - witness[nPubOut+nPubIn+1..] = private values
func NewCircomAssignment(r1cs *R1CSFile, witness []*big.Int) (*CircomCircuit, error) {
	if uint32(len(witness)) != r1cs.Header.NWires {
		return nil, fmt.Errorf("witness size mismatch: got %d, expected %d", len(witness), r1cs.Header.NWires)
	}

	// Verify wire 0 is 1.
	if witness[0].Cmp(big.NewInt(1)) != 0 {
		return nil, fmt.Errorf("wire 0 must be 1, got %s", witness[0])
	}

	nPub := r1cs.Header.NPublicInputs()
	nPriv := r1cs.Header.NWires - 1 - nPub

	circuit := &CircomCircuit{
		PublicWires:  make([]frontend.Variable, nPub),
		PrivateWires: make([]frontend.Variable, nPriv),
		R1CS:         r1cs,
	}

	// Map public wires (1..nPub).
	for i := uint32(0); i < nPub; i++ {
		circuit.PublicWires[i] = witness[i+1]
	}

	// Map private wires (nPub+1..nWires-1).
	for i := uint32(0); i < nPriv; i++ {
		circuit.PrivateWires[i] = witness[nPub+1+i]
	}

	return circuit, nil
}

// ExtractPublicInputs returns the public input values from a Circom witness.
func ExtractPublicInputs(r1cs *R1CSFile, witness []*big.Int) []*big.Int {
	nPub := r1cs.Header.NPublicInputs()
	pub := make([]*big.Int, nPub)
	for i := uint32(0); i < nPub; i++ {
		pub[i] = new(big.Int).Set(witness[i+1])
	}
	return pub
}
