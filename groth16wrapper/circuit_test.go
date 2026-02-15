package groth16wrapper

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	native_plonk "github.com/consensys/gnark/backend/plonk"
	plonkbackend_bn254 "github.com/consensys/gnark/backend/plonk/bn254"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/recursion"
	recursion_plonk "github.com/consensys/gnark/std/recursion/plonk"
	"github.com/consensys/gnark/test"
	"github.com/consensys/gnark/test/unsafekzg"
)

// ---------------------------------------------------------------------------
// Native helpers
// ---------------------------------------------------------------------------

// ComputeVkHash computes the circuit VK hash natively, matching the in-circuit
// bitmode MiMC encoding. This is the native counterpart of the VkHash
// computation in Circuit.Define.
func ComputeVkHash(nativeVK *plonkbackend_bn254.VerifyingKey, field *big.Int) (*big.Int, error) {
	h, err := recursion.NewShort(field, field)
	if err != nil {
		return nil, err
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

	return new(big.Int).SetBytes(h.Sum(nil)), nil
}

// ComputePublicInputsHash hashes N inner public inputs natively using
// non-bitmode MiMC, matching the in-circuit computation.
func ComputePublicInputsHash(pubWitness witness.Witness, field *big.Int) (*big.Int, error) {
	vec := pubWitness.Vector()
	vect, ok := vec.(fr_bn254.Vector)
	if !ok {
		return nil, nil
	}

	h, err := recursion.NewShort(field, field)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, (field.BitLen()+7)/8)
	for i := range vect {
		bi := new(big.Int)
		vect[i].BigInt(bi)
		bi.FillBytes(buf)
		h.Write(buf)
	}

	return new(big.Int).SetBytes(h.Sum(nil)), nil
}

// makeInnerProof generates a recursion-compatible PlonK proof for the given
// inner circuit.
func makeInnerProof(
	t *testing.T,
	innerCircuit frontend.Circuit,
	innerAssignment frontend.Circuit,
	field *big.Int,
) (constraint.ConstraintSystem, native_plonk.VerifyingKey, witness.Witness, native_plonk.Proof) {
	t.Helper()

	innerCcs, err := frontend.Compile(field, scs.NewBuilder, innerCircuit)
	if err != nil {
		t.Fatalf("compile inner: %v", err)
	}

	srsG, srsLagrange, err := unsafekzg.NewSRS(innerCcs)
	if err != nil {
		t.Fatalf("new SRS: %v", err)
	}

	innerPK, innerVK, err := native_plonk.Setup(innerCcs, srsG, srsLagrange)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	innerWitness, err := frontend.NewWitness(innerAssignment, field)
	if err != nil {
		t.Fatalf("new witness: %v", err)
	}

	innerProof, err := native_plonk.Prove(innerCcs, innerPK, innerWitness,
		recursion_plonk.GetNativeProverOptions(field, field))
	if err != nil {
		t.Fatalf("prove: %v", err)
	}

	innerPubWitness, err := innerWitness.Public()
	if err != nil {
		t.Fatalf("public witness: %v", err)
	}

	err = native_plonk.Verify(innerProof, innerVK, innerPubWitness,
		recursion_plonk.GetNativeVerifierOptions(field, field))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	return innerCcs, innerVK, innerPubWitness, innerProof
}

// solveOuter constructs the outer circuit + assignment and checks IsSolved.
func solveOuter(
	t *testing.T,
	innerCcs constraint.ConstraintSystem,
	innerVK native_plonk.VerifyingKey,
	innerPubWitness witness.Witness,
	innerProof native_plonk.Proof,
	field *big.Int,
	pubInputValues []frontend.Variable,
) {
	t.Helper()
	assert := test.NewAssert(t)

	nativeVK := innerVK.(*plonkbackend_bn254.VerifyingKey)
	vkHash, err := ComputeVkHash(nativeVK, field)
	assert.NoError(err)
	pubInputsHash, err := ComputePublicInputsHash(innerPubWitness, field)
	assert.NoError(err)

	circuitBvk, err := recursion_plonk.ValueOfBaseVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](innerVK)
	assert.NoError(err)
	circuitCvk, err := recursion_plonk.ValueOfCircuitVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine](innerVK)
	assert.NoError(err)
	circuitProof, err := recursion_plonk.ValueOfProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](innerProof)
	assert.NoError(err)

	nbPub := innerCcs.GetNbPublicVariables()

	outerCircuit := &Circuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		BaseKey:           circuitBvk,
		Proof:             recursion_plonk.PlaceholderProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](innerCcs),
		CircuitKey:        recursion_plonk.PlaceholderCircuitVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine](innerCcs),
		InnerPublicInputs: make([]frontend.Variable, nbPub),
	}
	outerAssignment := &Circuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		Proof:             circuitProof,
		CircuitKey:        circuitCvk,
		InnerPublicInputs: pubInputValues,
		VkHash:            vkHash,
		PublicInputsHash:  pubInputsHash,
	}

	err = test.IsSolved(outerCircuit, outerAssignment, field)
	assert.NoError(err)
}

// ---------------------------------------------------------------------------
// Inner test circuits
// ---------------------------------------------------------------------------

// innerCircuitOnePub has 1 public input: P*Q = N.
type innerCircuitOnePub struct {
	P, Q frontend.Variable
	N    frontend.Variable `gnark:",public"`
}

func (c *innerCircuitOnePub) Define(api frontend.API) error {
	res := api.Mul(c.P, c.Q)
	api.AssertIsEqual(res, c.N)
	return nil
}

// innerCircuitTwoPub has 2 public inputs: product and sum.
type innerCircuitTwoPub struct {
	A, B frontend.Variable
	X    frontend.Variable `gnark:",public"` // A*B
	Y    frontend.Variable `gnark:",public"` // A+B
}

func (c *innerCircuitTwoPub) Define(api frontend.API) error {
	api.AssertIsEqual(api.Mul(c.A, c.B), c.X)
	api.AssertIsEqual(api.Add(c.A, c.B), c.Y)
	return nil
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestCircuit_1PubInput verifies a PlonK proof with 1 inner public input.
func TestCircuit_1PubInput(t *testing.T) {
	field := ecc.BN254.ScalarField()

	innerCcs, innerVK, innerPubWitness, innerProof := makeInnerProof(t,
		&innerCircuitOnePub{},
		&innerCircuitOnePub{P: 3, Q: 5, N: 15},
		field,
	)

	solveOuter(t, innerCcs, innerVK, innerPubWitness, innerProof, field,
		[]frontend.Variable{15})

	// Also compile to R1CS and report size.
	assert := test.NewAssert(t)
	circuitBvk, err := recursion_plonk.ValueOfBaseVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](innerVK)
	assert.NoError(err)

	outerCircuit := &Circuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		BaseKey:           circuitBvk,
		Proof:             recursion_plonk.PlaceholderProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](innerCcs),
		CircuitKey:        recursion_plonk.PlaceholderCircuitVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine](innerCcs),
		InnerPublicInputs: make([]frontend.Variable, innerCcs.GetNbPublicVariables()),
	}
	outerCcs, err := frontend.Compile(field, r1cs.NewBuilder, outerCircuit)
	assert.NoError(err)
	t.Logf("1-pub-input: %d R1CS constraints, %d public variables",
		outerCcs.GetNbConstraints(), outerCcs.GetNbPublicVariables())
}

// TestCircuit_2PubInputs verifies a PlonK proof with 2 inner public inputs.
func TestCircuit_2PubInputs(t *testing.T) {
	field := ecc.BN254.ScalarField()

	innerCcs, innerVK, innerPubWitness, innerProof := makeInnerProof(t,
		&innerCircuitTwoPub{},
		&innerCircuitTwoPub{A: 3, B: 5, X: 15, Y: 8},
		field,
	)

	solveOuter(t, innerCcs, innerVK, innerPubWitness, innerProof, field,
		[]frontend.Variable{15, 8})

	assert := test.NewAssert(t)
	circuitBvk, err := recursion_plonk.ValueOfBaseVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](innerVK)
	assert.NoError(err)

	outerCircuit := &Circuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		BaseKey:           circuitBvk,
		Proof:             recursion_plonk.PlaceholderProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](innerCcs),
		CircuitKey:        recursion_plonk.PlaceholderCircuitVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine](innerCcs),
		InnerPublicInputs: make([]frontend.Variable, innerCcs.GetNbPublicVariables()),
	}
	outerCcs, err := frontend.Compile(field, r1cs.NewBuilder, outerCircuit)
	assert.NoError(err)
	t.Logf("2-pub-inputs: %d R1CS constraints, %d public variables",
		outerCcs.GetNbConstraints(), outerCcs.GetNbPublicVariables())
}

// TestCircuit_WrongPublicInput checks rejection on bad public input.
func TestCircuit_WrongPublicInput(t *testing.T) {
	assert := test.NewAssert(t)
	field := ecc.BN254.ScalarField()

	innerCcs, innerVK, _, innerProof := makeInnerProof(t,
		&innerCircuitOnePub{},
		&innerCircuitOnePub{P: 3, Q: 5, N: 15},
		field,
	)

	nativeVK := innerVK.(*plonkbackend_bn254.VerifyingKey)
	vkHash, err := ComputeVkHash(nativeVK, field)
	assert.NoError(err)

	circuitBvk, err := recursion_plonk.ValueOfBaseVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](innerVK)
	assert.NoError(err)
	circuitCvk, err := recursion_plonk.ValueOfCircuitVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine](innerVK)
	assert.NoError(err)
	circuitProof, err := recursion_plonk.ValueOfProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](innerProof)
	assert.NoError(err)

	outerCircuit := &Circuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		BaseKey:           circuitBvk,
		Proof:             recursion_plonk.PlaceholderProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](innerCcs),
		CircuitKey:        recursion_plonk.PlaceholderCircuitVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine](innerCcs),
		InnerPublicInputs: make([]frontend.Variable, 1),
	}

	// Compute wrong public inputs hash for input 16 instead of 15.
	wrongH, err := recursion.NewShort(field, field)
	assert.NoError(err)
	buf := make([]byte, 32)
	big.NewInt(16).FillBytes(buf)
	wrongH.Write(buf)
	wrongPubHash := new(big.Int).SetBytes(wrongH.Sum(nil))

	badAssignment := &Circuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		Proof:             circuitProof,
		CircuitKey:        circuitCvk,
		InnerPublicInputs: []frontend.Variable{16},
		VkHash:            vkHash,
		PublicInputsHash:  wrongPubHash,
	}

	err = test.IsSolved(outerCircuit, badAssignment, field)
	assert.Error(err)
}

// TestCircuit_WrongVkHash checks rejection on bad VK hash.
func TestCircuit_WrongVkHash(t *testing.T) {
	assert := test.NewAssert(t)
	field := ecc.BN254.ScalarField()

	innerCcs, innerVK, innerPubWitness, innerProof := makeInnerProof(t,
		&innerCircuitOnePub{},
		&innerCircuitOnePub{P: 3, Q: 5, N: 15},
		field,
	)
	pubInputsHash, err := ComputePublicInputsHash(innerPubWitness, field)
	assert.NoError(err)

	circuitBvk, err := recursion_plonk.ValueOfBaseVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](innerVK)
	assert.NoError(err)
	circuitCvk, err := recursion_plonk.ValueOfCircuitVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine](innerVK)
	assert.NoError(err)
	circuitProof, err := recursion_plonk.ValueOfProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](innerProof)
	assert.NoError(err)

	outerCircuit := &Circuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		BaseKey:           circuitBvk,
		Proof:             recursion_plonk.PlaceholderProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](innerCcs),
		CircuitKey:        recursion_plonk.PlaceholderCircuitVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine](innerCcs),
		InnerPublicInputs: make([]frontend.Variable, 1),
	}

	badAssignment := &Circuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		Proof:             circuitProof,
		CircuitKey:        circuitCvk,
		InnerPublicInputs: []frontend.Variable{15},
		VkHash:            big.NewInt(42),
		PublicInputsHash:  pubInputsHash,
	}

	err = test.IsSolved(outerCircuit, badAssignment, field)
	assert.Error(err)
}

// TestCircuit_WrongCircuitKey checks rejection on tampered VK.
func TestCircuit_WrongCircuitKey(t *testing.T) {
	assert := test.NewAssert(t)
	field := ecc.BN254.ScalarField()

	innerCcs, innerVK, innerPubWitness, innerProof := makeInnerProof(t,
		&innerCircuitOnePub{},
		&innerCircuitOnePub{P: 3, Q: 5, N: 15},
		field,
	)

	nativeVK := innerVK.(*plonkbackend_bn254.VerifyingKey)
	vkHash, err := ComputeVkHash(nativeVK, field)
	assert.NoError(err)
	pubInputsHash, err := ComputePublicInputsHash(innerPubWitness, field)
	assert.NoError(err)

	circuitBvk, err := recursion_plonk.ValueOfBaseVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](innerVK)
	assert.NoError(err)
	circuitCvk, err := recursion_plonk.ValueOfCircuitVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine](innerVK)
	assert.NoError(err)
	circuitProof, err := recursion_plonk.ValueOfProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](innerProof)
	assert.NoError(err)

	outerCircuit := &Circuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		BaseKey:           circuitBvk,
		Proof:             recursion_plonk.PlaceholderProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](innerCcs),
		CircuitKey:        recursion_plonk.PlaceholderCircuitVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine](innerCcs),
		InnerPublicInputs: make([]frontend.Variable, 1),
	}

	badCvk := circuitCvk
	badCvk.Size = 1024

	badAssignment := &Circuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		Proof:             circuitProof,
		CircuitKey:        badCvk,
		InnerPublicInputs: []frontend.Variable{15},
		VkHash:            vkHash,
		PublicInputsHash:  pubInputsHash,
	}

	err = test.IsSolved(outerCircuit, badAssignment, field)
	assert.Error(err)
}
