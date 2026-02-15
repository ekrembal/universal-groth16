package circom

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"
)

// BN254 prime: 21888242871839275222246405745257275088548364400416034343698204186575808495617
var bn254Prime, _ = new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)

// buildTestR1CS creates a binary R1CS file in memory for testing.
//
// The circuit implements: out = x * x
// where x is a public input and out is a public output.
//
// Wires:
//
//	0: constant 1
//	1: out (public output)
//	2: x   (public input)
//
// Constraint: x * x = out  =>  A=[x], B=[x], C=[out]
func buildTestR1CS(prime *big.Int, fieldSize uint32) []byte {
	var buf bytes.Buffer

	// Magic: "r1cs"
	buf.Write([]byte{0x72, 0x31, 0x63, 0x73})
	// Version: 1
	binary.Write(&buf, binary.LittleEndian, uint32(1))
	// Number of sections: 3
	binary.Write(&buf, binary.LittleEndian, uint32(3))

	// === Header Section (type 1) ===
	headerBuf := buildHeaderSection(prime, fieldSize, 3, 1, 1, 0, 10, 1)
	binary.Write(&buf, binary.LittleEndian, uint32(1))             // section type
	binary.Write(&buf, binary.LittleEndian, uint64(len(headerBuf))) // section size
	buf.Write(headerBuf)

	// === Constraints Section (type 2) ===
	constraintBuf := buildConstraintSection(fieldSize)
	binary.Write(&buf, binary.LittleEndian, uint32(2))                 // section type
	binary.Write(&buf, binary.LittleEndian, uint64(len(constraintBuf))) // section size
	buf.Write(constraintBuf)

	// === Wire2Label Map Section (type 3) ===
	labelBuf := buildLabelSection(3)
	binary.Write(&buf, binary.LittleEndian, uint32(3))              // section type
	binary.Write(&buf, binary.LittleEndian, uint64(len(labelBuf))) // section size
	buf.Write(labelBuf)

	return buf.Bytes()
}

func buildHeaderSection(prime *big.Int, fieldSize, nWires, nPubOut, nPubIn, nPrvIn uint32, nLabels uint64, nConstraints uint32) []byte {
	var buf bytes.Buffer

	// Field size.
	binary.Write(&buf, binary.LittleEndian, fieldSize)

	// Prime in LE bytes.
	primeBytes := prime.Bytes() // Big-endian
	leBytes := make([]byte, fieldSize)
	for i, b := range primeBytes {
		leBytes[len(primeBytes)-1-i] = b
	}
	buf.Write(leBytes)

	// Header fields.
	binary.Write(&buf, binary.LittleEndian, nWires)
	binary.Write(&buf, binary.LittleEndian, nPubOut)
	binary.Write(&buf, binary.LittleEndian, nPubIn)
	binary.Write(&buf, binary.LittleEndian, nPrvIn)
	binary.Write(&buf, binary.LittleEndian, nLabels)
	binary.Write(&buf, binary.LittleEndian, nConstraints)

	return buf.Bytes()
}

func buildConstraintSection(fieldSize uint32) []byte {
	var buf bytes.Buffer

	// Single constraint: x * x = out
	// A: [wire=2, coeff=1]  (x)
	// B: [wire=2, coeff=1]  (x)
	// C: [wire=1, coeff=1]  (out)

	writeTerm := func(wireID uint32, coeff int64) {
		binary.Write(&buf, binary.LittleEndian, wireID)
		coeffBytes := make([]byte, fieldSize)
		if coeff > 0 {
			b := big.NewInt(coeff).Bytes()
			for i, v := range b {
				coeffBytes[len(b)-1-i] = v
			}
		}
		buf.Write(coeffBytes)
	}

	// A: 1 term
	binary.Write(&buf, binary.LittleEndian, uint32(1))
	writeTerm(2, 1) // 1*x

	// B: 1 term
	binary.Write(&buf, binary.LittleEndian, uint32(1))
	writeTerm(2, 1) // 1*x

	// C: 1 term
	binary.Write(&buf, binary.LittleEndian, uint32(1))
	writeTerm(1, 1) // 1*out

	return buf.Bytes()
}

func buildLabelSection(nWires uint32) []byte {
	var buf bytes.Buffer
	for i := uint32(0); i < nWires; i++ {
		binary.Write(&buf, binary.LittleEndian, uint64(i))
	}
	return buf.Bytes()
}

func TestParseR1CS(t *testing.T) {
	data := buildTestR1CS(bn254Prime, 32)
	r, err := ParseR1CS(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("ParseR1CS: %v", err)
	}

	if r.Header.FieldSize != 32 {
		t.Errorf("FieldSize = %d, want 32", r.Header.FieldSize)
	}
	if r.Header.NWires != 3 {
		t.Errorf("NWires = %d, want 3", r.Header.NWires)
	}
	if r.Header.NPubOut != 1 {
		t.Errorf("NPubOut = %d, want 1", r.Header.NPubOut)
	}
	if r.Header.NPubIn != 1 {
		t.Errorf("NPubIn = %d, want 1", r.Header.NPubIn)
	}
	if r.Header.NConstraints != 1 {
		t.Errorf("NConstraints = %d, want 1", r.Header.NConstraints)
	}
	if len(r.Constraints) != 1 {
		t.Fatalf("len(Constraints) = %d, want 1", len(r.Constraints))
	}

	c := r.Constraints[0]
	if len(c.A) != 1 || c.A[0].WireID != 2 || c.A[0].Coefficient.Cmp(big.NewInt(1)) != 0 {
		t.Errorf("A = %+v, want [{2, 1}]", c.A)
	}
	if len(c.B) != 1 || c.B[0].WireID != 2 || c.B[0].Coefficient.Cmp(big.NewInt(1)) != 0 {
		t.Errorf("B = %+v, want [{2, 1}]", c.B)
	}
	if len(c.C) != 1 || c.C[0].WireID != 1 || c.C[0].Coefficient.Cmp(big.NewInt(1)) != 0 {
		t.Errorf("C = %+v, want [{1, 1}]", c.C)
	}

	t.Logf("Parsed: %s", r.String())
}

func TestCircomCircuitPlonK(t *testing.T) {
	// Build a test R1CS: out = x * x
	data := buildTestR1CS(bn254Prime, 32)
	r1csFile, err := ParseR1CS(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("ParseR1CS: %v", err)
	}

	// Create the circuit placeholder.
	circuit := NewCircomCircuit(r1csFile)

	// Compile to SCS (for PlonK).
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, circuit)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	t.Logf("Compiled: %d SCS constraints", ccs.GetNbConstraints())

	// Setup KZG SRS.
	srs, srsLagrange, err := unsafekzg.NewSRS(ccs)
	if err != nil {
		t.Fatalf("NewSRS: %v", err)
	}

	// PlonK setup.
	pk, vk, err := plonk.Setup(ccs, srs, srsLagrange)
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}

	// Create witness: x=3, out=9
	witness := []*big.Int{
		big.NewInt(1), // wire 0: constant 1
		big.NewInt(9), // wire 1: out (public output)
		big.NewInt(3), // wire 2: x (public input)
	}

	assignment, err := NewCircomAssignment(r1csFile, witness)
	if err != nil {
		t.Fatalf("NewCircomAssignment: %v", err)
	}

	// Create full witness.
	fullWitness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("NewWitness: %v", err)
	}

	// Prove.
	proof, err := plonk.Prove(ccs, pk, fullWitness)
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}

	// Extract public witness.
	pubWitness, err := fullWitness.Public()
	if err != nil {
		t.Fatalf("Public: %v", err)
	}

	// Verify.
	err = plonk.Verify(proof, vk, pubWitness)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	t.Log("PlonK proof verified successfully!")
}

// TestCircomCircuitMultiConstraint tests with a more complex circuit:
// temp = x * y   (private intermediate)
// out = temp + z  (public output)
//
// Wires:
//
//	0: constant 1
//	1: out   (public output)
//	2: x     (public input)
//	3: y     (public input)
//	4: z     (public input)
//	5: temp  (private intermediate)
//
// Constraints:
//
//	A=[x] * B=[y] = C=[temp]          => x*y = temp
//	A=[temp,z] * B=[1] = C=[out]      => (temp+z)*1 = out
func TestCircomCircuitMultiConstraint(t *testing.T) {
	var buf bytes.Buffer

	// Magic + version + nSections.
	buf.Write([]byte{0x72, 0x31, 0x63, 0x73})
	binary.Write(&buf, binary.LittleEndian, uint32(1))
	binary.Write(&buf, binary.LittleEndian, uint32(3))

	// Header.
	headerBuf := buildHeaderSection(bn254Prime, 32,
		6,  // nWires (0,1,2,3,4,5)
		1,  // nPubOut
		3,  // nPubIn (x, y, z)
		0,  // nPrvIn
		20, // nLabels
		2,  // nConstraints
	)
	binary.Write(&buf, binary.LittleEndian, uint32(1))
	binary.Write(&buf, binary.LittleEndian, uint64(len(headerBuf)))
	buf.Write(headerBuf)

	// Constraints.
	var cBuf bytes.Buffer
	fieldSize := uint32(32)

	writeTerm := func(wireID uint32, coeff int64) {
		binary.Write(&cBuf, binary.LittleEndian, wireID)
		coeffBytes := make([]byte, fieldSize)
		if coeff > 0 {
			b := big.NewInt(coeff).Bytes()
			for i, v := range b {
				coeffBytes[len(b)-1-i] = v
			}
		}
		cBuf.Write(coeffBytes)
	}

	// Constraint 0: x * y = temp
	binary.Write(&cBuf, binary.LittleEndian, uint32(1)) // A: 1 term
	writeTerm(2, 1)                                       // 1*x
	binary.Write(&cBuf, binary.LittleEndian, uint32(1)) // B: 1 term
	writeTerm(3, 1)                                       // 1*y
	binary.Write(&cBuf, binary.LittleEndian, uint32(1)) // C: 1 term
	writeTerm(5, 1)                                       // 1*temp

	// Constraint 1: (temp + z) * 1 = out
	binary.Write(&cBuf, binary.LittleEndian, uint32(2)) // A: 2 terms
	writeTerm(5, 1)                                       // 1*temp
	writeTerm(4, 1)                                       // 1*z
	binary.Write(&cBuf, binary.LittleEndian, uint32(1)) // B: 1 term
	writeTerm(0, 1)                                       // 1*one (wire 0)
	binary.Write(&cBuf, binary.LittleEndian, uint32(1)) // C: 1 term
	writeTerm(1, 1)                                       // 1*out

	constraintBytes := cBuf.Bytes()
	binary.Write(&buf, binary.LittleEndian, uint32(2))
	binary.Write(&buf, binary.LittleEndian, uint64(len(constraintBytes)))
	buf.Write(constraintBytes)

	// Wire labels.
	labelBuf := buildLabelSection(6)
	binary.Write(&buf, binary.LittleEndian, uint32(3))
	binary.Write(&buf, binary.LittleEndian, uint64(len(labelBuf)))
	buf.Write(labelBuf)

	// Parse.
	r1csFile, err := ParseR1CS(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("ParseR1CS: %v", err)
	}

	t.Logf("Parsed: %s", r1csFile.String())

	// Compile and prove.
	circuit := NewCircomCircuit(r1csFile)
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, circuit)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	t.Logf("Compiled: %d SCS constraints", ccs.GetNbConstraints())

	srs, srsLagrange, err := unsafekzg.NewSRS(ccs)
	if err != nil {
		t.Fatalf("NewSRS: %v", err)
	}

	pk, vk, err := plonk.Setup(ccs, srs, srsLagrange)
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}

	// x=3, y=4, z=5 => temp=12, out=17
	witness := []*big.Int{
		big.NewInt(1),  // wire 0: one
		big.NewInt(17), // wire 1: out (pub output)
		big.NewInt(3),  // wire 2: x (pub input)
		big.NewInt(4),  // wire 3: y (pub input)
		big.NewInt(5),  // wire 4: z (pub input)
		big.NewInt(12), // wire 5: temp (private)
	}

	assignment, err := NewCircomAssignment(r1csFile, witness)
	if err != nil {
		t.Fatalf("NewCircomAssignment: %v", err)
	}

	fullWitness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("NewWitness: %v", err)
	}

	proof, err := plonk.Prove(ccs, pk, fullWitness)
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}

	pubWitness, err := fullWitness.Public()
	if err != nil {
		t.Fatalf("Public: %v", err)
	}

	err = plonk.Verify(proof, vk, pubWitness)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	t.Log("Multi-constraint PlonK proof verified successfully!")

	// Negative test: wrong output should fail.
	badWitness := []*big.Int{
		big.NewInt(1),  // wire 0: one
		big.NewInt(18), // wire 1: out = WRONG
		big.NewInt(3),
		big.NewInt(4),
		big.NewInt(5),
		big.NewInt(12),
	}
	badAssignment, err := NewCircomAssignment(r1csFile, badWitness)
	if err != nil {
		t.Fatalf("NewCircomAssignment (bad): %v", err)
	}
	badFull, err := frontend.NewWitness(badAssignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("NewWitness (bad): %v", err)
	}
	_, err = plonk.Prove(ccs, pk, badFull)
	if err == nil {
		t.Fatal("Expected Prove to fail with wrong witness, but it succeeded")
	}
	t.Logf("Negative test passed: Prove failed with: %v", err)
}
