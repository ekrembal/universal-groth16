//go:build integrations

package circom

import (
	"os"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
)

const risc0R1CSPath = "artifacts/stark_verify.r1cs"

func TestParseRISC0R1CS(t *testing.T) {
	if _, err := os.Stat(risc0R1CSPath); os.IsNotExist(err) {
		t.Skipf("RISC0 R1CS file not found at %s (download from https://risc0-artifacts.s3.us-west-2.amazonaws.com/tsc/2024-04-04/stark_verify.r1cs)", risc0R1CSPath)
	}

	t.Log("Parsing RISC0 stark_verify.r1cs (this may take a while for ~1.4GB file)...")

	r1cs, err := ParseR1CSFile(risc0R1CSPath)
	if err != nil {
		t.Fatalf("ParseR1CSFile: %v", err)
	}

	t.Logf("Parsed successfully!")
	t.Logf("  Field size:    %d bytes", r1cs.Header.FieldSize)
	t.Logf("  Prime:         0x%s", r1cs.Header.Prime.Text(16))
	t.Logf("  Wires:         %d", r1cs.Header.NWires)
	t.Logf("  Public outs:   %d", r1cs.Header.NPubOut)
	t.Logf("  Public inputs: %d", r1cs.Header.NPubIn)
	t.Logf("  Private inputs:%d", r1cs.Header.NPrvIn)
	t.Logf("  Labels:        %d", r1cs.Header.NLabels)
	t.Logf("  Constraints:   %d", r1cs.Header.NConstraints)

	// Basic sanity checks.
	if r1cs.Header.FieldSize != 32 {
		t.Errorf("Expected field size 32, got %d", r1cs.Header.FieldSize)
	}

	// BN254 prime: 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
	expectedPrime := "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001"
	if r1cs.Header.Prime.Text(16) != expectedPrime {
		t.Errorf("Expected BN254 prime, got 0x%s", r1cs.Header.Prime.Text(16))
	}

	// RISC0's circuit has 5 public inputs (from documentation).
	t.Logf("  Total public wires: %d (out=%d + in=%d)",
		r1cs.Header.NPublicInputs(), r1cs.Header.NPubOut, r1cs.Header.NPubIn)

	// Verify we parsed all constraints.
	if uint32(len(r1cs.Constraints)) != r1cs.Header.NConstraints {
		t.Errorf("Constraint count mismatch: parsed %d, header says %d",
			len(r1cs.Constraints), r1cs.Header.NConstraints)
	}

	// Log some stats about the constraints.
	var totalTermsA, totalTermsB, totalTermsC int
	maxTerms := 0
	for _, c := range r1cs.Constraints {
		totalTermsA += len(c.A)
		totalTermsB += len(c.B)
		totalTermsC += len(c.C)
		for _, terms := range [][]R1CSTerm{c.A, c.B, c.C} {
			if len(terms) > maxTerms {
				maxTerms = len(terms)
			}
		}
	}
	t.Logf("  Total terms: A=%d, B=%d, C=%d", totalTermsA, totalTermsB, totalTermsC)
	t.Logf("  Max terms in a single LC: %d", maxTerms)
	t.Logf("  Avg terms per constraint: A=%.1f, B=%.1f, C=%.1f",
		float64(totalTermsA)/float64(len(r1cs.Constraints)),
		float64(totalTermsB)/float64(len(r1cs.Constraints)),
		float64(totalTermsC)/float64(len(r1cs.Constraints)),
	)
}

func TestCompileRISC0ToSCS(t *testing.T) {
	if _, err := os.Stat(risc0R1CSPath); os.IsNotExist(err) {
		t.Skipf("RISC0 R1CS file not found at %s", risc0R1CSPath)
	}

	t.Log("Parsing RISC0 stark_verify.r1cs...")
	r1cs, err := ParseR1CSFile(risc0R1CSPath)
	if err != nil {
		t.Fatalf("ParseR1CSFile: %v", err)
	}
	t.Logf("Parsed: %d constraints, %d wires", r1cs.Header.NConstraints, r1cs.Header.NWires)

	t.Log("Compiling to SCS (PlonK)... this may take a while for 5.7M constraints")
	circuit := NewCircomCircuit(r1cs)

	start := time.Now()
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, circuit)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	elapsed := time.Since(start)

	t.Logf("Compiled to SCS successfully!")
	t.Logf("  R1CS constraints: %d", r1cs.Header.NConstraints)
	t.Logf("  SCS constraints:  %d", ccs.GetNbConstraints())
	t.Logf("  Blowup factor:    %.2fx", float64(ccs.GetNbConstraints())/float64(r1cs.Header.NConstraints))
	t.Logf("  Public variables: %d", ccs.GetNbPublicVariables())
	t.Logf("  Secret variables: %d", ccs.GetNbSecretVariables())
	t.Logf("  Compile time:     %v", elapsed)
}
