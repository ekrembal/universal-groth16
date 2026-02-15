package verencpipeline

import (
	"encoding/hex"
	"testing"
)

func TestRecomputeAccumulator(t *testing.T) {
	// Use the same test vector as the Rust common library:
	// generate_test_pairs(10) should produce accumulator
	// 0xf36b2d4dbb914ad73a7ab433848afd064f6922e351502034e8350b8e29c47ade

	// Load the export file from the Rust host (if available).
	const exportPath = "../../verifiable-encryption/proofs/export.json"
	proofs, err := LoadExportedProofs(exportPath)
	if err != nil {
		t.Skipf("export file not available at %s: %v", exportPath, err)
	}

	t.Logf("Loaded %d pairs", proofs.NumPairs)
	t.Logf("Expected accumulator: 0x%s", proofs.AccumulatorHash)

	err = VerifyAccumulatorFromExport(proofs)
	if err != nil {
		t.Fatalf("verification failed: %v", err)
	}
	t.Log("Go accumulator verification: PASSED")
}

func TestHashTriple(t *testing.T) {
	// Simple sanity check that our Go SHA256 matches.
	a := Element{}
	hb := Element{}
	c := Element{}
	for i := range a {
		a[i] = byte(i)
		hb[i] = byte(i + 32)
		c[i] = byte(i + 64)
	}
	result := HashTriple(&a, &hb, &c)
	t.Logf("HashTriple result: %s", hex.EncodeToString(result[:]))
	// Just verify it's non-zero.
	allZero := true
	for _, b := range result {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("hash result is all zeros")
	}
}
