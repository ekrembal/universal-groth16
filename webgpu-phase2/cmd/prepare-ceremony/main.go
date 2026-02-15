// Command prepare-ceremony compiles the outer Groth16 circuit,
// runs Phase 1 (from scratch or from a PPoT .ptau file),
// initializes Phase 2, and exports the initial Phase 2 binary
// for browser-based contributions.
//
// Usage:
//
//	# Quick mock circuit, Phase 1 from scratch:
//	go run ./webgpu-phase2/cmd/prepare-ceremony --mode=mock --output=phase2_init.bin
//
//	# Real circuit, Phase 1 from PPoT ptau (recommended):
//	go run ./webgpu-phase2/cmd/prepare-ceremony --mode=full --ptau=ppot_0080_21.ptau --output=phase2_init.bin
//
//	# Download a ptau file:
//	go run ./webgpu-phase2/cmd/prepare-ceremony --download-ptau=08 --output=ppot_08.ptau
//
// PPoT ptau files (Perpetual Powers of Tau, 80 contributors):
//
//	https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/ppot_0080_XX.ptau
//
//	Power  Constraints  File size
//	08     256          ~100 KB
//	14     16384        ~18 MB
//	18     262144       ~288 MB
//	21     2097152      ~2.3 GB    ← typical for PlonkVerifierGroth16Circuit
//	28     268435456    ~288 GB    (final)
package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/backend/groth16/bn254/mpcsetup"
	gIo "github.com/consensys/gnark/io"
	"github.com/consensys/gnark/backend/plonk"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	recursion_plonk "github.com/consensys/gnark/std/recursion/plonk"
	"github.com/consensys/gnark/test/unsafekzg"
)

const ptauBaseURL = "https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080"

func main() {
	mode := flag.String("mode", "mock", "Circuit: 'mock' (tiny test) or 'full' (PlonkVerifierGroth16Circuit)")
	output := flag.String("output", "phase2_init.bin", "Output file path")
	ptauPath := flag.String("ptau", "", "Path to .ptau file for Phase 1 (PPoT ceremony). If empty, Phase 1 is generated from scratch.")
	downloadPtau := flag.String("download-ptau", "", "Download a PPoT ptau file by power (e.g. '08', '21', 'final'). Saves to --output path and exits.")
	format := flag.String("format", "raw", "Output format: 'raw' (uncompressed, fast browser parsing) or 'compressed' (gnark default, smaller)")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	// Handle ptau download mode
	if *downloadPtau != "" {
		downloadPtauFile(*downloadPtau, *output)
		return
	}

	useRaw := *format == "raw"

	switch *mode {
	case "mock":
		prepareMock(*output, *ptauPath, useRaw)
	case "full":
		prepareFull(*output, *ptauPath, useRaw)
	default:
		log.Fatalf("unknown mode: %s (use 'mock' or 'full')", *mode)
	}
}

// ════════════════════════════════════════════════════════════════════════
// Circuit compilation
// ════════════════════════════════════════════════════════════════════════

// prepareMock creates a Phase 2 ceremony from a tiny test circuit.
func prepareMock(outputPath, ptauPath string, useRaw bool) {
	log.Println("[mock] Compiling tiny test circuit...")
	start := time.Now()
	ccs := compileTinyCircuit()
	log.Printf("[mock] Compiled: %d constraints, %d pub vars (%.2fs)",
		ccs.GetNbConstraints(), ccs.GetNbPublicVariables(), time.Since(start).Seconds())

	initAndExport(ccs, outputPath, ptauPath, useRaw)
}

// prepareFull creates a Phase 2 ceremony for the real PlonkVerifierGroth16Circuit.
func prepareFull(outputPath, ptauPath string, useRaw bool) {
	field := ecc.BN254.ScalarField()

	// Step 1: Compile mock inner PlonK circuit
	log.Println("[full] Compiling mock inner PlonK circuit...")
	start := time.Now()

	innerCircuit := &MockAccumulatorCircuit{}
	innerCCS, err := frontend.Compile(field, scs.NewBuilder, innerCircuit)
	if err != nil {
		log.Fatalf("compile inner circuit: %v", err)
	}
	log.Printf("[full] Inner circuit: %d SCS constraints (%.2fs)",
		innerCCS.GetNbConstraints(), time.Since(start).Seconds())

	// Step 2: PlonK setup for inner circuit (needed to get VK structure)
	log.Println("[full] Generating inner SRS and PlonK setup...")
	start = time.Now()

	innerSRS, innerSRSLag, err := unsafekzg.NewSRS(innerCCS)
	if err != nil {
		log.Fatalf("inner SRS: %v", err)
	}
	_, innerVK, err := plonk.Setup(innerCCS, innerSRS, innerSRSLag)
	if err != nil {
		log.Fatalf("inner PlonK setup: %v", err)
	}
	log.Printf("[full] Inner PlonK setup done (%.2fs)", time.Since(start).Seconds())

	// Step 3: Compile outer Groth16 circuit
	log.Println("[full] Compiling outer Groth16 circuit (PlonkVerifierGroth16Circuit)...")
	start = time.Now()

	circuitBvk, err := recursion_plonk.ValueOfBaseVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](innerVK)
	if err != nil {
		log.Fatalf("base VK: %v", err)
	}

	outerCircuit := &recursion_plonk.PlonkVerifierGroth16Circuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		BaseKey:           circuitBvk,
		Proof:             recursion_plonk.PlaceholderProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](innerCCS),
		CircuitKey:        recursion_plonk.PlaceholderCircuitVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine](innerCCS),
		InnerPublicInputs: make([]frontend.Variable, innerCCS.GetNbPublicVariables()),
	}

	outerCCS, err := frontend.Compile(field, r1cs.NewBuilder, outerCircuit)
	if err != nil {
		log.Fatalf("compile outer circuit: %v", err)
	}
	r1csCCS := outerCCS.(*cs.R1CS)
	log.Printf("[full] Outer circuit: %d R1CS constraints, %d pub vars (%.2fs)",
		r1csCCS.GetNbConstraints(), r1csCCS.GetNbPublicVariables(), time.Since(start).Seconds())

	initAndExport(r1csCCS, outputPath, ptauPath, useRaw)
}

// ════════════════════════════════════════════════════════════════════════
// Phase 1 → Phase 2 pipeline
// ════════════════════════════════════════════════════════════════════════

// initAndExport builds Phase 1 SrsCommons (from ptau or scratch),
// initializes Phase 2, and writes the binary output.
func initAndExport(ccs *cs.R1CS, outputPath, ptauPath string, useRaw bool) {
	nbConstraints := ccs.GetNbConstraints()
	nbPubVars := ccs.GetNbPublicVariables()

	domainSize := ecc.NextPowerOfTwo(uint64(nbConstraints + nbPubVars))
	domainPower := uint64(log2(domainSize))
	log.Printf("[setup] Domain size: %d (2^%d)", domainSize, domainPower)

	var commons mpcsetup.SrsCommons

	if ptauPath != "" {
		// ── Phase 1 from PPoT ptau file ──────────────────────────────
		log.Printf("[phase1] Loading Phase 1 from PPoT ptau: %s", ptauPath)
		start := time.Now()

		loaded, err := ParsePtauToCommons(ptauPath, domainPower)
		if err != nil {
			log.Fatalf("parse ptau: %v", err)
		}
		commons = *loaded
		log.Printf("[phase1] PPoT Phase 1 loaded (%.2fs)", time.Since(start).Seconds())
		log.Printf("[phase1] Trust assumption: 80 independent PPoT contributors")
	} else {
		// ── Phase 1 from scratch (single contributor, dev only) ──────
		log.Println("[phase1] Generating Phase 1 from scratch (NOT for production)...")
		start := time.Now()

		var p1 mpcsetup.Phase1
		p1.Initialize(domainSize)
		log.Printf("[phase1] Phase 1 initialized (%.2fs)", time.Since(start).Seconds())

		log.Println("[phase1] Contributing to Phase 1...")
		start = time.Now()
		p1.Contribute()
		log.Printf("[phase1] Phase 1 contribution done (%.2fs)", time.Since(start).Seconds())

		log.Println("[phase1] Sealing Phase 1...")
		start = time.Now()
		beaconChallenge := []byte("development-beacon-not-for-production")
		commons = p1.Seal(beaconChallenge)
		log.Printf("[phase1] Phase 1 sealed (%.2fs)", time.Since(start).Seconds())
	}

	// ── Phase 2: circuit-specific initialization ─────────────────────
	log.Println("[phase2] Initializing Phase 2...")
	start := time.Now()

	var p2 mpcsetup.Phase2
	p2.Initialize(ccs, &commons)
	log.Printf("[phase2] Phase 2 initialized (%.2fs)", time.Since(start).Seconds())

	log.Printf("[phase2] State sizes:")
	log.Printf("  G1.Z:        %d points", len(p2.Parameters.G1.Z))
	log.Printf("  G1.PKK:      %d points", len(p2.Parameters.G1.PKK))
	log.Printf("  G1.SigmaCKK: %d commitment groups", len(p2.Parameters.G1.SigmaCKK))
	for i, ck := range p2.Parameters.G1.SigmaCKK {
		log.Printf("    [%d]: %d points", i, len(ck))
	}
	log.Printf("  G2.Sigma:    %d points", len(p2.Parameters.G2.Sigma))

	// ── Serialize and export ─────────────────────────────────────────
	if useRaw {
		log.Println("[export] Serializing Phase 2 state (raw/uncompressed)...")
	} else {
		log.Println("[export] Serializing Phase 2 state (compressed)...")
	}
	start = time.Now()

	var buf bytes.Buffer
	if useRaw {
		if err := writePhase2Raw(&p2, &buf); err != nil {
			log.Fatalf("serialize Phase 2 raw: %v", err)
		}
	} else {
		if _, err := p2.WriteTo(&buf); err != nil {
			log.Fatalf("serialize Phase 2: %v", err)
		}
	}
	log.Printf("[export] Serialized: %d bytes (%.2f MB) in %.2fs",
		buf.Len(), float64(buf.Len())/(1024*1024), time.Since(start).Seconds())

	if err := os.WriteFile(outputPath, buf.Bytes(), 0644); err != nil {
		log.Fatalf("write file: %v", err)
	}
	log.Printf("[export] Written to %s", outputPath)
	log.Println("[done] Phase 2 ceremony file ready for contributions!")
}

// ════════════════════════════════════════════════════════════════════════
// Raw (uncompressed) serialization
// ════════════════════════════════════════════════════════════════════════

// writePhase2Raw serializes a Phase2 using uncompressed (raw) point encoding.
//
// The binary layout matches gnark's Phase2.WriteTo exactly, except that all
// curve points are written in uncompressed form (G1: 64 bytes, G2: 128 bytes).
// gnark's Phase2.ReadFrom auto-detects compressed vs uncompressed, so the raw
// file can still be read back by gnark.
//
// Why raw? Compressed points require a modular square root (fpSqrt) to
// decompress. With ~4M G1 points, that's ~4M 254-bit modular exponentiations
// in JavaScript BigInt — hours of computation. Uncompressed points parse
// instantly by reading x and y directly.
func writePhase2Raw(p2 *mpcsetup.Phase2, w io.Writer) error {
	nbCommitments := len(p2.Parameters.G2.Sigma)

	// 1. nbCommitments (uint16 BE) — same as gnark
	if err := binary.Write(w, binary.BigEndian, uint16(nbCommitments)); err != nil {
		return fmt.Errorf("write nbCommitments: %w", err)
	}

	// 2. Parameters — same order as refsSlice(), but with RawEncoding
	enc := curve.NewEncoder(w, curve.RawEncoding())

	// G1.Delta (single point)
	if err := enc.Encode(&p2.Parameters.G1.Delta); err != nil {
		return fmt.Errorf("encode G1.Delta: %w", err)
	}
	// G1.PKK (slice)
	if err := enc.Encode(p2.Parameters.G1.PKK); err != nil {
		return fmt.Errorf("encode G1.PKK: %w", err)
	}
	// G1.Z (slice)
	if err := enc.Encode(p2.Parameters.G1.Z); err != nil {
		return fmt.Errorf("encode G1.Z: %w", err)
	}
	// G2.Delta (single point)
	if err := enc.Encode(&p2.Parameters.G2.Delta); err != nil {
		return fmt.Errorf("encode G2.Delta: %w", err)
	}
	// SigmaCKK[i] (slices)
	for i := range p2.Parameters.G1.SigmaCKK {
		if err := enc.Encode(p2.Parameters.G1.SigmaCKK[i]); err != nil {
			return fmt.Errorf("encode SigmaCKK[%d]: %w", i, err)
		}
	}
	// G2.Sigma[i] (single points)
	for i := range p2.Parameters.G2.Sigma {
		if err := enc.Encode(&p2.Parameters.G2.Sigma[i]); err != nil {
			return fmt.Errorf("encode G2.Sigma[%d]: %w", i, err)
		}
	}

	// 3. Proofs — use their own WriteTo (compressed, only a few points)
	if _, err := p2.Delta.WriteTo(w); err != nil {
		return fmt.Errorf("write Delta proof: %w", err)
	}
	for i := range p2.Sigmas {
		if _, err := p2.Sigmas[i].WriteTo(w); err != nil {
			return fmt.Errorf("write Sigma[%d] proof: %w", i, err)
		}
	}

	// 4. Challenge
	if _, err := gIo.WriteBytesShort(p2.Challenge, w); err != nil {
		return fmt.Errorf("write challenge: %w", err)
	}

	return nil
}

// ════════════════════════════════════════════════════════════════════════
// PPoT download
// ════════════════════════════════════════════════════════════════════════

func downloadPtauFile(power, outputPath string) {
	var filename string
	if power == "final" {
		filename = "ppot_0080_final.ptau"
	} else {
		filename = fmt.Sprintf("ppot_0080_%s.ptau", power)
	}
	url := fmt.Sprintf("%s/%s", ptauBaseURL, filename)

	log.Printf("[download] Fetching %s ...", url)
	start := time.Now()

	resp, err := http.Get(url)
	if err != nil {
		log.Fatalf("download: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Fatalf("download failed: HTTP %d", resp.StatusCode)
	}

	f, err := os.Create(outputPath)
	if err != nil {
		log.Fatalf("create output: %v", err)
	}
	defer f.Close()

	n, err := io.Copy(f, resp.Body)
	if err != nil {
		log.Fatalf("write: %v", err)
	}

	log.Printf("[download] Saved %s (%d bytes, %.1f MB) in %.1fs",
		outputPath, n, float64(n)/(1024*1024), time.Since(start).Seconds())
}

// ════════════════════════════════════════════════════════════════════════
// Circuits
// ════════════════════════════════════════════════════════════════════════

func log2(n uint64) int {
	count := 0
	for n > 1 {
		n >>= 1
		count++
	}
	return count
}

type tinyCircuit struct {
	X [4]frontend.Variable `gnark:",public"`
}

func (c *tinyCircuit) Define(api frontend.API) error {
	for i := range c.X {
		api.AssertIsEqual(c.X[i], i)
	}
	return nil
}

func compileTinyCircuit() *cs.R1CS {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &tinyCircuit{})
	if err != nil {
		log.Fatalf("compile tiny circuit: %v", err)
	}
	return ccs.(*cs.R1CS)
}

// MockAccumulatorCircuit simulates the inner PlonK circuit (Stage 2 output).
type MockAccumulatorCircuit struct {
	AccumulatorHash frontend.Variable `gnark:",public"`
	SecretA         frontend.Variable
	SecretB         frontend.Variable
}

func (c *MockAccumulatorCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(api.Mul(c.SecretA, c.SecretB), c.AccumulatorHash)
	return nil
}
