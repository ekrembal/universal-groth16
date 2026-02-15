// ptau.go — Parse snarkjs/circom Perpetual Powers of Tau (.ptau) files
// and convert to gnark's SrsCommons for Groth16 Phase 1.
//
// The ptau binary format (binfile):
//
//	magic:     4 bytes  "ptau"
//	version:   uint32 LE
//	nSections: uint32 LE
//
//	For each section:
//	  sectionID:   uint32 LE
//	  sectionSize: uint64 LE
//	  data:        [sectionSize] bytes
//
// Section layout:
//
//	1: Header      — n8(4) | prime(n8 LE) | power(4) | ceremonyPower(4)
//	2: tauG1       — (2^(power+1) - 1) × G1 points
//	3: tauG2       — (2^power + 1) × G2 points
//	4: alphaTauG1  — 2^power × G1 points
//	5: betaTauG1   — 2^power × G1 points
//	6: betaG2      — 1 × G2 point
//
// Point encoding (little-endian, uncompressed):
//
//	G1: x(32B LE) | y(32B LE)                       = 64 bytes
//	G2: x.c0(32B LE) | x.c1(32B LE) | y.c0(32B LE) | y.c1(32B LE) = 128 bytes
//
// where c0 = real part (gnark A0), c1 = imaginary part (gnark A1).
package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark/backend/groth16/bn254/mpcsetup"
)

// ptau section IDs
const (
	secHeader     = 1
	secTauG1      = 2
	secTauG2      = 3
	secAlphaTauG1 = 4
	secBetaTauG1  = 5
	secBetaG2     = 6
)

const (
	g1Bytes = 64  // uncompressed G1: 2 × 32
	g2Bytes = 128 // uncompressed G2: 4 × 32
	fpBytes = 32  // BN254 field element
)

// BN254 base field modulus — used to verify the ptau file is for the right curve.
var bn254Prime, _ = new(big.Int).SetString(
	"21888242871839275222246405745257275088696311157297823662689037894645226208583", 10,
)

type sectionInfo struct {
	id     uint32
	size   uint64
	offset int64 // byte offset in the file where section DATA starts
}

// ParsePtauToCommons reads a .ptau file and constructs gnark's SrsCommons.
//
// domainPower is the required log₂(N) where N is the FFT domain size.
// The ptau file must have power ≥ domainPower.
func ParsePtauToCommons(path string, domainPower uint64) (*mpcsetup.SrsCommons, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open ptau: %w", err)
	}
	defer f.Close()

	// ── Read file header ──────────────────────────────────────────────
	magic := make([]byte, 4)
	if _, err := io.ReadFull(f, magic); err != nil {
		return nil, fmt.Errorf("read magic: %w", err)
	}
	if string(magic) != "ptau" {
		return nil, fmt.Errorf("invalid magic: %q (expected \"ptau\")", string(magic))
	}

	var version, nSections uint32
	if err := binary.Read(f, binary.LittleEndian, &version); err != nil {
		return nil, fmt.Errorf("read version: %w", err)
	}
	if err := binary.Read(f, binary.LittleEndian, &nSections); err != nil {
		return nil, fmt.Errorf("read nSections: %w", err)
	}
	log.Printf("[ptau] version=%d, sections=%d", version, nSections)

	// ── Index all sections ────────────────────────────────────────────
	sections, err := indexSections(f, nSections)
	if err != nil {
		return nil, err
	}

	// ── Read & validate header section ────────────────────────────────
	hdr, ok := sections[secHeader]
	if !ok {
		return nil, fmt.Errorf("ptau missing header section")
	}
	power, ceremonyPower, err := readPtauHeader(f, hdr)
	if err != nil {
		return nil, err
	}
	log.Printf("[ptau] power=%d (max 2^%d constraints), ceremony_power=%d, contributors=80",
		power, power, ceremonyPower)

	if uint64(power) < domainPower {
		return nil, fmt.Errorf("ptau power %d too small; circuit needs 2^%d", power, domainPower)
	}

	N := uint64(1) << domainPower

	// ── Read point sections ───────────────────────────────────────────
	commons := new(mpcsetup.SrsCommons)

	// tauG1: need 2N − 1 points
	nTauG1 := 2*N - 1
	log.Printf("[ptau] reading tauG1: %d G1 points (%d MB)...", nTauG1, nTauG1*g1Bytes/1024/1024)
	commons.G1.Tau, err = readG1Section(f, sections, secTauG1, nTauG1)
	if err != nil {
		return nil, fmt.Errorf("tauG1: %w", err)
	}

	// tauG2: need N points (ptau has N+1, take first N)
	log.Printf("[ptau] reading tauG2: %d G2 points (%d MB)...", N, N*g2Bytes/1024/1024)
	commons.G2.Tau, err = readG2Section(f, sections, secTauG2, N)
	if err != nil {
		return nil, fmt.Errorf("tauG2: %w", err)
	}

	// alphaTauG1: need N points
	log.Printf("[ptau] reading alphaTauG1: %d G1 points (%d MB)...", N, N*g1Bytes/1024/1024)
	commons.G1.AlphaTau, err = readG1Section(f, sections, secAlphaTauG1, N)
	if err != nil {
		return nil, fmt.Errorf("alphaTauG1: %w", err)
	}

	// betaTauG1: need N points
	log.Printf("[ptau] reading betaTauG1: %d G1 points (%d MB)...", N, N*g1Bytes/1024/1024)
	commons.G1.BetaTau, err = readG1Section(f, sections, secBetaTauG1, N)
	if err != nil {
		return nil, fmt.Errorf("betaTauG1: %w", err)
	}

	// betaG2: 1 point
	log.Printf("[ptau] reading betaG2...")
	betaSec, ok := sections[secBetaG2]
	if !ok {
		return nil, fmt.Errorf("ptau missing betaG2 section")
	}
	if _, err := f.Seek(betaSec.offset, io.SeekStart); err != nil {
		return nil, fmt.Errorf("seek betaG2: %w", err)
	}
	buf := make([]byte, g2Bytes)
	if _, err := io.ReadFull(f, buf); err != nil {
		return nil, fmt.Errorf("read betaG2: %w", err)
	}
	parseG2Point(buf, &commons.G2.Beta)

	log.Printf("[ptau] SrsCommons loaded successfully")
	return commons, nil
}

// ════════════════════════════════════════════════════════════════════════
// Internal helpers
// ════════════════════════════════════════════════════════════════════════

// indexSections reads all section headers and records their data offsets.
func indexSections(f *os.File, nSections uint32) (map[uint32]sectionInfo, error) {
	sections := make(map[uint32]sectionInfo, nSections)
	for i := uint32(0); i < nSections; i++ {
		var id uint32
		var size uint64
		if err := binary.Read(f, binary.LittleEndian, &id); err != nil {
			return nil, fmt.Errorf("section[%d] id: %w", i, err)
		}
		if err := binary.Read(f, binary.LittleEndian, &size); err != nil {
			return nil, fmt.Errorf("section[%d] size: %w", i, err)
		}
		offset, _ := f.Seek(0, io.SeekCurrent)
		sections[id] = sectionInfo{id: id, size: size, offset: offset}
		if _, err := f.Seek(int64(size), io.SeekCurrent); err != nil {
			return nil, fmt.Errorf("skip section[%d]: %w", i, err)
		}
	}
	return sections, nil
}

// readPtauHeader parses the header section and validates BN254 curve.
func readPtauHeader(f *os.File, sec sectionInfo) (power, ceremonyPower uint32, err error) {
	if _, err = f.Seek(sec.offset, io.SeekStart); err != nil {
		return
	}

	// n8: field element byte size
	var n8 uint32
	if err = binary.Read(f, binary.LittleEndian, &n8); err != nil {
		return
	}
	if n8 != 32 {
		err = fmt.Errorf("unexpected field size %d (expected 32 for BN254)", n8)
		return
	}

	// prime modulus (LE)
	primeBuf := make([]byte, n8)
	if _, err = io.ReadFull(f, primeBuf); err != nil {
		return
	}
	prime := leBytesToBigInt(primeBuf)
	if prime.Cmp(bn254Prime) != 0 {
		err = fmt.Errorf("wrong curve: ptau prime does not match BN254")
		return
	}

	if err = binary.Read(f, binary.LittleEndian, &power); err != nil {
		return
	}
	if err = binary.Read(f, binary.LittleEndian, &ceremonyPower); err != nil {
		return
	}
	return
}

// readG1Section reads `count` G1 points from a ptau section.
func readG1Section(f *os.File, sections map[uint32]sectionInfo, secID uint32, count uint64) ([]curve.G1Affine, error) {
	sec, ok := sections[secID]
	if !ok {
		return nil, fmt.Errorf("missing section %d", secID)
	}
	needed := count * g1Bytes
	if sec.size < needed {
		return nil, fmt.Errorf("section %d: need %d bytes (%d points), have %d",
			secID, needed, count, sec.size)
	}

	if _, err := f.Seek(sec.offset, io.SeekStart); err != nil {
		return nil, err
	}

	// Read all raw bytes for this section at once (faster than many small reads)
	raw := make([]byte, needed)
	if _, err := io.ReadFull(f, raw); err != nil {
		return nil, fmt.Errorf("read %d bytes: %w", needed, err)
	}

	points := make([]curve.G1Affine, count)
	for i := uint64(0); i < count; i++ {
		off := i * g1Bytes
		parseG1Point(raw[off:off+g1Bytes], &points[i])
		if i > 0 && i%1_000_000 == 0 {
			log.Printf("  ... %d / %d", i, count)
		}
	}

	return points, nil
}

// readG2Section reads `count` G2 points from a ptau section.
func readG2Section(f *os.File, sections map[uint32]sectionInfo, secID uint32, count uint64) ([]curve.G2Affine, error) {
	sec, ok := sections[secID]
	if !ok {
		return nil, fmt.Errorf("missing section %d", secID)
	}
	needed := count * g2Bytes
	if sec.size < needed {
		return nil, fmt.Errorf("section %d: need %d bytes (%d points), have %d",
			secID, needed, count, sec.size)
	}

	if _, err := f.Seek(sec.offset, io.SeekStart); err != nil {
		return nil, err
	}

	raw := make([]byte, needed)
	if _, err := io.ReadFull(f, raw); err != nil {
		return nil, fmt.Errorf("read %d bytes: %w", needed, err)
	}

	points := make([]curve.G2Affine, count)
	for i := uint64(0); i < count; i++ {
		off := i * g2Bytes
		parseG2Point(raw[off:off+g2Bytes], &points[i])
		if i > 0 && i%500_000 == 0 {
			log.Printf("  ... %d / %d", i, count)
		}
	}

	return points, nil
}

// parseG1Point converts a 64-byte ptau G1 point (LE) into a gnark G1Affine.
//
//	buf layout: x(32B LE) | y(32B LE)
func parseG1Point(buf []byte, p *curve.G1Affine) {
	p.X = leToFpElement(buf[0:fpBytes])
	p.Y = leToFpElement(buf[fpBytes : 2*fpBytes])
}

// parseG2Point converts a 128-byte ptau G2 point (LE) into a gnark G2Affine.
//
//	buf layout: x.c0(32B LE) | x.c1(32B LE) | y.c0(32B LE) | y.c1(32B LE)
//	gnark E2: A0 = real (c0), A1 = imaginary (c1)
func parseG2Point(buf []byte, p *curve.G2Affine) {
	p.X.A0 = leToFpElement(buf[0:fpBytes])           // x real
	p.X.A1 = leToFpElement(buf[fpBytes : 2*fpBytes])  // x imaginary
	p.Y.A0 = leToFpElement(buf[2*fpBytes : 3*fpBytes]) // y real
	p.Y.A1 = leToFpElement(buf[3*fpBytes : 4*fpBytes]) // y imaginary
}

// leToFpElement converts a 32-byte little-endian field element to gnark's fp.Element.
//
// IMPORTANT: The PPoT (.ptau) file stores field elements in Montgomery form
// (as used by ffjavascript/snarkjs internally), NOT in standard form.
// gnark's fp.Element also uses Montgomery representation internally.
// So we set the uint64 limbs directly from the LE bytes — no conversion needed.
//
// If we used fp.Element.SetBytes(be), it would interpret the bytes as a standard
// value and multiply by R (converting standard → Montgomery), effectively
// double-converting: result = value_mont * R = x * R², which is wrong.
func leToFpElement(le []byte) fp.Element {
	var elem fp.Element
	elem[0] = binary.LittleEndian.Uint64(le[0:8])
	elem[1] = binary.LittleEndian.Uint64(le[8:16])
	elem[2] = binary.LittleEndian.Uint64(le[16:24])
	elem[3] = binary.LittleEndian.Uint64(le[24:32])
	return elem
}

// leBytesToBigInt converts little-endian bytes to a big.Int.
func leBytesToBigInt(le []byte) *big.Int {
	be := make([]byte, len(le))
	for i := range le {
		be[len(le)-1-i] = le[i]
	}
	return new(big.Int).SetBytes(be)
}
