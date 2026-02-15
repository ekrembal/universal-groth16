// Package circom provides a parser for the Circom R1CS binary format and
// conversion utilities to gnark's constraint systems.
//
// The Circom R1CS format is documented at:
// https://github.com/iden3/r1csfile/blob/master/doc/r1cs_bin_format.md
//
// Each R1CS constraint has the form: A * B - C = 0
// where A, B, C are linear combinations of wires.
package circom

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"os"
)

// R1CSFile represents a parsed Circom R1CS binary file.
type R1CSFile struct {
	Header      R1CSHeader
	Constraints []R1CSConstraint
	WireLabels  []uint64
}

// R1CSHeader contains the header section of the R1CS file.
type R1CSHeader struct {
	FieldSize    uint32
	Prime        *big.Int
	NWires       uint32
	NPubOut      uint32
	NPubIn       uint32
	NPrvIn       uint32
	NLabels      uint64
	NConstraints uint32
}

// R1CSConstraint represents a single R1CS constraint: A * B - C = 0.
type R1CSConstraint struct {
	A []R1CSTerm // Linear combination A
	B []R1CSTerm // Linear combination B
	C []R1CSTerm // Linear combination C
}

// R1CSTerm represents a single term in a linear combination: coefficient * wire.
type R1CSTerm struct {
	WireID      uint32
	Coefficient *big.Int
}

// ParseR1CSFile parses a Circom R1CS binary file from the given path.
// This uses file seeking to avoid buffering the entire file in memory,
// which is important for large files like RISC0's stark_verify.r1cs (~1.4 GB).
func ParseR1CSFile(path string) (*R1CSFile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	defer f.Close()

	result := &R1CSFile{}

	// Read magic number.
	var magic [4]byte
	if _, err := io.ReadFull(f, magic[:]); err != nil {
		return nil, fmt.Errorf("read magic: %w", err)
	}
	if magic != [4]byte{0x72, 0x31, 0x63, 0x73} {
		return nil, fmt.Errorf("invalid magic: %x (expected r1cs)", magic)
	}

	// Read version.
	var version uint32
	if err := binary.Read(f, binary.LittleEndian, &version); err != nil {
		return nil, fmt.Errorf("read version: %w", err)
	}
	if version != 1 {
		return nil, fmt.Errorf("unsupported version: %d", version)
	}

	// Read number of sections.
	var nSections uint32
	if err := binary.Read(f, binary.LittleEndian, &nSections); err != nil {
		return nil, fmt.Errorf("read nSections: %w", err)
	}

	// First pass: record section offsets and find the header.
	type sectionInfo struct {
		sType  uint32
		offset int64
		size   uint64
	}
	sectionInfos := make([]sectionInfo, nSections)

	for i := uint32(0); i < nSections; i++ {
		var sType uint32
		var sSize uint64
		if err := binary.Read(f, binary.LittleEndian, &sType); err != nil {
			return nil, fmt.Errorf("read section type [%d]: %w", i, err)
		}
		if err := binary.Read(f, binary.LittleEndian, &sSize); err != nil {
			return nil, fmt.Errorf("read section size [%d]: %w", i, err)
		}
		offset, err := f.Seek(0, io.SeekCurrent)
		if err != nil {
			return nil, fmt.Errorf("seek current [%d]: %w", i, err)
		}
		sectionInfos[i] = sectionInfo{sType: sType, offset: offset, size: sSize}

		// Skip section data.
		if _, err := f.Seek(int64(sSize), io.SeekCurrent); err != nil {
			return nil, fmt.Errorf("skip section [%d]: %w", i, err)
		}
	}

	// Parse header first.
	for _, si := range sectionInfos {
		if si.sType == 1 {
			if _, err := f.Seek(si.offset, io.SeekStart); err != nil {
				return nil, fmt.Errorf("seek to header: %w", err)
			}
			if err := parseHeader(f, result); err != nil {
				return nil, fmt.Errorf("parse header: %w", err)
			}
			break
		}
	}
	if result.Header.FieldSize == 0 {
		return nil, fmt.Errorf("no header section found")
	}

	// Parse remaining sections using seek.
	for _, si := range sectionInfos {
		switch si.sType {
		case 1:
			// Already parsed.
		case 2:
			if _, err := f.Seek(si.offset, io.SeekStart); err != nil {
				return nil, fmt.Errorf("seek to constraints: %w", err)
			}
			// Use buffered reader for performance with large constraint sections.
			br := bufio.NewReaderSize(f, 4*1024*1024) // 4MB buffer
			constraints, err := parseConstraints(br, result.Header.NConstraints, result.Header.FieldSize)
			if err != nil {
				return nil, fmt.Errorf("parse constraints: %w", err)
			}
			result.Constraints = constraints
		case 3:
			if _, err := f.Seek(si.offset, io.SeekStart); err != nil {
				return nil, fmt.Errorf("seek to wire labels: %w", err)
			}
			labels, err := parseWireLabels(f, result.Header.NWires)
			if err != nil {
				return nil, fmt.Errorf("parse wire labels: %w", err)
			}
			result.WireLabels = labels
		}
	}

	return result, nil
}

// sectionEntry stores the raw bytes and metadata for a section.
type sectionEntry struct {
	sectionType uint32
	data        []byte
}

// ParseR1CS parses a Circom R1CS binary from a reader.
// Sections may appear in any order; we buffer them and process in dependency order.
func ParseR1CS(r io.Reader) (*R1CSFile, error) {
	result := &R1CSFile{}

	// Read magic number: "r1cs" = 0x72 0x31 0x63 0x73
	var magic [4]byte
	if _, err := io.ReadFull(r, magic[:]); err != nil {
		return nil, fmt.Errorf("read magic: %w", err)
	}
	if magic != [4]byte{0x72, 0x31, 0x63, 0x73} {
		return nil, fmt.Errorf("invalid magic: %x (expected r1cs)", magic)
	}

	// Read version (4 bytes LE).
	var version uint32
	if err := binary.Read(r, binary.LittleEndian, &version); err != nil {
		return nil, fmt.Errorf("read version: %w", err)
	}
	if version != 1 {
		return nil, fmt.Errorf("unsupported version: %d", version)
	}

	// Read number of sections (4 bytes LE).
	var nSections uint32
	if err := binary.Read(r, binary.LittleEndian, &nSections); err != nil {
		return nil, fmt.Errorf("read nSections: %w", err)
	}

	// Read all sections into memory first, then process in order.
	sections := make([]sectionEntry, nSections)
	for i := uint32(0); i < nSections; i++ {
		var sType uint32
		var sSize uint64
		if err := binary.Read(r, binary.LittleEndian, &sType); err != nil {
			return nil, fmt.Errorf("read section type [%d]: %w", i, err)
		}
		if err := binary.Read(r, binary.LittleEndian, &sSize); err != nil {
			return nil, fmt.Errorf("read section size [%d]: %w", i, err)
		}
		data := make([]byte, sSize)
		if _, err := io.ReadFull(r, data); err != nil {
			return nil, fmt.Errorf("read section data [%d, type=%d, size=%d]: %w", i, sType, sSize, err)
		}
		sections[i] = sectionEntry{sectionType: sType, data: data}
	}

	// Process header first (section type 1).
	for _, s := range sections {
		if s.sectionType == 1 {
			if err := parseHeader(bytes.NewReader(s.data), result); err != nil {
				return nil, fmt.Errorf("parse header: %w", err)
			}
			break
		}
	}

	if result.Header.FieldSize == 0 {
		return nil, fmt.Errorf("no header section found")
	}

	// Process remaining sections.
	for _, s := range sections {
		switch s.sectionType {
		case 1:
			// Already parsed.
		case 2: // Constraints
			constraints, err := parseConstraints(bytes.NewReader(s.data), result.Header.NConstraints, result.Header.FieldSize)
			if err != nil {
				return nil, fmt.Errorf("parse constraints: %w", err)
			}
			result.Constraints = constraints
		case 3: // Wire to label map
			labels, err := parseWireLabels(bytes.NewReader(s.data), result.Header.NWires)
			if err != nil {
				return nil, fmt.Errorf("parse wire labels: %w", err)
			}
			result.WireLabels = labels
		default:
			// Skip unknown sections.
		}
	}

	return result, nil
}

func parseHeader(r io.Reader, result *R1CSFile) error {
	h := &result.Header

	// Field size (4 bytes LE).
	if err := binary.Read(r, binary.LittleEndian, &h.FieldSize); err != nil {
		return fmt.Errorf("field size: %w", err)
	}

	// Prime (fieldSize bytes, LE).
	primeBytes := make([]byte, h.FieldSize)
	if _, err := io.ReadFull(r, primeBytes); err != nil {
		return fmt.Errorf("prime: %w", err)
	}
	// Convert from LE to big.Int.
	h.Prime = new(big.Int)
	for i := len(primeBytes) - 1; i >= 0; i-- {
		h.Prime.Lsh(h.Prime, 8)
		h.Prime.Or(h.Prime, big.NewInt(int64(primeBytes[i])))
	}

	// nWires (4 bytes LE).
	if err := binary.Read(r, binary.LittleEndian, &h.NWires); err != nil {
		return fmt.Errorf("nWires: %w", err)
	}

	// nPubOut (4 bytes LE).
	if err := binary.Read(r, binary.LittleEndian, &h.NPubOut); err != nil {
		return fmt.Errorf("nPubOut: %w", err)
	}

	// nPubIn (4 bytes LE).
	if err := binary.Read(r, binary.LittleEndian, &h.NPubIn); err != nil {
		return fmt.Errorf("nPubIn: %w", err)
	}

	// nPrvIn (4 bytes LE).
	if err := binary.Read(r, binary.LittleEndian, &h.NPrvIn); err != nil {
		return fmt.Errorf("nPrvIn: %w", err)
	}

	// nLabels (8 bytes LE).
	if err := binary.Read(r, binary.LittleEndian, &h.NLabels); err != nil {
		return fmt.Errorf("nLabels: %w", err)
	}

	// nConstraints (4 bytes LE).
	if err := binary.Read(r, binary.LittleEndian, &h.NConstraints); err != nil {
		return fmt.Errorf("nConstraints: %w", err)
	}

	return nil
}

func parseConstraints(r io.Reader, nConstraints, fieldSize uint32) ([]R1CSConstraint, error) {
	constraints := make([]R1CSConstraint, nConstraints)
	for i := uint32(0); i < nConstraints; i++ {
		a, err := parseLinearCombination(r, fieldSize)
		if err != nil {
			return nil, fmt.Errorf("constraint %d A: %w", i, err)
		}
		b, err := parseLinearCombination(r, fieldSize)
		if err != nil {
			return nil, fmt.Errorf("constraint %d B: %w", i, err)
		}
		c, err := parseLinearCombination(r, fieldSize)
		if err != nil {
			return nil, fmt.Errorf("constraint %d C: %w", i, err)
		}
		constraints[i] = R1CSConstraint{A: a, B: b, C: c}
	}
	return constraints, nil
}

func parseLinearCombination(r io.Reader, fieldSize uint32) ([]R1CSTerm, error) {
	var nTerms uint32
	if err := binary.Read(r, binary.LittleEndian, &nTerms); err != nil {
		return nil, fmt.Errorf("nTerms: %w", err)
	}

	terms := make([]R1CSTerm, nTerms)
	for j := uint32(0); j < nTerms; j++ {
		var wireID uint32
		if err := binary.Read(r, binary.LittleEndian, &wireID); err != nil {
			return nil, fmt.Errorf("wireID: %w", err)
		}

		coeffBytes := make([]byte, fieldSize)
		if _, err := io.ReadFull(r, coeffBytes); err != nil {
			return nil, fmt.Errorf("coeff: %w", err)
		}

		// Convert from LE to big.Int.
		coeff := new(big.Int)
		for k := len(coeffBytes) - 1; k >= 0; k-- {
			coeff.Lsh(coeff, 8)
			coeff.Or(coeff, big.NewInt(int64(coeffBytes[k])))
		}

		terms[j] = R1CSTerm{WireID: wireID, Coefficient: coeff}
	}
	return terms, nil
}

func parseWireLabels(r io.Reader, nWires uint32) ([]uint64, error) {
	labels := make([]uint64, nWires)
	for i := uint32(0); i < nWires; i++ {
		if err := binary.Read(r, binary.LittleEndian, &labels[i]); err != nil {
			return nil, fmt.Errorf("label %d: %w", i, err)
		}
	}
	return labels, nil
}

// String returns a human-readable summary of the R1CS file.
func (f *R1CSFile) String() string {
	return fmt.Sprintf(
		"R1CS: field=%d bytes, prime=%s, wires=%d, pubOut=%d, pubIn=%d, prvIn=%d, labels=%d, constraints=%d",
		f.Header.FieldSize, f.Header.Prime.Text(16), f.Header.NWires,
		f.Header.NPubOut, f.Header.NPubIn, f.Header.NPrvIn,
		f.Header.NLabels, f.Header.NConstraints,
	)
}

// NPublicInputs returns the total number of public inputs (outputs + inputs).
// Wire 0 is always the constant 1.
// Wires 1..NPubOut are public outputs.
// Wires NPubOut+1..NPubOut+NPubIn are public inputs.
func (h *R1CSHeader) NPublicInputs() uint32 {
	return h.NPubOut + h.NPubIn
}
