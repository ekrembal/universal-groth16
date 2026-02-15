package circom

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
)

// LoadWitnessBin loads a witness from a binary file.
// The binary format is: [4 bytes LE: nWires] [fieldSize bytes LE: wire_0] ... [fieldSize bytes LE: wire_{n-1}]
func LoadWitnessBin(path string, fieldSize uint32) ([]*big.Int, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	defer f.Close()
	return ReadWitnessBin(f, fieldSize)
}

// ReadWitnessBin reads a witness from a binary reader.
func ReadWitnessBin(r io.Reader, fieldSize uint32) ([]*big.Int, error) {
	var nWires uint32
	if err := binary.Read(r, binary.LittleEndian, &nWires); err != nil {
		return nil, fmt.Errorf("read nWires: %w", err)
	}

	witness := make([]*big.Int, nWires)
	for i := uint32(0); i < nWires; i++ {
		valBytes := make([]byte, fieldSize)
		if _, err := io.ReadFull(r, valBytes); err != nil {
			return nil, fmt.Errorf("read wire %d: %w", i, err)
		}
		// Convert from LE to big.Int.
		val := new(big.Int)
		for k := len(valBytes) - 1; k >= 0; k-- {
			val.Lsh(val, 8)
			val.Or(val, big.NewInt(int64(valBytes[k])))
		}
		witness[i] = val
	}
	return witness, nil
}

// LoadWitnessJSON loads a witness from a JSON file.
// The JSON format is: {"witness": ["decimal_string", ...]}
// or just an array: ["decimal_string", ...]
func LoadWitnessJSON(path string) ([]*big.Int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}

	// Try array-of-strings format first.
	var arr []string
	if err := json.Unmarshal(data, &arr); err == nil {
		return parseWitnessStrings(arr)
	}

	// Try object format: {"witness": [...]}
	var obj struct {
		Witness []string `json:"witness"`
	}
	if err := json.Unmarshal(data, &obj); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	return parseWitnessStrings(obj.Witness)
}

func parseWitnessStrings(strs []string) ([]*big.Int, error) {
	witness := make([]*big.Int, len(strs))
	for i, s := range strs {
		val := new(big.Int)
		if _, ok := val.SetString(s, 10); !ok {
			// Try hex.
			if _, ok := val.SetString(s, 16); !ok {
				return nil, fmt.Errorf("invalid value at index %d: %s", i, s)
			}
		}
		witness[i] = val
	}
	return witness, nil
}

// SaveWitnessBin writes a witness to a binary file.
func SaveWitnessBin(path string, witness []*big.Int, fieldSize uint32) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create: %w", err)
	}
	defer f.Close()

	if err := binary.Write(f, binary.LittleEndian, uint32(len(witness))); err != nil {
		return fmt.Errorf("write nWires: %w", err)
	}

	for i, val := range witness {
		valBytes := make([]byte, fieldSize)
		b := val.Bytes()
		// Convert from big-endian to LE.
		for j := 0; j < len(b) && j < int(fieldSize); j++ {
			valBytes[j] = b[len(b)-1-j]
		}
		if _, err := f.Write(valBytes); err != nil {
			return fmt.Errorf("write wire %d: %w", i, err)
		}
	}
	return nil
}

// SaveWitnessJSON writes a witness to a JSON file.
func SaveWitnessJSON(path string, witness []*big.Int) error {
	strs := make([]string, len(witness))
	for i, val := range witness {
		strs[i] = val.Text(10)
	}
	data, err := json.MarshalIndent(strs, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}

// LoadWitnessWtns loads a Circom .wtns (witness) binary file.
// Format: magic "wtns" (4 bytes), version (4 bytes LE), nSections (4 bytes LE),
// then sections:
//   Section type 1: header
//     fieldSize (4 bytes LE), prime (fieldSize bytes LE), nWires (4 bytes LE)
//   Section type 2: witness values
//     nWires * fieldSize bytes (each value in LE)
func LoadWitnessWtns(path string) ([]*big.Int, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	defer f.Close()

	// Magic.
	var magic [4]byte
	if _, err := io.ReadFull(f, magic[:]); err != nil {
		return nil, fmt.Errorf("read magic: %w", err)
	}
	if magic != [4]byte{'w', 't', 'n', 's'} {
		return nil, fmt.Errorf("invalid magic: %x", magic)
	}

	// Version.
	var version uint32
	if err := binary.Read(f, binary.LittleEndian, &version); err != nil {
		return nil, fmt.Errorf("read version: %w", err)
	}

	// nSections.
	var nSections uint32
	if err := binary.Read(f, binary.LittleEndian, &nSections); err != nil {
		return nil, fmt.Errorf("read nSections: %w", err)
	}

	var fieldSize, nWires uint32
	var witness []*big.Int

	for i := uint32(0); i < nSections; i++ {
		var sectionType uint32
		var sectionSize uint64
		if err := binary.Read(f, binary.LittleEndian, &sectionType); err != nil {
			return nil, fmt.Errorf("read section type: %w", err)
		}
		if err := binary.Read(f, binary.LittleEndian, &sectionSize); err != nil {
			return nil, fmt.Errorf("read section size: %w", err)
		}

		switch sectionType {
		case 1: // Header
			if err := binary.Read(f, binary.LittleEndian, &fieldSize); err != nil {
				return nil, fmt.Errorf("read fieldSize: %w", err)
			}
			// Skip prime.
			primeBytes := make([]byte, fieldSize)
			if _, err := io.ReadFull(f, primeBytes); err != nil {
				return nil, fmt.Errorf("read prime: %w", err)
			}
			if err := binary.Read(f, binary.LittleEndian, &nWires); err != nil {
				return nil, fmt.Errorf("read nWires: %w", err)
			}

		case 2: // Witness
			if fieldSize == 0 || nWires == 0 {
				return nil, fmt.Errorf("witness section before header")
			}
			witness = make([]*big.Int, nWires)
			for j := uint32(0); j < nWires; j++ {
				valBytes := make([]byte, fieldSize)
				if _, err := io.ReadFull(f, valBytes); err != nil {
					return nil, fmt.Errorf("read wire %d: %w", j, err)
				}
				val := new(big.Int)
				for k := len(valBytes) - 1; k >= 0; k-- {
					val.Lsh(val, 8)
					val.Or(val, big.NewInt(int64(valBytes[k])))
				}
				witness[j] = val
			}

		default:
			// Skip unknown sections.
			buf := make([]byte, sectionSize)
			if _, err := io.ReadFull(f, buf); err != nil {
				return nil, fmt.Errorf("skip section: %w", err)
			}
		}
	}

	if witness == nil {
		return nil, fmt.Errorf("no witness section found")
	}
	return witness, nil
}
