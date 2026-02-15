package srs

import (
	"bufio"
	"fmt"
	"log"
	stdbits "math/bits"
	"os"
	"path/filepath"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	kzg_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/kzg"
	"github.com/consensys/gnark-crypto/kzg"
	"github.com/consensys/gnark-ignition-verifier/ignition"
	"github.com/consensys/gnark/constraint"
)

// DefaultSRSDir is the default directory for caching downloaded SRS files.
const DefaultSRSDir = "./srs_cache"

// DefaultSRSPath returns the default path for the canonical SRS file.
func DefaultSRSPath() string {
	return filepath.Join(DefaultSRSDir, "aztec_ignition_bn254.srs")
}

// DownloadAztecIgnitionSRS downloads the Aztec Ignition ceremony SRS, verifies
// all contributions, and saves the resulting KZG SRS in gnark-crypto format.
//
// The SRS supports circuits up to ~100M constraints (2^26+ points).
//
// Parameters:
//   - startIdx: index of the first contribution to verify (174 recommended, this
//     is what SP1 uses). Lower values verify more contributions but take longer.
//   - outputPath: where to save the gnark-crypto SRS file.
//   - cacheDir: directory for caching downloaded ceremony transcripts.
//
// The download is ~2-4 GB and takes 10-30 minutes depending on internet speed.
func DownloadAztecIgnitionSRS(startIdx int, outputPath, cacheDir string) error {
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return fmt.Errorf("create cache dir: %w", err)
	}

	config := ignition.Config{
		BaseURL:  "https://aztec-ignition.s3.amazonaws.com/",
		Ceremony: "MAIN IGNITION",
		CacheDir: cacheDir,
	}

	log.Println("[SRS] Fetching manifest...")
	manifest, err := ignition.NewManifest(config)
	if err != nil {
		return fmt.Errorf("fetch manifest: %w", err)
	}

	log.Printf("[SRS] Manifest: %d participants, %d G1 points",
		len(manifest.Participants), manifest.NumG1Points)

	current, next := ignition.NewContribution(manifest.NumG1Points), ignition.NewContribution(manifest.NumG1Points)

	log.Printf("[SRS] Downloading contribution %d...", startIdx)
	if err := current.Get(manifest.Participants[startIdx], config); err != nil {
		return fmt.Errorf("fetch contribution %d: %w", startIdx, err)
	}

	log.Printf("[SRS] Downloading contribution %d...", startIdx+1)
	if err := next.Get(manifest.Participants[startIdx+1], config); err != nil {
		return fmt.Errorf("fetch contribution %d: %w", startIdx+1, err)
	}
	if !next.Follows(&current) {
		return fmt.Errorf("contribution %d does not follow %d", startIdx+1, startIdx)
	}

	for i := startIdx + 2; i < len(manifest.Participants); i++ {
		log.Printf("[SRS] Processing contribution %d/%d", i+1, len(manifest.Participants))
		current, next = next, current
		if err := next.Get(manifest.Participants[i], config); err != nil {
			return fmt.Errorf("fetch contribution %d: %w", i+1, err)
		}
		if !next.Follows(&current) {
			return fmt.Errorf("contribution %d does not follow %d", i+1, i)
		}
	}

	log.Println("[SRS] All contributions verified ✓")

	// Build KZG SRS from the last valid contribution.
	_, _, _, g2gen := bn254.Generators()
	srs := kzg_bn254.SRS{
		Pk: kzg_bn254.ProvingKey{
			G1: next.G1,
		},
		Vk: kzg_bn254.VerifyingKey{
			G1: next.G1[0],
			G2: [2]bn254.G2Affine{
				g2gen,
				next.G2[0],
			},
		},
	}

	// Save to file.
	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("create SRS file: %w", err)
	}
	defer f.Close()

	if _, err := srs.WriteTo(f); err != nil {
		return fmt.Errorf("write SRS: %w", err)
	}

	log.Printf("[SRS] Saved %d G1 points to %s", len(next.G1), outputPath)
	return nil
}

// LoadCanonicalSRS loads a gnark-crypto KZG SRS from a file saved by
// DownloadAztecIgnitionSRS.
func LoadCanonicalSRS(path string) (*kzg_bn254.SRS, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open SRS: %w", err)
	}
	defer f.Close()

	var srs kzg_bn254.SRS
	if _, err := srs.ReadFrom(bufio.NewReader(f)); err != nil {
		return nil, fmt.Errorf("read SRS: %w", err)
	}
	return &srs, nil
}

// ToLagrangeSRS converts a canonical SRS to Lagrange form sized for the given
// constraint system. This is required by PlonK's Setup function.
func ToLagrangeSRS(cs constraint.ConstraintSystem, canonical kzg.SRS) (kzg.SRS, error) {
	srs, ok := canonical.(*kzg_bn254.SRS)
	if !ok {
		return nil, fmt.Errorf("expected *kzg_bn254.SRS, got %T", canonical)
	}

	sizeSystem := cs.GetNbPublicVariables() + cs.GetNbConstraints()
	nextPowerTwo := 1 << stdbits.Len(uint(sizeSystem))

	if nextPowerTwo > len(srs.Pk.G1) {
		return nil, fmt.Errorf("SRS too small: need %d G1 points, have %d (circuit has %d constraints + %d public vars)",
			nextPowerTwo, len(srs.Pk.G1), cs.GetNbConstraints(), cs.GetNbPublicVariables())
	}

	lagG1, err := kzg_bn254.ToLagrangeG1(srs.Pk.G1[:nextPowerTwo])
	if err != nil {
		return nil, fmt.Errorf("to lagrange: %w", err)
	}

	return &kzg_bn254.SRS{
		Pk: kzg_bn254.ProvingKey{G1: lagG1},
		Vk: srs.Vk,
	}, nil
}
