// Command download downloads and verifies the Aztec Ignition ceremony
// SRS, then saves it in gnark-crypto format.
//
// Usage:
//
//	go run ./srs/cmd/download [--output path] [--cache-dir path] [--start-idx N]
//
// The download is ~2-4 GB and takes 10-30 minutes depending on internet speed.
// The resulting SRS file supports circuits up to ~100M constraints.
package main

import (
	"flag"
	"log"

	"github.com/ekrembal/universal-groth16/srs"
)

func main() {
	output := flag.String("output", srs.DefaultSRSPath(), "output path for the SRS file")
	cacheDir := flag.String("cache-dir", "./data", "directory for caching downloaded ceremony transcripts")
	startIdx := flag.Int("start-idx", 174, "start contribution index (174 recommended, matches SP1)")
	flag.Parse()

	log.Printf("Downloading Aztec Ignition SRS (start=%d) → %s", *startIdx, *output)
	log.Printf("Cache dir: %s", *cacheDir)

	if err := srs.DownloadAztecIgnitionSRS(*startIdx, *output, *cacheDir); err != nil {
		log.Fatalf("FATAL: %v", err)
	}

	log.Println("Done!")
}
