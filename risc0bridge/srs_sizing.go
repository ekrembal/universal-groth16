//go:build integrations

package risc0bridge

// SRS Sizing Analysis for Universal PlonK Verifier Pipeline
//
// # Summary
//
// The pipeline requires a KZG SRS (Structured Reference String) for PlonK
// proving. All PlonK circuits in the pipeline must use the same SRS for the
// outer PlonkVerifierGroth16Circuit to verify them.
//
// # Circuit Constraint Counts
//
// | Circuit                          | System | Constraints | SRS (power of 2) |
// |----------------------------------|--------|-------------|-------------------|
// | SP1 recursion (gnark-native)     | SCS    | ~20-60M*    | 2^25 - 2^26      |
// | RISC0 Groth16 verifier (wrapper) | SCS    | ~3.4M       | 2^22              |
// | PlonK verifier (outer Groth16)   | R1CS   | ~1.2M       | N/A (Groth16)     |
//
// (*) SP1's exact constraint count varies by recursion program and is not
//     publicly documented. Conservative estimate based on typical STARK
//     verifiers implemented in gnark.
//
// # SRS Requirement
//
// The SRS size must be at least NextPowerOfTwo(maxConstraints + nbPublicVars).
// Since all inner PlonK circuits share the same SRS:
//   - If SP1 needs 2^25, the SRS must be at least 2^25
//   - The RISC0 wrapper (2^22) fits comfortably within any SRS >= 2^22
//
// # Recommended SRS
//
// Use the Aztec Ignition ceremony SRS:
//   - Max size: ~100.8M points → supports up to 2^26 (~67M constraints)
//   - This is sufficient for all circuits in the pipeline
//   - SP1 already uses this SRS in production
//   - Public download: https://kzg-srs.s3.us-west-2.amazonaws.com/kzg_srs_100800000_bn254_MAIN_IGNITION
//
// # RISC0's Groth16 SRS
//
// RISC0's Circom Groth16 uses Hermez Powers of Tau (2^23), which is a
// different format from KZG SRS. This is for the inner Groth16 proof only;
// the Groth16-to-PlonK wrapper uses the KZG SRS above.
//
// # Groth16 Setup (Outer Circuit)
//
// The outer PlonkVerifierGroth16Circuit uses Groth16 which requires a
// circuit-specific trusted setup ceremony. This is independent of the
// KZG SRS. The outer Groth16 circuit has ~1.2M R1CS constraints.

const (
	// MinSRSPowerForRISC0Wrapper is the minimum SRS power of 2 needed
	// for the RISC0 Groth16 verifier PlonK circuit (~3.4M constraints).
	MinSRSPowerForRISC0Wrapper = 22

	// RecommendedSRSPower is the recommended SRS power of 2 that covers
	// both SP1 and RISC0 circuits with margin.
	RecommendedSRSPower = 25

	// MaxAztecIgnitionPower is the maximum power of 2 supported by the
	// Aztec Ignition SRS (~100.8M points).
	MaxAztecIgnitionPower = 26
)
