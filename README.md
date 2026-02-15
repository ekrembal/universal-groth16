# Universal Groth16

A universal Groth16 wrapper circuit that verifies any gnark BN254 PlonK proof
in-circuit, combined with aggregation circuits for RISC0 and SP1 proofs, a
WebGPU-accelerated Phase 2 contribution tool, and a ceremony frontend.

## Architecture

```
Inner circuits (any PlonK proof)
  |
  v
groth16wrapper.Circuit          <-- THE auditable circuit
  |                                 Verifies PlonK proof in Groth16
  |                                 2 public inputs: VkHash + PublicInputsHash
  v
Final Groth16 proof (~256 bytes, ~2ms verification)
```

For aggregating RISC0 + SP1 proofs, two approaches are provided:

**Approach A** (`circuits/unified`): Verifies a RISC0 Groth16 proof and an SP1
PlonK proof in a single PlonK circuit, then wraps with Groth16. Trusts RISC0's
Groth16 TSC.

**Approach B** (`circuits/twostage`): Verifies both RISC0 and SP1 as PlonK
proofs (RISC0 STARK verified directly via Circom R1CS), then wraps with
Groth16. Fully trustless -- only requires a universal KZG SRS (Aztec Ignition).

## Repository Structure

```
groth16wrapper/                 Core Groth16 wrapper circuit (audit target)
circuits/
  unified/                      Approach A: Groth16 + PlonK verifier
  twostage/                     Approach B: PlonK + PlonK verifier
risc0bridge/                    RISC0 Groth16 -> PlonK integration
sp1bridge/                      SP1 PlonK integration utilities
circom/                         Circom R1CS -> gnark SCS converter
srs/                            Aztec Ignition SRS management
e2e/                            End-to-end integration tests
webgpu-phase2/                  WebGPU Phase 2 contribution tool
tsc-frontend/                   Ceremony frontend (React)
examples/
  verifiable-encryption/        Full example: Rust (RISC0 + SP1) + Go pipeline
BENCHMARKS.md                   Detailed benchmark results
```

## Quick Start

```bash
# Build all Go packages
cd universal-groth16
go build ./...

# Run the core circuit tests (verifies PlonK proof in Groth16)
go test -v -run TestCircuit ./groth16wrapper/ -timeout 10m

# Run the two-stage pipeline test
go test -v -run TestTwoStageCircuit ./circuits/twostage/ -timeout 30m

# Run e2e tests (RISC0 + SP1 -> same Groth16 wrapper)
go test -v ./e2e/ -timeout 30m

# Download Aztec Ignition SRS (for production use)
go run ./srs/cmd/download/
```

## Key Properties

- **Universal**: One Groth16 trusted setup ceremony works for any inner PlonK
  circuit with the same number of public inputs and the same KZG SRS.
- **Constant-size proofs**: Final Groth16 proof is ~256 bytes with ~2ms
  verification time, regardless of inner circuit complexity.
- **VkHash binding**: The circuit hashes ALL fields of the circuit-specific
  verifying key (Size, SizeInv, Generator, permutations, selectors), ensuring
  that the VkHash uniquely identifies which inner circuit was proven.
- **Public input commitment**: Inner public inputs are hashed (MiMC) and
  exposed as `PublicInputsHash`, allowing the verifier to check them without
  revealing them on-chain.

## Dependencies

- [gnark](https://github.com/consensys/gnark) -- zk-SNARK library (Go)
- [gnark-crypto](https://github.com/consensys/gnark-crypto) -- cryptographic primitives
- Aztec Ignition SRS -- universal KZG trusted setup (2^28 points)

## Benchmarks

See [BENCHMARKS.md](BENCHMARKS.md) for detailed timing and constraint counts.

| Circuit | Constraints | Prove time |
|---------|-------------|------------|
| Groth16 wrapper (1 pub input) | ~1.33M R1CS | ~3.5s |
| Unified PlonK (Approach A) | ~10.4M SCS | ~1m10s |
| Two-Stage PlonK (Approach B) | ~7.7M SCS | ~57s |
| RISC0 STARK verifier (Stage 1a) | ~34M SCS | est. 15-45m |

## License

See the license files in the respective subdirectories.
