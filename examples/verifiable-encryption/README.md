# Verifiable Encryption Pipeline

Proves verifiable XOR encryption using both RISC0 and SP1 ZKVMs, then compresses
both proofs into a single Groth16 proof via a unified PlonK circuit.

## Architecture

```
RISC0 STARK proof (5 pub inputs) ─┐
                                   ├─→ Unified PlonK circuit (gnark)
SP1 STARK→PlonK proof (2 pub inputs) ─┘       │
                                               ├─→ Single PlonK proof
                                               │
                                               └─→ Groth16 wrapper (gnark)
                                                       │
                                                       └─→ Final Groth16 proof
                                                            (2 public inputs)
```

## Computation

Given pairs `(a_i, b_i)` of 32-byte elements:

- `c_i = a_i XOR b_i` (ciphertext)
- `h(b_i) = SHA256(b_i)` (commitment)
- `inner_i = SHA256(a_i || h(b_i) || c_i)` (triple hash)
- `accumulator = fold(inner_0, ..., inner_n)` where `fold(x, y) = SHA256(x || y)`

The accumulator hash is the public output proven by both ZKVMs.

## Project Structure

```
common/           # Shared Rust library (no_std, SHA256 accumulator)
risc0-verenc/     # RISC0 guest + host
sp1-verenc/       # SP1 guest + host
host/             # Orchestrator (generates test data, exports)
bridge/           # Proof serialization for Go pipeline
verifier/         # Rust verification function
```

## Quick Start

### 1. Generate test data

```bash
cd host && cargo run -- --num-pairs 10 --output-dir ../proofs
```

### 2. Run RISC0 prover

```bash
cd risc0-verenc
# Execute only (fast, no proof):
cargo run --release -- --execute --num-pairs 10
# STARK proof:
cargo run --release -- --prove --num-pairs 10
# Full Groth16 (RISC0 standard flow):
cargo run --release -- --prove-groth16 --num-pairs 10
```

### 3. Run SP1 prover

```bash
cd sp1-verenc
# Execute only:
cargo run --release --bin verenc-sp1 -- --execute --num-pairs 10
# STARK proof (compressed):
cargo run --release --bin verenc-sp1 -- --prove --num-pairs 10
# PlonK proof:
cargo run --release --bin verenc-sp1 -- --prove-plonk --num-pairs 10
# Groth16 (SP1 standard flow):
cargo run --release --bin verenc-sp1 -- --prove-groth16 --num-pairs 10
```

### 4. Verify accumulator (Rust)

```bash
cd verifier && cargo run -- ../proofs/export.json
```

### 5. Run Go pipeline (PlonK + Groth16 compression)

```bash
cd ../gnark
go test -v -run TestBenchmarkFullPipeline -timeout=3600s ./pipeline/...
```

## Benchmarks (10 pairs, Apple Silicon)

| Stage | Time | Constraints |
|-------|------|-------------|
| RISC0 STARK (succinct) | ~81s | - |
| SP1 STARK (compressed) | ~97s | - |
| Unified PlonK circuit | ~3min | ~7.6M SCS |
| Outer Groth16 circuit | ~30s | ~1.3M R1CS |
| **Total pipeline** | **~5-6min** | - |

## Verification

The verifier takes:
- The final Groth16 proof
- Arrays: `a_1, ..., a_n`, `h(b_1), ..., h(b_n)`, `c_1, ..., c_n`

It recomputes the accumulator hash and verifies the Groth16 proof.
The verifier learns `a_i` (keys) and `c_i` (ciphertexts) but NOT `b_i` (plaintexts).
