# Benchmarks

All measurements on Apple Silicon (M-series), single-threaded gnark, BN254 curve.

> **Important**: Both approaches currently use **mock inner circuits** (1-5 constraints)
> to simulate RISC0 and SP1 proofs. The unified verifier circuits and Groth16 wrappers
> are real and fully tested, but the inner proofs they verify are trivial placeholders.
> Real inner proofs require running the actual RISC0 / SP1 proving pipelines.

---

## Two Approaches

We implemented two complete pipelines that both produce a single Groth16 proof attesting
that both a RISC0 proof and an SP1 proof are valid. They differ in how RISC0's proof
is handled:

| | **Approach A**: Groth16 + PlonK | **Approach B**: Two-Stage PlonK |
|---|---|---|
| **RISC0 inner proof** | RISC0's native Groth16 (trusts RISC0 TSC) | RISC0 STARK verified in PlonK (trustless) |
| **SP1 inner proof** | SP1's native PlonK | SP1's native PlonK |
| **Unified circuit** | `UnifiedVerifierCircuit` (Groth16 verifier + PlonK verifier) | `TwoStagePlonKCircuit` (two PlonK verifiers) |
| **Outer wrapper** | `PlonkVerifierGroth16Circuit` | `PlonkVerifierGroth16Circuit` |
| **Trust assumption** | Trusts RISC0 Groth16 TSC | Trustless (universal KZG SRS only) |
| **Code** | `pipeline/unified.go` | `pipeline/unified_plonk.go` |

---

## Approach A: Groth16 + PlonK (trusts RISC0 TSC)

```
RISC0 Groth16 proof (5 pub inputs) ──┐
                                      ├─→ UnifiedVerifierCircuit (PlonK)
SP1 PlonK proof (2 pub inputs) ──────┘           │
                                                  └─→ PlonkVerifierGroth16Circuit (Groth16)
                                                              │
                                                              └─→ Final Groth16 proof
```

### Constraint sizes

| Circuit | System | Constraints | Public vars |
|---------|--------|-------------|-------------|
| RISC0 inner (mock) | R1CS | ~5 | 5 |
| SP1 inner (mock) | SCS | ~3 | 2 |
| **Unified PlonK verifier** | **SCS** | **~10,370,000** | **5** |
| **Outer Groth16 wrapper** | **R1CS** | **~1,370,000** | **3** |

### Timings (with mock inner proofs)

| Stage | Time |
|-------|------|
| Unified PlonK compile | ~5.5s |
| Unified PlonK setup (unsafekzg) | ~1m50s |
| Unified PlonK prove + verify | ~1m10s |
| Outer Groth16 compile | ~5s |
| Outer Groth16 setup (mock TSC) | ~1m20s |
| Outer Groth16 prove + verify | ~3.5s |
| **Total pipeline** | **~5m** |

### SRS requirements

- **Unified PlonK**: needs KZG SRS with at least 2^24 G1 points (~16.7M) to support the ~10.4M SCS circuit. Aztec Ignition ceremony provides 2^28 points (268M), which is sufficient.
- **Outer Groth16**: uses circuit-specific setup (mock or real TSC), no SRS sharing needed.

### Notes

- The ~10.4M SCS constraint count comes from verifying one Groth16 proof (BN254 pairing verification, ~6M constraints) plus one PlonK proof (~3.8M constraints) plus the method_id/VkeyHash checks and public-input pass-through.
- The Groth16 verifier inside the PlonK circuit is expensive because it requires emulated BN254 pairing arithmetic.
- **Trust assumption**: relies on RISC0's Groth16 trusted setup ceremony (238 contributions, audited).

---

## Approach B: Two-Stage PlonK (trustless)

```
Stage 1a: RISC0 succinct STARK proof
  → Circom R1CS → gnark SCS → PlonK proof

Stage 1b: SP1 compressed STARK
  → SP1 native pipeline → PlonK proof

Stage 2: TwoStagePlonKCircuit
  → Verifies both Stage 1 PlonK proofs
  → Checks hardcoded method_id / VkeyHash
  → Exposes AccumulatorHash as public output
  → Single PlonK proof

Stage 3: PlonkVerifierGroth16Circuit
  → Wraps Stage 2 PlonK proof in Groth16
  → Final Groth16 proof (2 public inputs: VkHash + PublicInputsHash)
```

### RISC0 STARK verifier circuit (real, parsed from `stark_verify.r1cs`)

| Metric | Value |
|--------|-------|
| Circom R1CS constraints | 5,676,573 |
| gnark SCS constraints | 34,361,125 |
| R1CS → SCS blowup factor | 6.05x |
| Wires | 5,635,930 |
| Public outputs | 5 |
| Private inputs (IOP elements) | 25,749 |
| Field | BN254 (same as gnark) |
| R1CS file size | 1.4 GB |
| R1CS file SHA-256 | `84d3c34b7c0eb55ad1b16b24f75e0b9de307f7b74089ea4a20a998390ee24178` |
| R1CS parse time | ~18s |
| SCS compile time | ~24s |

### Constraint sizes

| Circuit | System | Constraints | Public vars |
|---------|--------|-------------|-------------|
| **Stage 1a: RISC0 STARK verifier** | **SCS** | **34,361,125** | **5** |
| Stage 1b: SP1 (mock) | SCS | ~1 | 2 |
| **Stage 2: Unified PlonK verifier** | **SCS** | **7,730,159** | **1** |
| **Stage 3: Outer Groth16 wrapper** | **R1CS** | **1,329,160** | **3** |

### Timings

| Stage | Time | Notes |
|-------|------|-------|
| Stage 1a: RISC0 STARK PlonK compile | ~24s | Real circuit, 34M SCS |
| Stage 1a: RISC0 STARK PlonK setup | **est. 15-30 min** | Not yet measured (needs ~2^26 SRS) |
| Stage 1a: RISC0 STARK PlonK prove | **est. 15-45 min** | Not yet measured |
| Stage 1b: SP1 PlonK | ~2-5 min | SP1's native pipeline (external) |
| Stage 2: Unified PlonK compile | ~3.7s | |
| Stage 2: Unified PlonK setup | ~1m33s | |
| **Stage 2: Unified PlonK prove** | **~57s** | |
| Stage 2: Unified PlonK verify | ~2ms | |
| Stage 3: Outer Groth16 compile | ~3.6s | |
| Stage 3: Outer Groth16 setup (mock TSC) | ~1m19s | One-time per circuit |
| **Stage 3: Outer Groth16 prove** | **~3.7s** | |
| **Stage 3: Outer Groth16 verify** | **~2ms** | |
| **End-to-end (est.)** | **~20-50 min** | Dominated by Stage 1a |

### SRS requirements

- **Stage 1a** (RISC0 STARK PlonK): needs KZG SRS with at least 2^26 G1 points (~67M) for the 34M SCS circuit. Aztec Ignition provides 2^28 points (268M), sufficient.
- **Stage 2** (Unified PlonK): needs at least 2^24 points (~16.7M) for the 7.7M SCS circuit.
- **Stage 3** (Outer Groth16): circuit-specific setup, no SRS sharing.

### Why the Stage 2 circuit is smaller than Approach A

In Approach A, the unified circuit verifies a **Groth16 proof** (~6M constraints for BN254 pairing)
plus a **PlonK proof** (~3.8M constraints), totaling ~10.4M SCS constraints.

In Approach B, Stage 2 verifies **two PlonK proofs** (~3.8M each), totaling ~7.7M SCS constraints.
PlonK verification is cheaper than Groth16 verification in-circuit because it avoids the expensive
emulated pairing computation (PlonK uses KZG batch verification with a single pairing check).

---

## Comparison

| Metric | Approach A (Groth16 + PlonK) | Approach B (Two-Stage PlonK) |
|--------|------------------------------|------------------------------|
| Trust model | Trusts RISC0 Groth16 TSC | Fully trustless |
| Unified circuit constraints | ~10.4M SCS | ~7.7M SCS |
| Outer Groth16 constraints | ~1.37M R1CS | ~1.33M R1CS |
| Total stages | 2 (unified PlonK → Groth16) | 4 (RISC0 PlonK → SP1 PlonK → unified PlonK → Groth16) |
| End-to-end prove time | ~5 min (mock inner) | ~20-50 min (dominated by Stage 1a RISC0 STARK) |
| Final proof verify time | ~2ms | ~2ms |
| Final proof size | ~256 bytes | ~256 bytes |
| Implementation complexity | Lower | Higher (Circom R1CS parser, witness pipeline) |
| KZG SRS needed | 2^24 points | 2^26 points (for Stage 1a) |

### When to use which

- **Approach A** is appropriate if you trust RISC0's Groth16 trusted setup ceremony and want faster end-to-end proving.
- **Approach B** is appropriate if you want zero trust assumptions beyond the universal KZG SRS (Aztec Ignition) and are willing to accept longer proving times.

Both approaches produce an identical final artifact: a BN254 Groth16 proof with 2 public inputs (VkHash + PublicInputsHash) that can be verified on-chain in ~2ms.

---

## What uses mock proofs

| Component | Status |
|-----------|--------|
| Circom R1CS parser | **Real** -- tested with actual `stark_verify.r1cs` (5.7M constraints) |
| R1CS → SCS compiler | **Real** -- compiled actual RISC0 circuit to 34M SCS constraints |
| Witness pipeline (Rust) | **Built** -- `risc0-witness-gen` binary compiles, not yet run with real STARK proof |
| RISC0 seal export (Rust) | **Built** -- `--export-seal` flag added, needs real RISC0 succinct proof |
| RISC0 inner proof in unified circuit | **Mock** -- tiny 5-constraint circuit simulates RISC0 |
| SP1 inner proof in unified circuit | **Mock** -- tiny 2-constraint circuit simulates SP1 |
| Stage 2 unified PlonK verifier | **Real circuit** -- verifies real PlonK proofs (of mock inner circuits) |
| Stage 3 outer Groth16 wrapper | **Real circuit** -- verifies real PlonK proof, produces real Groth16 proof |
| Groth16 trusted setup | **Mock** -- uses `groth16.Setup()` not a real ceremony |
| KZG SRS | **Mock** -- uses `unsafekzg.NewSRS()` not Aztec Ignition |

To move to production:
1. Generate real RISC0 succinct STARK proof (`--export-seal`)
2. Run the Circom witness generator with the real seal
3. Generate Stage 1a PlonK proof with the real 34M SCS circuit and real witness
4. Generate real SP1 PlonK proof from SP1's pipeline
5. Feed both real proofs into Stage 2
6. Download Aztec Ignition SRS (replace unsafekzg)
7. Run real Groth16 TSC (replace mock setup)

---

## Files

| File | Description |
|------|-------------|
| `pipeline/unified.go` | Approach A: `UnifiedVerifierCircuit` (Groth16 + PlonK) |
| `pipeline/unified_test.go` | Approach A: full pipeline test with mock proofs |
| `pipeline/benchmark_test.go` | Approach A: detailed benchmark with timings |
| `pipeline/unified_plonk.go` | Approach B: `TwoStagePlonKCircuit` (PlonK + PlonK) |
| `pipeline/unified_plonk_test.go` | Approach B: Stage 2 test with mock proofs |
| `pipeline/benchmark_full_test.go` | Approach B: full pipeline benchmark (Stage 1-3) |
| `pipeline/outer_groth16_test.go` | Approach B: Stage 3 standalone test |
| `pipeline/circom/r1cs_parser.go` | Circom R1CS binary format parser |
| `pipeline/circom/converter.go` | R1CS-to-gnark circuit converter |
| `pipeline/circom/witness.go` | Witness loading (.wtns, .json, .bin) |
| `pipeline/circom/pipeline.go` | End-to-end Circom-to-PlonK orchestrator |
| `pipeline/circom/risc0_test.go` | Tests with real RISC0 `stark_verify.r1cs` |
| `pipeline/srs.go` | Aztec Ignition SRS download / management |
| `std/recursion/plonk/verifier_groth16.go` | `PlonkVerifierGroth16Circuit` (outer wrapper) |
| `verifiable-encryption/risc0-verenc/host/` | RISC0 host with `--export-seal` |
| `verifiable-encryption/risc0-verenc/witness-gen/` | Circom witness generator (circom-witnesscalc) |
