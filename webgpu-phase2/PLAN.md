# Implementation & Testing Plan

## Overview

This plan covers implementing WebGPU primitives for Phase 2 TSC and testing them against gnark's reference implementation. We use **[demox-labs/webgpu-crypto](https://github.com/demox-labs/webgpu-crypto)** for BN254 and adapt it for Phase 2's batch scalar multiplication.

---

## Part A: demox-labs/webgpu-crypto Integration

### 1. What webgpu-crypto Provides

| Component | Path | Use for Phase 2 |
|-----------|------|-----------------|
| BN254 Curve WGSL | `src/gpu/wgsl/BN254CurveBaseWGSL.ts` | G1 add, double, scalar mul |
| BN254 Params | `src/gpu/wgsl/BN254Params.ts`, `params/BN254Constants.ts` | Fp, Fr moduli |
| Point scalar mul | `entries/pointScalarMultipassReuseBuffer.ts` | Per-point `[s]·P` (multipass) |
| Naive MSM | `entries/naiveMSMEntry.ts` | Per-point mul + batch pattern |
| Chunking | `utils.ts`: `chunkArray`, `chunkGPUInputs` | Batching for buffer limits |
| Utils | `bigIntToU32Array`, `u32ArrayToBigInts` | Endian conversion |

**Note**: webgpu-crypto's `pointScalarMultipassReuseBuffer` is hardcoded to BLS12_377; we need BN254. Use `naiveMSMEntry` (accepts `curve: CurveType.BN254`) or fork and parameterize. The inverse step currently outputs only x; Phase 2 needs full affine (x, y). Extend to output (x/z², y/z³) or add Montgomery batch inversion.

### 2. Coordinate Systems & Batch Inversion

- **gnark**: Stores Affine (X, Y); does arithmetic in Jacobian/Projective (X, Y, Z).
- **webgpu-crypto**: Uses Extended/Projective (x, y, t, z) for BLS12-377; BN254 uses Projective (x, y, z).
- **Phase 2 workflow**:
  1. Read Affine points from input buffer.
  2. Convert to Jacobian/Projective for scalar multiplication.
  3. **Convert back to Affine** before writing: (x/z², y/z³) requires per-point inversion of z.

**Batch inversion options**:

| Option | Pros | Cons |
|--------|------|------|
| **Montgomery batch inversion in WGSL** | All on GPU, fast | Multi-pass compute shader |
| **Read Z to CPU, invert in WASM, pass back** | Simpler | CPU-GPU transfer |
| **Extend webgpu-crypto inverse step** | Reuse existing | Output (x,y) affine per point |

**Recommendation**: Extend webgpu-crypto's inverse step to output full affine (x, y). If that's not feasible, implement Montgomery batch inversion in WGSL (or use a multi-pass approach: compute z⁻¹, then x/z², y/z³).

### 3. WebGPU Buffer Limits

| Limit | Typical value | Notes |
|-------|---------------|-------|
| `maxStorageBufferBindingSize` | **128 MB** | Per binding; often 128 MB on consumer GPUs |
| `maxBufferSize` | Up to 4 GB | Larger, but binding is capped |

**Phase 2 sizing**:
- 2M points × 64 bytes = **128 MB** per buffer (G1 Affine).
- 2M points × 32 bytes = 64 MB per scalar buffer.
- **At limit**: A single 128 MB buffer may fail on some devices.

**Batching strategy**:
- Chunk size: **2¹⁸ = 262,144 points** → 16 MB per buffer (safe).
- Or **2¹⁹ = 524,288 points** → 32 MB per buffer.
- Query `device.limits.maxStorageBufferBindingSize` at runtime; choose batch size so `batchSize × 64 ≤ limit × 0.9`.

### 4. Endianness

| Layer | Format | Notes |
|-------|--------|-------|
| gnark / Go | Big-Endian | Standard BN254 serialization |
| WebGPU / WGSL | Little-Endian | u32 limbs native |
| WASM memory | Little-Endian | |

**Action**: Perform endian swaps in the **TypeScript binding layer** before sending buffers to the GPU and after reading results. Use `bigIntToU32Array` / `u32ArrayToBigInts` (webgpu-crypto) or equivalent; ensure gnark bytes (Big-Endian) are converted to the format webgpu-crypto expects (Little-Endian u32 limbs).

---

## Part B: gnark Testing Patterns (to Reuse)

### 1. gnark Phase 2 Test Structure (unchanged)

**Location**: `backend/groth16/bn254/mpcsetup/setup_test.go`

| Test | Purpose | Reusable for WebGPU |
|------|---------|---------------------|
| `TestCommonsUpdate` | SrsCommons.update with known (tau,α,β) | **Yes** — golden vectors for scalar mul |
| `TestPhase2` | Phase2.Contribute + Verify | **Yes** — full contribute roundtrip |
| `TestPedersen` | Phase2.update with known delta, sigma | **Yes** — isolated update test |
| `TestAll` | Full Phase1+Phase2 chain | **Yes** — integration |
| `commonsSmallValues(N, tau, alpha, beta)` | Deterministic SRS | **Yes** — test vector source |

### 2. gnark Assertion Helpers

```go
// setup_test.go
assertG1VectorEqual(t, "name", expected, computed []curve.G1Affine)
  → require.Equal for each element

assertG1G2Equal(t, p1 curve.G1Affine, p2 curve.G2Affine)
  → pairing check: e(p1, g2) = e(g1, p2)

assertPairingsEqual(t, p1, p2, q1, q2)
  → e(p1, p2) · e(q1, q2) = 1
```

**WebGPU equivalent**: Compare bytes (G1 64B, G2 128B) or run pairing in WASM for cross-check.

### 3. Test Vector Generation (Go → JSON)

Add a small Go tool or test that exports:

```json
{
  "fp_modulus": "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001",
  "g1_generator": "0x...",
  "g1_scalar_mul": [
    { "point": "0x...", "scalar": "0x...", "expected": "0x..." },
    ...
  ],
  "phase2_scale_slice": [
    { "points": ["0x...", ...], "scalar": "0x...", "expected": ["0x...", ...] }
  ],
  "commons_small_N8": { "tau": 2, "alpha": 3, "beta": 4, "G1_Tau": [...], ... }
}
```

**Location**: `webgpu-phase2/testvectors/generate_test.go` or `cmd/generate-testvectors/`

---

## Part C: Implementation Phases (Using webgpu-crypto)

### Phase 1: Integrate webgpu-crypto BN254

1. Add `demox-labs/webgpu-crypto` (or fork) as dependency.
2. Verify BN254 params match gnark (Fp, Fr moduli).
3. **Tests**: Run webgpu-crypto's existing BN254 tests; compare G1 scalar mul against gnark test vectors.

### Phase 2: Batch Scalar Mul for Phase 2

1. Adapt `pointScalarMultipassReuseBuffer` (or `naiveMSMEntry` per-point path) for **single scalar, many points**: `scaleG1Slice(P[], s)`.
2. Ensure output is **full Affine (x, y)** — extend inverse step if needed.
3. **Tests**: Small slice (8, 64 points) vs gnark `scaleG1Slice`; use `phase2_vectors.json`.

### Phase 3: Batching & Chunking (TypeScript Layer)

1. Implement `scaleG1SliceBatched(points: Uint8Array, scalar: bigint)`:
   - Query `device.limits.maxStorageBufferBindingSize`.
   - Chunk points into batches of ≤ `limit / 64` (e.g. 2¹⁸ points).
   - For each chunk: endian-convert → GPU → compute → read back → endian-convert.
   - Concatenate results.
2. **Tests**: 2¹⁸ points; verify against gnark for a subset.

### Phase 4: Phase 2 update() Integration

1. Parse Phase2 Parameters from gnark binary format.
2. Run `scaleG1SliceBatched` for Z, PKK (and SigmaCKK if commitments).
3. Run single scalar muls for Delta, Sigma (WASM/@noble/curves or webgpu-crypto CPU path).
4. Serialize result to gnark format.
5. **Tests**: Full `update()` roundtrip; gnark `Verify` accepts output.

### Phase 5: Fr, G2

- **Fr**: `delta_inv` — use @noble/curves or WASM.
- **G2**: Delta, Sigma — few points; use @noble/curves bn254 or WASM.

---

## Part D: Outer TypeScript Implementation

### 1. Module Structure

```
src/
  webgpu/
    device.ts          # requestDevice, query limits
    buffers.ts         # createBuffer, copy, chunk helpers
    scaleG1Slice.ts    # scaleG1SliceBatched (main entry)
  phase2/
    parse.ts           # Parse gnark Phase2 binary format
    update.ts          # Orchestrate update() using scaleG1Slice + single muls
    serialize.ts       # Serialize to gnark format
  bindings/
    endian.ts          # beBytesToU32LE, u32LEToBeBytes
```

### 2. scaleG1SliceBatched (Core)

```typescript
async function scaleG1SliceBatched(
  device: GPUDevice,
  points: Uint8Array,   // gnark format: 64 bytes per point, Big-Endian
  scalar: bigint
): Promise<Uint8Array> {
  const limit = device.limits.maxStorageBufferBindingSize;
  const bytesPerPoint = 64;
  const batchSize = Math.min(
    Math.floor((limit * 0.9) / bytesPerPoint),
    2 ** 20  // cap for sanity
  );
  const numPoints = points.length / bytesPerPoint;
  const result = new Uint8Array(points.length);

  for (let offset = 0; offset < numPoints; offset += batchSize) {
    const count = Math.min(batchSize, numPoints - offset);
    const chunk = points.slice(offset * bytesPerPoint, (offset + count) * bytesPerPoint);
    const chunkResult = await scaleG1SliceChunk(device, chunk, scalar);
    result.set(chunkResult, offset * bytesPerPoint);
  }
  return result;
}
```

### 3. Endian Binding (endian.ts)

```typescript
// gnark: 32 bytes Big-Endian per field element (x, y)
// webgpu-crypto: 8 u32 limbs Little-Endian per field
function gnarkG1ToU32LE(be64: Uint8Array): Uint32Array {
  // Swap each 32-byte field to LE u32 limbs
  // ...
}
function u32LEToGnarkG1(le: Uint32Array): Uint8Array {
  // ...
}
```

### 4. Phase 2 update() Orchestration

```typescript
async function phase2Update(
  device: GPUDevice,
  params: Phase2Params,  // Z, PKK, Delta, SigmaCKK, etc.
  delta: bigint,
  sigma: bigint[]
): Promise<Phase2Params> {
  const deltaInv = modInverse(delta, FR_MODULUS);
  // 1. scaleG1SliceBatched(Z, deltaInv)
  // 2. scaleG1SliceBatched(PKK, deltaInv)
  // 3. For each i: scaleG1SliceBatched(SigmaCKK[i], sigma[i])
  // 4. Single scalar muls: Delta, Sigma (WASM)
  return updatedParams;
}
```

### 5. Dependencies

- `@noble/curves` (bn254) — Fr inverse, G2 scalar mul (few points)
- `demox-labs/webgpu-crypto` — BN254 WGSL, batch scalar mul (or fork)
- Optional: `gnark` WASM build for verification

---

## Part E: Test Infrastructure

### 1. Test Vector Generator (Go)

```
webgpu-phase2/
  cmd/
    generate-testvectors/
      main.go          # Exports JSON test vectors
  testvectors/
    phase2_vectors.json  # Generated (fp_modulus, g1_scalar_mul, phase2_z_0, etc.)
```

**Generator logic** (pseudo):

```go
// From setup_test.go patterns
commons := commonsSmallValues(8, 2, 3, 4)
// Export commons.G1.Tau[0..7], G2.Tau[0..7], etc.

var p Phase2
evals := p.Initialize(cs, &commons)
contributions := []fr.Element{delta, sigma...}
p.update(&contributions[0], contributions[1:])
// Export p.Parameters.G1.Z, PKK, Delta, etc. (before and after)
```

### 2. WebGPU Test Runner

- **Node/browser**: Load WGSL, run compute, read back buffers.
- **Compare**: Output bytes vs test vector `expected`.
- **Framework**: Vitest, Jest, or plain Node script.

### 3. gnark Integration Test

- Add `TestPhase2WebGPU` in gnark (or in webgpu-phase2):
  1. Run Phase2.Initialize + first Contribute in Go.
  2. Serialize Phase2 state to bytes.
  3. (Future) Call WebGPU contribute; deserialize result.
  4. Run Phase2.Verify in Go.

Initially: steps 1–2 only (export format). WebGPU consume later.

---

## Part F: File Layout

```
webgpu-phase2/
  README.md
  PRIMITIVES.md
  PLAN.md
  src/                    # TypeScript (uses webgpu-crypto)
    webgpu/
      device.ts
      buffers.ts
      scaleG1Slice.ts
    phase2/
      parse.ts
      update.ts
      serialize.ts
    bindings/
      endian.ts
  testvectors/
    phase2_vectors.json   # From cmd/generate-testvectors
  cmd/
    generate-testvectors/
      main.go
  test/
    scaleG1Slice.test.ts
    phase2_update.test.ts
```

---

## Part G: Running gnark Tests for Reference

```bash
# Phase 2–related tests
go test -v ./backend/groth16/bn254/mpcsetup/... -run TestCommonsUpdate
go test -v ./backend/groth16/bn254/mpcsetup/... -run TestPhase2
go test -v ./backend/groth16/bn254/mpcsetup/... -run TestPedersen
go test -v ./backend/groth16/bn254/mpcsetup/... -run TestAll
```

Use these to validate that test vectors and WebGPU output match.

---

## Part H: Success Criteria

1. **Unit**: Each primitive (Fp, G1 add/double/scalar_mul) matches gnark on golden inputs.
2. **Batch**: `scaleG1Slice` output matches gnark for slices of size 8, 64, 256.
3. **Integration**: Phase2 `update()` output matches gnark; Verify accepts WebGPU contribution.
4. **Performance**: Batch kernel runs in reasonable time for ~2M points (stretch goal).
