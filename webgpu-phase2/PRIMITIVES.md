# Cryptographic Primitives for WebGPU Phase 2

This document lists the primitives required to implement Phase 2 `Contribute()` in WebGPU. All operations are over **BN254**.

**Strategy**: Use **[demox-labs/webgpu-crypto](https://github.com/demox-labs/webgpu-crypto)** for BN254 (Field Math, Curve Math, MSM). We adapt its batch scalar multiplication for Phase 2's `scaleG1Slice`. Primitives we may need to extend or verify:

---

## 1. Field Arithmetic (from webgpu-crypto)

### 1.1 Base Field Fp (BN254)

- **Modulus**: `p = 21888242871839275222246405745257275088696311157297823662689037894645226208583`
- **Size**: 254 bits
- **Representation**: 4×u64 limbs (or 8×u32) in WGSL

| Primitive | Description | Used in |
|-----------|-------------|---------|
| `fp_add(a, b)` | Modular addition | G1 add, G1 double |
| `fp_sub(a, b)` | Modular subtraction | G1 add, G1 sub |
| `fp_mul(a, b)` | Montgomery multiplication | All |
| `fp_square(a)` | `a² mod p` | G1 double |
| `fp_inv(a)` | Modular inverse | G1 affine normalization |
| `fp_from_bytes(bytes)` | Deserialize from big-endian | Load points |
| `fp_to_bytes(a)` | Serialize to big-endian | Store points |

### 1.2 Scalar Field Fr (BN254)

- **Modulus**: `r = 21888242871839275222246405745257275088548364400416034343698204186575808495617`
- **Size**: 256 bits
- **Used for**: Scalar in `[s]·P`

| Primitive | Description | Used in |
|-----------|-------------|---------|
| `fr_from_bytes(bytes)` | Deserialize scalar | Load delta, sigma |
| `fr_to_bytes(a)` | Serialize scalar | Proof output |
| `fr_inv(a)` | Modular inverse | `delta_inv` in update |
| `fr_to_bigint(a)` | Convert to big.Int for scalar mul | Scalar multiplication |

### 1.3 Extension Field Fp² (for G2)

- **Definition**: `Fp² = Fp[i] / (i² + 1)`
- **Element**: `(c0, c1)` where `a + b·i`

| Primitive | Description | Used in |
|-----------|-------------|---------|
| `fp2_add`, `fp2_sub`, `fp2_mul` | Fp² arithmetic | G2 add, G2 double |
| `fp2_inv` | Fp² inverse | G2 normalization |
| `fp2_from_bytes`, `fp2_to_bytes` | Serialization | Load/store G2 points |

---

## 2. Elliptic Curve Operations

### 2.1 G1 (BN254)

- **Curve**: `y² = x³ + 3` over Fp
- **Point**: Affine `(x, y)` or Jacobian `(X, Y, Z)`
- **Identity**: Point at infinity (handled as special case)

| Primitive | Description | Complexity | Used in |
|-----------|-------------|------------|---------|
| `g1_add(P, Q)` | P + Q (affine or Jacobian) | ~10 fp_mul | Phase2 update |
| `g1_sub(P, Q)` | P - Q | P + (-Q) | FFT butterfly |
| `g1_double(P)` | 2·P | ~6 fp_mul | Scalar mul |
| `g1_neg(P)` | -P | Negate y | g1_sub |
| `g1_scalar_mul(P, s)` | [s]·P | ~256 double+add | **Phase2 hot path** |
| `g1_affine_from_jacobian(J)` | Jacobian → Affine | 1 inv, 2 mul | Normalize output |
| `g1_is_infinity(P)` | Check identity | Compare coords | Edge cases |
| `g1_from_bytes(bytes)` | Deserialize (64 B) | 2× fp_from_bytes | Load |
| `g1_to_bytes(P)` | Serialize (64 B) | 2× fp_to_bytes | Store |

**Scalar multiplication** (`g1_scalar_mul`): Double-and-add over 256 bits. Each iteration: double, conditional add. ~256 doubles + ~128 adds on average.

### 2.2 G2 (BN254)

- **Curve**: Same equation over Fp²
- **Point**: Affine `(x, y)` with x, y ∈ Fp²
- **Element size**: 128 bytes (2× Fp² = 4× Fp)

| Primitive | Description | Used in |
|-----------|-------------|---------|
| `g2_add(P, Q)` | P + Q | Phase2 update |
| `g2_double(P)` | 2·P | Scalar mul |
| `g2_scalar_mul(P, s)` | [s]·P | Delta, Sigma (few points) |
| `g2_from_bytes(bytes)` | Deserialize (128 B) | Load |
| `g2_to_bytes(P)` | Serialize (128 B) | Store |

**Note**: G2 scalar muls are few (Delta, Sigma[i])—can stay on CPU/WASM initially. G1 batch is the bottleneck.

---

## 3. Phase 2–Specific Operations

### 3.1 Batch G1 Scalar Multiplication (Hot Path)

```
scaleG1Slice(slice []G1Affine, scalar *big.Int)
  for i := 0; i < len(slice); i++:
    slice[i] = g1_scalar_mul(&slice[i], scalar)
```

- **Input**: Slice of G1 points, one scalar
- **Output**: In-place update
- **Count**: ~4M for 1.6M constraints (Z + PKK)
- **WebGPU**: One workgroup per point; each computes `[scalar]·P[i]`

### 3.2 Single G1/G2 Scalar Muls

- `G1.Delta = delta * G1.Delta`
- `G2.Delta = delta * G2.Delta`
- `G2.Sigma[i] = sigma[i] * G2.Sigma[i]`
- `SigmaCKK[i][j] = sigma[i] * SigmaCKK[i][j]` (per commitment)

### 3.3 Field Operations (CPU/WASM)

- `delta_inv = fr_inv(delta)` — scalar inverse
- `delta.BigInt(&I)` — convert to big.Int for scalar mul
- SHA256 for challenge (existing Web Crypto API)
- Fiat–Shamir derivation of delta, sigma (gnark-crypto `UpdateValues`)

---

## 4. Data Formats (gnark-compatible)

### G1Affine (64 bytes)

```
x: 32 bytes big-endian (Fp)
y: 32 bytes big-endian (Fp)
```

### G2Affine (128 bytes)

```
x: 64 bytes (Fp²: c0 || c1, each 32 bytes)
y: 64 bytes (Fp²: c0 || c1)
```

### Scalar (32 bytes)

```
fr.Element: 32 bytes big-endian
```

---

## 5. Implementation Order (with webgpu-crypto)

1. **Integrate webgpu-crypto** — BN254 params, curve WGSL
2. **Batch G1 scalar mul** — Adapt `pointScalarMultipassReuseBuffer` for scaleG1Slice; ensure full Affine output
3. **Batching** — Chunk by `maxStorageBufferBindingSize` (see PLAN.md)
4. **Fr** — delta_inv via @noble/curves or WASM
5. **G2** — Delta, Sigma (few points) via @noble/curves or WASM

---

## 6. webgpu-crypto vs gnark-crypto

| gnark-crypto | webgpu-crypto | Notes |
|--------------|---------------|-------|
| `bn254.G1Affine` | `AffinePoint`, `Point` (Projective) | Affine in/out; Projective for mul |
| `bn254.G2Affine` | — | Use @noble/curves for few points |
| `fr.Element` | `Field` (u32 limbs) | `bigIntToU32Array` |
| `ScalarMultiplication` | `mul_point_64_bits*`, `point_mul_multi_reuse` | Per-point scalar mul |

Test vectors: generated from gnark (Go) via `cmd/generate-testvectors`; consumed by TypeScript tests.
