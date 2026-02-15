/**
 * Pure-BigInt BN254 cryptographic primitives.
 *
 * Provides Fp, Fp2, Fr arithmetic and G1/G2 elliptic curve operations.
 * These are used as the CPU fallback; the WebGPU path accelerates batch G1 ops.
 */

import {
  FP_MODULUS,
  FR_MODULUS,
  CURVE_B,
  TWIST_B_C0,
  TWIST_B_C1,
} from './constants.js';
import type { G1Affine, G2Affine, Fp2Element } from './phase2/types.js';

// ===========================================================================
// Fp — base field arithmetic (mod p)
// ===========================================================================

/** (a + b) mod p */
export function fpAdd(a: bigint, b: bigint): bigint {
  return (a + b) % FP_MODULUS;
}

/** (a − b) mod p */
export function fpSub(a: bigint, b: bigint): bigint {
  return ((a - b) % FP_MODULUS + FP_MODULUS) % FP_MODULUS;
}

/** (a × b) mod p */
export function fpMul(a: bigint, b: bigint): bigint {
  return (a * b) % FP_MODULUS;
}

/** a² mod p */
export function fpSquare(a: bigint): bigint {
  return (a * a) % FP_MODULUS;
}

/** −a mod p */
export function fpNeg(a: bigint): bigint {
  if (a === 0n) return 0n;
  return FP_MODULUS - (a % FP_MODULUS);
}

/** Modular exponentiation: base^exp mod p */
export function fpPow(base: bigint, exp: bigint): bigint {
  return modPow(base, exp, FP_MODULUS);
}

/** Modular inverse: a⁻¹ mod p (Fermat's little theorem) */
export function fpInv(a: bigint): bigint {
  if (a === 0n) throw new Error('fpInv: division by zero');
  return modPow(a, FP_MODULUS - 2n, FP_MODULUS);
}

/**
 * Square root in Fp. Since p ≡ 3 mod 4, sqrt(a) = a^((p+1)/4).
 * @throws if a is not a quadratic residue.
 */
export function fpSqrt(a: bigint): bigint {
  if (a === 0n) return 0n;
  const exp = (FP_MODULUS + 1n) / 4n;
  const root = modPow(a, exp, FP_MODULUS);
  // Verify
  if ((root * root) % FP_MODULUS !== a % FP_MODULUS) {
    throw new Error('fpSqrt: not a quadratic residue');
  }
  return root;
}

/**
 * Check if a field element is "lexicographically largest" (> (p-1)/2).
 */
export function fpLexLargest(a: bigint): boolean {
  return a > (FP_MODULUS - 1n) / 2n;
}

// ===========================================================================
// Fp2 — extension field arithmetic (Fp[i] / (i² + 1))
// ===========================================================================

export function fp2Add(a: Fp2Element, b: Fp2Element): Fp2Element {
  return { c0: fpAdd(a.c0, b.c0), c1: fpAdd(a.c1, b.c1) };
}

export function fp2Sub(a: Fp2Element, b: Fp2Element): Fp2Element {
  return { c0: fpSub(a.c0, b.c0), c1: fpSub(a.c1, b.c1) };
}

/** (a0 + a1·i)(b0 + b1·i) = (a0·b0 − a1·b1) + (a0·b1 + a1·b0)·i */
export function fp2Mul(a: Fp2Element, b: Fp2Element): Fp2Element {
  const t0 = fpMul(a.c0, b.c0);
  const t1 = fpMul(a.c1, b.c1);
  return {
    c0: fpSub(t0, t1),
    c1: fpSub(fpMul(fpAdd(a.c0, a.c1), fpAdd(b.c0, b.c1)), fpAdd(t0, t1)),
  };
}

export function fp2Square(a: Fp2Element): Fp2Element {
  return fp2Mul(a, a);
}

export function fp2Neg(a: Fp2Element): Fp2Element {
  return { c0: fpNeg(a.c0), c1: fpNeg(a.c1) };
}

/** (c0 + c1·i)⁻¹ = (c0 − c1·i) / (c0² + c1²) */
export function fp2Inv(a: Fp2Element): Fp2Element {
  const norm = fpAdd(fpSquare(a.c0), fpSquare(a.c1));
  const normInv = fpInv(norm);
  return {
    c0: fpMul(a.c0, normInv),
    c1: fpNeg(fpMul(a.c1, normInv)),
  };
}

export function fp2IsZero(a: Fp2Element): boolean {
  return a.c0 === 0n && a.c1 === 0n;
}

export function fp2Eq(a: Fp2Element, b: Fp2Element): boolean {
  return a.c0 === b.c0 && a.c1 === b.c1;
}

/** Multiply Fp2 element by a scalar in Fp */
export function fp2MulScalar(a: Fp2Element, s: bigint): Fp2Element {
  return { c0: fpMul(a.c0, s), c1: fpMul(a.c1, s) };
}

/**
 * Square root in Fp2 = Fp[u]/(u²+1).
 * Uses the algorithm: if a = a0 + a1·u, find b = b0 + b1·u such that b² = a.
 */
export function fp2Sqrt(a: Fp2Element): Fp2Element {
  if (fp2IsZero(a)) return { c0: 0n, c1: 0n };

  if (a.c1 === 0n) {
    // a is in Fp. Try sqrt(a.c0).
    const check = modPow(a.c0, (FP_MODULUS - 1n) / 2n, FP_MODULUS);
    if (check === 1n || a.c0 === 0n) {
      return { c0: fpSqrt(a.c0), c1: 0n };
    } else {
      // a.c0 is not a QR in Fp, but -a.c0 is (since -1 is not a QR)
      // sqrt(a.c0 * u²) = sqrt(-a.c0) * u
      return { c0: 0n, c1: fpSqrt(fpNeg(a.c0)) };
    }
  }

  // General case: a.c1 ≠ 0
  // norm = a.c0² + a.c1² (the Fp-norm of the Fp2 element)
  const norm = fpAdd(fpSquare(a.c0), fpSquare(a.c1));
  const normSqrt = fpSqrt(norm);

  // t0 = (a.c0 + normSqrt) / 2
  let t0 = fpMul(fpAdd(a.c0, normSqrt), fpInv(2n));
  // Check if t0 is a QR
  let isQR = modPow(t0, (FP_MODULUS - 1n) / 2n, FP_MODULUS) === 1n || t0 === 0n;
  if (!isQR) {
    // Use (a.c0 - normSqrt) / 2
    t0 = fpMul(fpSub(a.c0, normSqrt), fpInv(2n));
  }

  const b0 = fpSqrt(t0);
  const b1 = fpMul(a.c1, fpInv(fpMul(2n, b0)));

  return { c0: b0, c1: b1 };
}

/**
 * Lexicographically largest check for Fp2.
 * In gnark-crypto: if A1 ≠ 0, check A1; if A1 = 0, check A0.
 * "A1" is c1 in our notation (the imaginary part).
 */
export function fp2LexLargest(a: Fp2Element): boolean {
  if (a.c1 !== 0n) {
    return fpLexLargest(a.c1);
  }
  return fpLexLargest(a.c0);
}

// ===========================================================================
// Fr — scalar field arithmetic (mod r)
// ===========================================================================

/** Modular inverse in Fr: a⁻¹ mod r */
export function frInv(a: bigint): bigint {
  if (a === 0n) throw new Error('frInv: division by zero');
  return modPow(a, FR_MODULUS - 2n, FR_MODULUS);
}

/** (a × b) mod r */
export function frMul(a: bigint, b: bigint): bigint {
  return (a * b) % FR_MODULUS;
}

/** Normalize scalar to [0, r) */
export function frNormalize(a: bigint): bigint {
  return ((a % FR_MODULUS) + FR_MODULUS) % FR_MODULUS;
}

// ===========================================================================
// G1 — elliptic curve operations (y² = x³ + 3 over Fp)
// ===========================================================================

/** Check if a G1 point is the identity (point at infinity). */
export function g1IsInfinity(p: G1Affine): boolean {
  return p.x === 0n && p.y === 0n;
}

/** Negate a G1 point: −(x, y) = (x, −y). */
export function g1Neg(p: G1Affine): G1Affine {
  if (g1IsInfinity(p)) return p;
  return { x: p.x, y: fpNeg(p.y) };
}

// --- Jacobian coordinates: (X, Y, Z) represents affine (X/Z², Y/Z³) ---

interface JacobianPoint {
  x: bigint;
  y: bigint;
  z: bigint;
}

const JAC_INFINITY: JacobianPoint = { x: 0n, y: 1n, z: 0n };

function toJacobian(p: G1Affine): JacobianPoint {
  if (g1IsInfinity(p)) return { ...JAC_INFINITY };
  return { x: p.x, y: p.y, z: 1n };
}

function toAffine(p: JacobianPoint): G1Affine {
  if (p.z === 0n) return { x: 0n, y: 0n };
  const zInv = fpInv(p.z);
  const zInv2 = fpSquare(zInv);
  const zInv3 = fpMul(zInv2, zInv);
  return {
    x: fpMul(p.x, zInv2),
    y: fpMul(p.y, zInv3),
  };
}

/** Double a Jacobian point: 2P (BN254: a = 0). */
function jacDouble(p: JacobianPoint): JacobianPoint {
  if (p.z === 0n) return { ...JAC_INFINITY };
  if (p.y === 0n) return { ...JAC_INFINITY };

  const A = fpSquare(p.x);
  const B = fpSquare(p.y);
  const C = fpSquare(B);
  const xPlusB = fpAdd(p.x, B);
  const D = fpMul(2n, fpSub(fpSquare(xPlusB), fpAdd(A, C)));
  const E = fpMul(3n, A); // 3a = 0 for BN254, so just 3·x²
  const F = fpSquare(E);

  const x3 = fpSub(F, fpMul(2n, D));
  const y3 = fpSub(fpMul(E, fpSub(D, x3)), fpMul(8n, C));
  const z3 = fpMul(2n, fpMul(p.y, p.z));

  return { x: x3, y: y3, z: z3 };
}

/** Add two Jacobian points: P + Q (handles all edge cases). */
function jacAdd(p: JacobianPoint, q: JacobianPoint): JacobianPoint {
  if (p.z === 0n) return { ...q };
  if (q.z === 0n) return { ...p };

  const z1z1 = fpSquare(p.z);
  const z2z2 = fpSquare(q.z);
  const u1 = fpMul(p.x, z2z2);
  const u2 = fpMul(q.x, z1z1);
  const s1 = fpMul(fpMul(p.y, q.z), z2z2);
  const s2 = fpMul(fpMul(q.y, p.z), z1z1);

  if (u1 === u2) {
    if (s1 === s2) return jacDouble(p);
    return { ...JAC_INFINITY };
  }

  const h = fpSub(u2, u1);
  const i = fpSquare(fpMul(2n, h));
  const j = fpMul(h, i);
  const r = fpMul(2n, fpSub(s2, s1));
  const v = fpMul(u1, i);

  const x3 = fpSub(fpSub(fpSquare(r), j), fpMul(2n, v));
  const y3 = fpSub(fpMul(r, fpSub(v, x3)), fpMul(2n, fpMul(s1, j)));
  const zSum = fpAdd(p.z, q.z);
  const z3 = fpMul(fpSub(fpSquare(zSum), fpAdd(z1z1, z2z2)), h);

  return { x: x3, y: y3, z: z3 };
}

/**
 * G1 scalar multiplication: [s]·P using double-and-add.
 * This is the CPU fallback. For batch operations use the WebGPU path.
 */
export function g1ScalarMul(point: G1Affine, scalar: bigint): G1Affine {
  scalar = frNormalize(scalar);
  if (scalar === 0n || g1IsInfinity(point)) return { x: 0n, y: 0n };

  let result: JacobianPoint = { ...JAC_INFINITY };
  let current = toJacobian(point);

  while (scalar > 0n) {
    if (scalar & 1n) {
      result = jacAdd(result, current);
    }
    current = jacDouble(current);
    scalar >>= 1n;
  }

  return toAffine(result);
}

/**
 * Batch G1 scalar multiplication: scale every point in the slice by the
 * same scalar.  CPU fallback — parallelize or use WebGPU for large batches.
 */
export function scaleG1Slice(
  points: G1Affine[],
  scalar: bigint,
): G1Affine[] {
  return points.map((p) => g1ScalarMul(p, scalar));
}

// ===========================================================================
// G2 — elliptic curve operations (y² = x³ + b' over Fp2)
// ===========================================================================

/** Check if a G2 point is the identity. */
export function g2IsInfinity(p: G2Affine): boolean {
  return fp2IsZero(p.x) && fp2IsZero(p.y);
}

/** Negate a G2 point. */
export function g2Neg(p: G2Affine): G2Affine {
  if (g2IsInfinity(p)) return p;
  return { x: p.x, y: fp2Neg(p.y) };
}

// --- Jacobian G2 coordinates ---

interface JacobianG2Point {
  x: Fp2Element;
  y: Fp2Element;
  z: Fp2Element;
}

const JAC_G2_INFINITY: JacobianG2Point = {
  x: { c0: 0n, c1: 0n },
  y: { c0: 1n, c1: 0n },
  z: { c0: 0n, c1: 0n },
};

function toJacobianG2(p: G2Affine): JacobianG2Point {
  if (g2IsInfinity(p)) return { ...JAC_G2_INFINITY };
  return { x: p.x, y: p.y, z: { c0: 1n, c1: 0n } };
}

function toAffineG2(p: JacobianG2Point): G2Affine {
  if (fp2IsZero(p.z)) {
    return {
      x: { c0: 0n, c1: 0n },
      y: { c0: 0n, c1: 0n },
    };
  }
  const zInv = fp2Inv(p.z);
  const zInv2 = fp2Square(zInv);
  const zInv3 = fp2Mul(zInv2, zInv);
  return {
    x: fp2Mul(p.x, zInv2),
    y: fp2Mul(p.y, zInv3),
  };
}

function jacDoubleG2(p: JacobianG2Point): JacobianG2Point {
  if (fp2IsZero(p.z)) return { ...JAC_G2_INFINITY };
  if (fp2IsZero(p.y)) return { ...JAC_G2_INFINITY };

  const A = fp2Square(p.x);
  const B = fp2Square(p.y);
  const C = fp2Square(B);
  const xPlusB = fp2Add(p.x, B);
  const D = fp2MulScalar(
    fp2Sub(fp2Square(xPlusB), fp2Add(A, C)),
    2n,
  );
  const E = fp2MulScalar(A, 3n);
  const F = fp2Square(E);

  const x3 = fp2Sub(F, fp2MulScalar(D, 2n));
  const y3 = fp2Sub(fp2Mul(E, fp2Sub(D, x3)), fp2MulScalar(C, 8n));
  const z3 = fp2MulScalar(fp2Mul(p.y, p.z), 2n);

  return { x: x3, y: y3, z: z3 };
}

function jacAddG2(
  p: JacobianG2Point,
  q: JacobianG2Point,
): JacobianG2Point {
  if (fp2IsZero(p.z)) return { ...q };
  if (fp2IsZero(q.z)) return { ...p };

  const z1z1 = fp2Square(p.z);
  const z2z2 = fp2Square(q.z);
  const u1 = fp2Mul(p.x, z2z2);
  const u2 = fp2Mul(q.x, z1z1);
  const s1 = fp2Mul(fp2Mul(p.y, q.z), z2z2);
  const s2 = fp2Mul(fp2Mul(q.y, p.z), z1z1);

  if (fp2Eq(u1, u2)) {
    if (fp2Eq(s1, s2)) return jacDoubleG2(p);
    return { ...JAC_G2_INFINITY };
  }

  const h = fp2Sub(u2, u1);
  const i = fp2Square(fp2MulScalar(h, 2n));
  const j = fp2Mul(h, i);
  const r = fp2MulScalar(fp2Sub(s2, s1), 2n);
  const v = fp2Mul(u1, i);

  const x3 = fp2Sub(fp2Sub(fp2Square(r), j), fp2MulScalar(v, 2n));
  const y3 = fp2Sub(
    fp2Mul(r, fp2Sub(v, x3)),
    fp2MulScalar(fp2Mul(s1, j), 2n),
  );
  const zSum = fp2Add(p.z, q.z);
  const z3 = fp2Mul(
    fp2Sub(fp2Square(zSum), fp2Add(z1z1, z2z2)),
    h,
  );

  return { x: x3, y: y3, z: z3 };
}

/**
 * G2 scalar multiplication: [s]·P using double-and-add.
 * Few G2 scalar muls are needed (Delta, Sigma) so CPU is fine.
 */
export function g2ScalarMul(point: G2Affine, scalar: bigint): G2Affine {
  scalar = frNormalize(scalar);
  if (scalar === 0n || g2IsInfinity(point)) {
    return { x: { c0: 0n, c1: 0n }, y: { c0: 0n, c1: 0n } };
  }

  let result: JacobianG2Point = { ...JAC_G2_INFINITY };
  let current = toJacobianG2(point);

  while (scalar > 0n) {
    if (scalar & 1n) {
      result = jacAddG2(result, current);
    }
    current = jacDoubleG2(current);
    scalar >>= 1n;
  }

  return toAffineG2(result);
}

// ===========================================================================
// Utility
// ===========================================================================

/** Generic modular exponentiation: base^exp mod m */
export function modPow(base: bigint, exp: bigint, m: bigint): bigint {
  let result = 1n;
  base = ((base % m) + m) % m;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % m;
    exp >>= 1n;
    base = (base * base) % m;
  }
  return result;
}
