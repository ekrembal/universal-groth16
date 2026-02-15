/**
 * Pure-BigInt BN254 cryptographic primitives.
 *
 * Provides Fp, Fp2, Fr arithmetic and G1/G2 elliptic curve operations.
 * These are used as the CPU fallback; the WebGPU path accelerates batch G1 ops.
 */
import type { G1Affine, G2Affine, Fp2Element } from './phase2/types.js';
/** (a + b) mod p */
export declare function fpAdd(a: bigint, b: bigint): bigint;
/** (a − b) mod p */
export declare function fpSub(a: bigint, b: bigint): bigint;
/** (a × b) mod p */
export declare function fpMul(a: bigint, b: bigint): bigint;
/** a² mod p */
export declare function fpSquare(a: bigint): bigint;
/** −a mod p */
export declare function fpNeg(a: bigint): bigint;
/** Modular exponentiation: base^exp mod p */
export declare function fpPow(base: bigint, exp: bigint): bigint;
/** Modular inverse: a⁻¹ mod p (Fermat's little theorem) */
export declare function fpInv(a: bigint): bigint;
/**
 * Square root in Fp. Since p ≡ 3 mod 4, sqrt(a) = a^((p+1)/4).
 * @throws if a is not a quadratic residue.
 */
export declare function fpSqrt(a: bigint): bigint;
/**
 * Check if a field element is "lexicographically largest" (> (p-1)/2).
 */
export declare function fpLexLargest(a: bigint): boolean;
export declare function fp2Add(a: Fp2Element, b: Fp2Element): Fp2Element;
export declare function fp2Sub(a: Fp2Element, b: Fp2Element): Fp2Element;
/** (a0 + a1·i)(b0 + b1·i) = (a0·b0 − a1·b1) + (a0·b1 + a1·b0)·i */
export declare function fp2Mul(a: Fp2Element, b: Fp2Element): Fp2Element;
export declare function fp2Square(a: Fp2Element): Fp2Element;
export declare function fp2Neg(a: Fp2Element): Fp2Element;
/** (c0 + c1·i)⁻¹ = (c0 − c1·i) / (c0² + c1²) */
export declare function fp2Inv(a: Fp2Element): Fp2Element;
export declare function fp2IsZero(a: Fp2Element): boolean;
export declare function fp2Eq(a: Fp2Element, b: Fp2Element): boolean;
/** Multiply Fp2 element by a scalar in Fp */
export declare function fp2MulScalar(a: Fp2Element, s: bigint): Fp2Element;
/**
 * Square root in Fp2 = Fp[u]/(u²+1).
 * Uses the algorithm: if a = a0 + a1·u, find b = b0 + b1·u such that b² = a.
 */
export declare function fp2Sqrt(a: Fp2Element): Fp2Element;
/**
 * Lexicographically largest check for Fp2.
 * In gnark-crypto: if A1 ≠ 0, check A1; if A1 = 0, check A0.
 * "A1" is c1 in our notation (the imaginary part).
 */
export declare function fp2LexLargest(a: Fp2Element): boolean;
/** Modular inverse in Fr: a⁻¹ mod r */
export declare function frInv(a: bigint): bigint;
/** (a × b) mod r */
export declare function frMul(a: bigint, b: bigint): bigint;
/** Normalize scalar to [0, r) */
export declare function frNormalize(a: bigint): bigint;
/** Check if a G1 point is the identity (point at infinity). */
export declare function g1IsInfinity(p: G1Affine): boolean;
/** Negate a G1 point: −(x, y) = (x, −y). */
export declare function g1Neg(p: G1Affine): G1Affine;
/**
 * G1 scalar multiplication: [s]·P using double-and-add.
 * This is the CPU fallback. For batch operations use the WebGPU path.
 */
export declare function g1ScalarMul(point: G1Affine, scalar: bigint): G1Affine;
/**
 * Batch G1 scalar multiplication: scale every point in the slice by the
 * same scalar.  CPU fallback — parallelize or use WebGPU for large batches.
 */
export declare function scaleG1Slice(points: G1Affine[], scalar: bigint): G1Affine[];
/** Check if a G2 point is the identity. */
export declare function g2IsInfinity(p: G2Affine): boolean;
/** Negate a G2 point. */
export declare function g2Neg(p: G2Affine): G2Affine;
/**
 * G2 scalar multiplication: [s]·P using double-and-add.
 * Few G2 scalar muls are needed (Delta, Sigma) so CPU is fine.
 */
export declare function g2ScalarMul(point: G2Affine, scalar: bigint): G2Affine;
/** Generic modular exponentiation: base^exp mod m */
export declare function modPow(base: bigint, exp: bigint, m: bigint): bigint;
