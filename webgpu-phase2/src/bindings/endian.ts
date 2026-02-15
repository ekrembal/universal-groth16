/**
 * Endian conversion utilities for bridging gnark (big-endian) and WebGPU (u32 limbs).
 *
 * gnark format:
 *   - Field elements: 32 bytes, big-endian
 *   - G1Affine: 64 bytes = x (32 BE) || y (32 BE)
 *   - G2Affine: 128 bytes = x.c0 (32 BE) || x.c1 (32 BE) || y.c0 (32 BE) || y.c1 (32 BE)
 *
 * webgpu-crypto format:
 *   - Field elements: 8 × u32 limbs, big-endian u32 order (MSB u32 first)
 *   - G1 affine point: 16 × u32 (x: 8, y: 8)
 */

import { FP_BYTES, LIMBS_PER_FIELD } from '../constants.js';

// ---------------------------------------------------------------------------
// BigInt ↔ big-endian bytes
// ---------------------------------------------------------------------------

/** Read a 32-byte big-endian field element as a bigint. */
export function beFieldToBigInt(bytes: Uint8Array, offset = 0): bigint {
  let result = 0n;
  for (let i = 0; i < FP_BYTES; i++) {
    result = (result << 8n) | BigInt(bytes[offset + i]);
  }
  return result;
}

/** Write a bigint to a 32-byte big-endian field element. */
export function bigIntToBeField(
  value: bigint,
  out: Uint8Array,
  offset = 0,
): void {
  for (let i = FP_BYTES - 1; i >= 0; i--) {
    out[offset + i] = Number(value & 0xffn);
    value >>= 8n;
  }
}

// ---------------------------------------------------------------------------
// BigInt ↔ u32 limb array (big-endian u32 order, matching webgpu-crypto)
// ---------------------------------------------------------------------------

/**
 * Convert a bigint to 8 u32 limbs in big-endian u32 order.
 * limbs[0] is the most-significant u32.
 */
export function bigIntToU32Array(value: bigint): Uint32Array {
  const limbs = new Uint32Array(LIMBS_PER_FIELD);
  for (let i = LIMBS_PER_FIELD - 1; i >= 0; i--) {
    limbs[i] = Number(value & 0xffffffffn);
    value >>= 32n;
  }
  return limbs;
}

/**
 * Convert 8 u32 limbs (big-endian u32 order) back to a bigint.
 */
export function u32ArrayToBigInt(
  limbs: Uint32Array,
  offset = 0,
): bigint {
  let result = 0n;
  for (let i = 0; i < LIMBS_PER_FIELD; i++) {
    result = (result << 32n) | BigInt(limbs[offset + i]);
  }
  return result;
}

// ---------------------------------------------------------------------------
// Big-endian bytes ↔ u32 limb array
// ---------------------------------------------------------------------------

/**
 * Convert 32 big-endian bytes to 8 u32 limbs (BE u32 order).
 * Equivalent to: bigIntToU32Array(beFieldToBigInt(bytes, offset))
 * but avoids the intermediate bigint.
 */
export function beBytesToU32(bytes: Uint8Array, offset = 0): Uint32Array {
  const view = new DataView(
    bytes.buffer,
    bytes.byteOffset + offset,
    FP_BYTES,
  );
  const limbs = new Uint32Array(LIMBS_PER_FIELD);
  for (let i = 0; i < LIMBS_PER_FIELD; i++) {
    limbs[i] = view.getUint32(i * 4, false); // big-endian read
  }
  return limbs;
}

/**
 * Convert 8 u32 limbs (BE u32 order) to 32 big-endian bytes.
 */
export function u32ToBeBytes(
  limbs: Uint32Array,
  limbOffset: number,
  out: Uint8Array,
  byteOffset: number,
): void {
  const view = new DataView(
    out.buffer,
    out.byteOffset + byteOffset,
    FP_BYTES,
  );
  for (let i = 0; i < LIMBS_PER_FIELD; i++) {
    view.setUint32(i * 4, limbs[limbOffset + i], false); // big-endian write
  }
}

// ---------------------------------------------------------------------------
// G1 point ↔ u32 limb array (for webgpu-crypto)
// ---------------------------------------------------------------------------

/**
 * Convert a gnark G1Affine (64 BE bytes) to 16 u32 limbs (x: 8, y: 8).
 */
export function gnarkG1ToU32(bytes: Uint8Array, offset = 0): Uint32Array {
  const result = new Uint32Array(LIMBS_PER_FIELD * 2);
  const xLimbs = beBytesToU32(bytes, offset);
  const yLimbs = beBytesToU32(bytes, offset + FP_BYTES);
  result.set(xLimbs, 0);
  result.set(yLimbs, LIMBS_PER_FIELD);
  return result;
}

/**
 * Convert 16 u32 limbs back to gnark G1Affine (64 BE bytes).
 */
export function u32ToGnarkG1(
  limbs: Uint32Array,
  limbOffset = 0,
): Uint8Array {
  const result = new Uint8Array(FP_BYTES * 2);
  u32ToBeBytes(limbs, limbOffset, result, 0);
  u32ToBeBytes(limbs, limbOffset + LIMBS_PER_FIELD, result, FP_BYTES);
  return result;
}

// ---------------------------------------------------------------------------
// Batch conversions
// ---------------------------------------------------------------------------

/**
 * Convert an array of gnark G1 points (N × 64 BE bytes) to a flat u32 array
 * (N × 16 u32 limbs) suitable for webgpu-crypto.
 */
export function gnarkG1BatchToU32(
  bytes: Uint8Array,
  numPoints: number,
): Uint32Array {
  const pointBytes = FP_BYTES * 2;
  const pointLimbs = LIMBS_PER_FIELD * 2;
  const result = new Uint32Array(numPoints * pointLimbs);
  for (let i = 0; i < numPoints; i++) {
    const limbs = gnarkG1ToU32(bytes, i * pointBytes);
    result.set(limbs, i * pointLimbs);
  }
  return result;
}

/**
 * Convert a flat u32 array (N × 16 limbs) back to gnark G1 bytes (N × 64 BE bytes).
 */
export function u32BatchToGnarkG1(
  limbs: Uint32Array,
  numPoints: number,
): Uint8Array {
  const pointBytes = FP_BYTES * 2;
  const pointLimbs = LIMBS_PER_FIELD * 2;
  const result = new Uint8Array(numPoints * pointBytes);
  for (let i = 0; i < numPoints; i++) {
    const g1Bytes = u32ToGnarkG1(limbs, i * pointLimbs);
    result.set(g1Bytes, i * pointBytes);
  }
  return result;
}
