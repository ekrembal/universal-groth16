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
/** Read a 32-byte big-endian field element as a bigint. */
export declare function beFieldToBigInt(bytes: Uint8Array, offset?: number): bigint;
/** Write a bigint to a 32-byte big-endian field element. */
export declare function bigIntToBeField(value: bigint, out: Uint8Array, offset?: number): void;
/**
 * Convert a bigint to 8 u32 limbs in big-endian u32 order.
 * limbs[0] is the most-significant u32.
 */
export declare function bigIntToU32Array(value: bigint): Uint32Array;
/**
 * Convert 8 u32 limbs (big-endian u32 order) back to a bigint.
 */
export declare function u32ArrayToBigInt(limbs: Uint32Array, offset?: number): bigint;
/**
 * Convert 32 big-endian bytes to 8 u32 limbs (BE u32 order).
 * Equivalent to: bigIntToU32Array(beFieldToBigInt(bytes, offset))
 * but avoids the intermediate bigint.
 */
export declare function beBytesToU32(bytes: Uint8Array, offset?: number): Uint32Array;
/**
 * Convert 8 u32 limbs (BE u32 order) to 32 big-endian bytes.
 */
export declare function u32ToBeBytes(limbs: Uint32Array, limbOffset: number, out: Uint8Array, byteOffset: number): void;
/**
 * Convert a gnark G1Affine (64 BE bytes) to 16 u32 limbs (x: 8, y: 8).
 */
export declare function gnarkG1ToU32(bytes: Uint8Array, offset?: number): Uint32Array;
/**
 * Convert 16 u32 limbs back to gnark G1Affine (64 BE bytes).
 */
export declare function u32ToGnarkG1(limbs: Uint32Array, limbOffset?: number): Uint8Array;
/**
 * Convert an array of gnark G1 points (N × 64 BE bytes) to a flat u32 array
 * (N × 16 u32 limbs) suitable for webgpu-crypto.
 */
export declare function gnarkG1BatchToU32(bytes: Uint8Array, numPoints: number): Uint32Array;
/**
 * Convert a flat u32 array (N × 16 limbs) back to gnark G1 bytes (N × 64 BE bytes).
 */
export declare function u32BatchToGnarkG1(limbs: Uint32Array, numPoints: number): Uint8Array;
