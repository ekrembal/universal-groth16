/**
 * Batch G1 scalar multiplication — the hot path for Phase 2.
 *
 * Strategy:
 *   1. GPU path (WebGPU available): uses WGSL compute shaders via 4-pass pipeline
 *   2. CPU path (fallback): uses pure-BigInt scalar multiplication
 *
 * For Phase 2, all points are scaled by the *same* scalar, so we broadcast
 * the scalar to every workgroup invocation.
 */
import type { G1Affine } from '../phase2/types.js';
/**
 * Scale a G1 slice by a scalar using CPU arithmetic.
 * Suitable for small slices or environments without WebGPU.
 */
export declare function scaleG1SliceCPU(points: G1Affine[], scalar: bigint): G1Affine[];
/**
 * Scale a G1 slice by a scalar using WebGPU.
 *
 * This is the high-performance path. It:
 *   1. Queries device limits for buffer sizing
 *   2. Chunks the points into batches fitting GPU buffer limits
 *   3. For each chunk: converts to u32 limbs → GPU 4-pass pipeline → converts back
 *   4. Concatenates results
 *
 * @param device WebGPU device
 * @param points array of G1 affine points to scale
 * @param scalar the scalar to multiply by
 * @returns scaled points
 */
export declare function scaleG1SliceGPU(device: GPUDevice, points: G1Affine[], scalar: bigint): Promise<G1Affine[]>;
/**
 * Scale a G1 slice by a scalar, using GPU if available, else CPU.
 *
 * If the GPU operation fails (device lost, timeout, etc.), automatically
 * falls back to CPU computation.
 *
 * @param points G1 affine points to scale
 * @param scalar the scalar to multiply every point by
 * @param device optional WebGPU device for GPU acceleration
 * @returns array of scaled G1 affine points
 */
export declare function scaleG1SliceBatched(points: G1Affine[], scalar: bigint, device?: GPUDevice): Promise<G1Affine[]>;
