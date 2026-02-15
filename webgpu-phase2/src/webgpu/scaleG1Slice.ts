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
import { scaleG1Slice as cpuScaleG1Slice } from '../crypto.js';
import { computeBatchSize } from './device.js';
import { bigIntToU32Array, u32ArrayToBigInt } from '../bindings/endian.js';
import { gpuBatchScalarMul } from './pipeline.js';
import { LIMBS_PER_FIELD, LIMBS_PER_G1 } from '../constants.js';

// ===========================================================================
// CPU fallback
// ===========================================================================

/**
 * Scale a G1 slice by a scalar using CPU arithmetic.
 * Suitable for small slices or environments without WebGPU.
 */
export function scaleG1SliceCPU(
  points: G1Affine[],
  scalar: bigint,
): G1Affine[] {
  return cpuScaleG1Slice(points, scalar);
}

// ===========================================================================
// Conversion: G1Affine[] ↔ u32 limbs
// ===========================================================================

/**
 * Pack G1Affine points into a flat Uint32Array for GPU upload.
 * Each point = 16 u32 limbs (x: 8, y: 8) in big-endian u32 order.
 */
function packPointsToU32(points: G1Affine[]): Uint32Array {
  const n = points.length;
  const result = new Uint32Array(n * LIMBS_PER_G1);
  for (let i = 0; i < n; i++) {
    const offset = i * LIMBS_PER_G1;
    const xLimbs = bigIntToU32Array(points[i].x);
    const yLimbs = bigIntToU32Array(points[i].y);
    result.set(xLimbs, offset);
    result.set(yLimbs, offset + LIMBS_PER_FIELD);
  }
  return result;
}

/**
 * Unpack a flat Uint32Array of GPU results back to G1Affine points.
 */
function unpackU32ToPoints(limbs: Uint32Array, n: number): G1Affine[] {
  const points: G1Affine[] = new Array(n);
  for (let i = 0; i < n; i++) {
    const offset = i * LIMBS_PER_G1;
    const x = u32ArrayToBigInt(limbs, offset);
    const y = u32ArrayToBigInt(limbs, offset + LIMBS_PER_FIELD);
    points[i] = { x, y };
  }
  return points;
}

// ===========================================================================
// GPU-accelerated path
// ===========================================================================

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
export async function scaleG1SliceGPU(
  device: GPUDevice,
  points: G1Affine[],
  scalar: bigint,
): Promise<G1Affine[]> {
  const batchSize = computeBatchSize(device);
  const numPoints = points.length;
  const result: G1Affine[] = new Array(numPoints);

  // Pre-compute scalar as u32 limbs (same for all batches)
  const scalarU32 = bigIntToU32Array(scalar);

  for (let offset = 0; offset < numPoints; offset += batchSize) {
    const count = Math.min(batchSize, numPoints - offset);
    const chunk = points.slice(offset, offset + count);

    // Convert to u32 limbs for GPU
    const affineU32 = packPointsToU32(chunk);

    // Run the 4-pass GPU scalar multiplication pipeline
    const resultU32 = await gpuBatchScalarMul(
      device,
      affineU32,
      scalarU32,
      count,
    );

    // Convert back to G1Affine
    const scaled = unpackU32ToPoints(resultU32, count);
    for (let i = 0; i < count; i++) {
      result[offset + i] = scaled[i];
    }
  }

  return result;
}

// ===========================================================================
// Unified entry point
// ===========================================================================

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
export async function scaleG1SliceBatched(
  points: G1Affine[],
  scalar: bigint,
  device?: GPUDevice,
): Promise<G1Affine[]> {
  if (device) {
    try {
      return await scaleG1SliceGPU(device, points, scalar);
    } catch (_err) {
      // GPU failed (device lost, timeout, resource exhaustion, etc.)
      // Fall back to CPU silently
      return scaleG1SliceCPU(points, scalar);
    }
  }
  return scaleG1SliceCPU(points, scalar);
}
