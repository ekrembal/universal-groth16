/**
 * GPU compute pipeline for batch G1 scalar multiplication.
 *
 * Orchestrates a 4-pass multipass scalar multiplication:
 *   Pass 1: Affine → Projective + first 64 bits of scalar mul
 *   Pass 2: Next 64 bits
 *   Pass 3: Next 64 bits
 *   Pass 4: Last 64 bits + Projective → Affine normalization
 *
 * This approach splits the 256-bit scalar multiplication across 4 GPU dispatches
 * to avoid exceeding GPU instruction limits per invocation.
 *
 * Buffer layout for points uses the webgpu-crypto convention:
 *   AffinePoint  = 16 × u32 (x: 8, y: 8)
 *   Point (ext)  = 32 × u32 (x: 8, y: 8, t: 8, z: 8)
 *   Field/Scalar = 8 × u32
 * All in big-endian u32 limb order (matching endian.ts).
 */
/**
 * Run the 4-pass batch G1 scalar multiplication on the GPU.
 *
 * @param device WebGPU device
 * @param affinePointsU32 Flat u32 array of N affine points (N × 16 u32 limbs)
 * @param scalarU32 Scalar as 8 u32 limbs
 * @param numPoints Number of points
 * @returns Flat u32 array of N affine result points (N × 16 u32 limbs)
 */
export declare function gpuBatchScalarMul(device: GPUDevice, affinePointsU32: Uint32Array, scalarU32: Uint32Array, numPoints: number): Promise<Uint32Array>;
