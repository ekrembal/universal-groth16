/**
 * WebGPU device initialization and capability querying.
 */
export interface DeviceCapabilities {
    /** Maximum bytes per storage buffer binding (typically 128 MB) */
    maxStorageBufferBindingSize: number;
    /** Maximum buffer size (up to 4 GB) */
    maxBufferSize: number;
    /** Maximum compute workgroup invocations */
    maxComputeWorkgroupSizeX: number;
}
/**
 * Request a WebGPU device with the capabilities needed for Phase 2.
 *
 * @throws if WebGPU is not available or no adapter is found.
 */
export declare function requestDevice(): Promise<GPUDevice>;
/**
 * Query device capabilities relevant to Phase 2 buffer sizing.
 */
export declare function getCapabilities(device: GPUDevice): DeviceCapabilities;
/**
 * Compute the optimal batch size for G1 point processing.
 *
 * The 4-pass pipeline creates several buffer types per point:
 *   - Affine (input/output): 16 × u32 = 64 bytes
 *   - Extended projective (intermediate): 32 × u32 = 128 bytes  ← largest
 *   - Per-point scalar: 8 × u32 = 32 bytes
 *
 * The batch size is limited by the largest single buffer, which is the
 * extended projective buffer at 128 bytes per point.
 *
 * @param device WebGPU device to query limits from.
 * @param safetyFactor fraction of the limit to use (default 0.8).
 * @returns maximum number of G1 points per batch.
 */
export declare function computeBatchSize(device: GPUDevice, safetyFactor?: number): number;
