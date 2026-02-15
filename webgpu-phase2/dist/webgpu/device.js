/**
 * WebGPU device initialization and capability querying.
 */
/**
 * Request a WebGPU device with the capabilities needed for Phase 2.
 *
 * @throws if WebGPU is not available or no adapter is found.
 */
export async function requestDevice() {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const gpu = globalThis.navigator?.gpu;
    if (!gpu) {
        throw new Error('WebGPU is not available in this environment. ' +
            'Use a browser with WebGPU support (Chrome 113+, Edge 113+, Firefox Nightly).');
    }
    const adapter = await gpu.requestAdapter({
        powerPreference: 'high-performance',
    });
    if (!adapter) {
        throw new Error('No WebGPU adapter found.');
    }
    const device = await adapter.requestDevice({
        requiredLimits: {
            maxStorageBufferBindingSize: adapter.limits.maxStorageBufferBindingSize,
            maxBufferSize: adapter.limits.maxBufferSize,
            maxComputeWorkgroupSizeX: adapter.limits.maxComputeWorkgroupSizeX,
        },
    });
    return device;
}
/**
 * Query device capabilities relevant to Phase 2 buffer sizing.
 */
export function getCapabilities(device) {
    return {
        maxStorageBufferBindingSize: device.limits.maxStorageBufferBindingSize,
        maxBufferSize: device.limits.maxBufferSize,
        maxComputeWorkgroupSizeX: device.limits.maxComputeWorkgroupSizeX,
    };
}
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
export function computeBatchSize(device, safetyFactor = 0.8) {
    const limit = device.limits.maxStorageBufferBindingSize;
    // The largest buffer per point is the extended projective: 32 × 4 = 128 bytes
    const bytesPerPoint = 128;
    const maxByLimit = Math.floor((limit * safetyFactor) / bytesPerPoint);
    // Cap at 2^18 (262144) to avoid GPU timeouts and excessive VRAM usage.
    // Each batch at 2^18 uses ~32 MB for ext buffers, well within limits.
    return Math.min(maxByLimit, 1 << 18);
}
//# sourceMappingURL=device.js.map