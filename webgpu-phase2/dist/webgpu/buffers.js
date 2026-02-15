/**
 * WebGPU buffer creation and data transfer helpers.
 */
/**
 * Create a GPU storage buffer with initial data.
 *
 * @param device WebGPU device
 * @param data initial data to upload
 * @param usage additional buffer usage flags
 * @returns the created GPUBuffer
 */
export function createStorageBuffer(device, data, usage = 0) {
    const buffer = device.createBuffer({
        size: data.byteLength,
        usage: GPUBufferUsage.STORAGE |
            GPUBufferUsage.COPY_SRC |
            GPUBufferUsage.COPY_DST |
            usage,
        mappedAtCreation: true,
    });
    const mapping = buffer.getMappedRange();
    if (data instanceof Uint32Array) {
        new Uint32Array(mapping).set(data);
    }
    else {
        new Uint8Array(mapping).set(data);
    }
    buffer.unmap();
    return buffer;
}
/**
 * Create a staging buffer for reading GPU results back to CPU.
 */
export function createStagingBuffer(device, size) {
    return device.createBuffer({
        size,
        usage: GPUBufferUsage.MAP_READ | GPUBufferUsage.COPY_DST,
    });
}
/**
 * Read data back from a GPU storage buffer.
 *
 * @param device WebGPU device
 * @param buffer source GPU buffer
 * @param size number of bytes to read
 * @returns Uint8Array with the buffer contents
 */
export async function readBuffer(device, buffer, size) {
    const staging = createStagingBuffer(device, size);
    const commandEncoder = device.createCommandEncoder();
    commandEncoder.copyBufferToBuffer(buffer, 0, staging, 0, size);
    device.queue.submit([commandEncoder.finish()]);
    await staging.mapAsync(GPUMapMode.READ);
    const result = new Uint8Array(staging.getMappedRange()).slice();
    staging.unmap();
    staging.destroy();
    return result;
}
/**
 * Read data back from a GPU buffer as Uint32Array.
 */
export async function readBufferU32(device, buffer, numU32) {
    const bytes = await readBuffer(device, buffer, numU32 * 4);
    return new Uint32Array(bytes.buffer, bytes.byteOffset, numU32);
}
//# sourceMappingURL=buffers.js.map