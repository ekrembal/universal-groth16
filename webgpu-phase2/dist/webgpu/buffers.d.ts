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
export declare function createStorageBuffer(device: GPUDevice, data: Uint8Array | Uint32Array, usage?: GPUBufferUsageFlags): GPUBuffer;
/**
 * Create a staging buffer for reading GPU results back to CPU.
 */
export declare function createStagingBuffer(device: GPUDevice, size: number): GPUBuffer;
/**
 * Read data back from a GPU storage buffer.
 *
 * @param device WebGPU device
 * @param buffer source GPU buffer
 * @param size number of bytes to read
 * @returns Uint8Array with the buffer contents
 */
export declare function readBuffer(device: GPUDevice, buffer: GPUBuffer, size: number): Promise<Uint8Array>;
/**
 * Read data back from a GPU buffer as Uint32Array.
 */
export declare function readBufferU32(device: GPUDevice, buffer: GPUBuffer, numU32: number): Promise<Uint32Array>;
