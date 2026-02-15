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
import { getPass1Shader, getIntermediateShader, getFinalShader, WORKGROUP_SIZE, } from './shaders.js';
import { createStorageBuffer, readBufferU32 } from './buffers.js';
/** Number of u32 limbs per field element. */
const FIELD_LIMBS = 8;
/** Number of u32 limbs per AffinePoint (2 fields). */
const AFFINE_LIMBS = 16;
/** Number of u32 limbs per extended Point (4 fields). */
const EXT_LIMBS = 32;
let cachedPipeline = null;
/**
 * Get or create the compute pipelines for the 4-pass scalar multiplication.
 * Pipelines are cached per device to avoid recompilation.
 */
function getOrCreatePipelines(device) {
    if (cachedPipeline && cachedPipeline.device === device) {
        return cachedPipeline;
    }
    const pass1Module = device.createShaderModule({
        code: getPass1Shader(WORKGROUP_SIZE),
    });
    const intermediateModule = device.createShaderModule({
        code: getIntermediateShader(WORKGROUP_SIZE),
    });
    const finalModule = device.createShaderModule({
        code: getFinalShader(WORKGROUP_SIZE),
    });
    const pass1Pipeline = device.createComputePipeline({
        layout: 'auto',
        compute: { module: pass1Module, entryPoint: 'main' },
    });
    const intermediatePipeline = device.createComputePipeline({
        layout: 'auto',
        compute: { module: intermediateModule, entryPoint: 'main' },
    });
    const finalPipeline = device.createComputePipeline({
        layout: 'auto',
        compute: { module: finalModule, entryPoint: 'main' },
    });
    cachedPipeline = {
        device,
        pass1Pipeline,
        intermediatePipeline,
        finalPipeline,
    };
    return cachedPipeline;
}
/**
 * Create a GPU buffer with the given size and usage flags.
 */
function createBuffer(device, size, usage) {
    return device.createBuffer({ size, usage });
}
/**
 * Run the 4-pass batch G1 scalar multiplication on the GPU.
 *
 * @param device WebGPU device
 * @param affinePointsU32 Flat u32 array of N affine points (N × 16 u32 limbs)
 * @param scalarU32 Scalar as 8 u32 limbs
 * @param numPoints Number of points
 * @returns Flat u32 array of N affine result points (N × 16 u32 limbs)
 */
export async function gpuBatchScalarMul(device, affinePointsU32, scalarU32, numPoints) {
    const pipelines = getOrCreatePipelines(device);
    const numWorkgroups = Math.ceil(numPoints / WORKGROUP_SIZE);
    // Buffer sizes in bytes
    const affineBufSize = numPoints * AFFINE_LIMBS * 4;
    const extBufSize = numPoints * EXT_LIMBS * 4;
    const scalarsBufSize = numPoints * FIELD_LIMBS * 4;
    const singleScalarBufSize = FIELD_LIMBS * 4;
    // ---- Create buffers ----
    // Input affine points
    const affineInputBuf = createStorageBuffer(device, affinePointsU32);
    // Scalar buffer (single scalar, broadcast to all invocations)
    const scalarBuf = createStorageBuffer(device, scalarU32);
    // Intermediate buffers: result points, temp points, per-point scalars
    // We need 2 sets for ping-pong between passes
    const STORAGE_RW = GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_SRC | GPUBufferUsage.COPY_DST;
    const resultBufA = createBuffer(device, extBufSize, STORAGE_RW);
    const tempBufA = createBuffer(device, extBufSize, STORAGE_RW);
    const scalarsBufA = createBuffer(device, scalarsBufSize, STORAGE_RW);
    const resultBufB = createBuffer(device, extBufSize, STORAGE_RW);
    const tempBufB = createBuffer(device, extBufSize, STORAGE_RW);
    const scalarsBufB = createBuffer(device, scalarsBufSize, STORAGE_RW);
    // Output affine points
    const affineOutputBuf = createBuffer(device, affineBufSize, STORAGE_RW);
    // Helper: run a single compute pass and wait for GPU to finish.
    // Waiting between passes prevents GPU timeouts (TDR) on large dispatches.
    async function runPass(pipeline, entries) {
        const bindGroup = device.createBindGroup({
            layout: pipeline.getBindGroupLayout(0),
            entries,
        });
        const encoder = device.createCommandEncoder();
        const pass = encoder.beginComputePass();
        pass.setPipeline(pipeline);
        pass.setBindGroup(0, bindGroup);
        pass.dispatchWorkgroups(numWorkgroups);
        pass.end();
        device.queue.submit([encoder.finish()]);
        // Wait for GPU to finish this pass before starting the next.
        // This prevents multiple heavy passes from piling up and causing TDR.
        await device.queue.onSubmittedWorkDone();
    }
    try {
        // ---- Pass 1: Affine → Projective + first 64 bits ----
        await runPass(pipelines.pass1Pipeline, [
            { binding: 0, resource: { buffer: affineInputBuf } },
            { binding: 1, resource: { buffer: scalarBuf } },
            { binding: 2, resource: { buffer: resultBufA } },
            { binding: 3, resource: { buffer: tempBufA } },
            { binding: 4, resource: { buffer: scalarsBufA } },
        ]);
        // ---- Pass 2: Intermediate (64 bits) ----
        await runPass(pipelines.intermediatePipeline, [
            { binding: 0, resource: { buffer: resultBufA } },
            { binding: 1, resource: { buffer: scalarsBufA } },
            { binding: 2, resource: { buffer: tempBufA } },
            { binding: 3, resource: { buffer: resultBufB } },
            { binding: 4, resource: { buffer: tempBufB } },
            { binding: 5, resource: { buffer: scalarsBufB } },
        ]);
        // ---- Pass 3: Intermediate (64 bits, ping-pong back to A) ----
        await runPass(pipelines.intermediatePipeline, [
            { binding: 0, resource: { buffer: resultBufB } },
            { binding: 1, resource: { buffer: scalarsBufB } },
            { binding: 2, resource: { buffer: tempBufB } },
            { binding: 3, resource: { buffer: resultBufA } },
            { binding: 4, resource: { buffer: tempBufA } },
            { binding: 5, resource: { buffer: scalarsBufA } },
        ]);
        // ---- Pass 4: Final (last 64 bits + normalize to affine) ----
        await runPass(pipelines.finalPipeline, [
            { binding: 0, resource: { buffer: resultBufA } },
            { binding: 1, resource: { buffer: scalarsBufA } },
            { binding: 2, resource: { buffer: tempBufA } },
            { binding: 3, resource: { buffer: affineOutputBuf } },
        ]);
        // ---- Read back results ----
        const resultU32 = await readBufferU32(device, affineOutputBuf, numPoints * AFFINE_LIMBS);
        return resultU32;
    }
    finally {
        // ---- Cleanup (always, even on error) ----
        affineInputBuf.destroy();
        scalarBuf.destroy();
        resultBufA.destroy();
        tempBufA.destroy();
        scalarsBufA.destroy();
        resultBufB.destroy();
        tempBufB.destroy();
        scalarsBufB.destroy();
        affineOutputBuf.destroy();
    }
}
//# sourceMappingURL=pipeline.js.map