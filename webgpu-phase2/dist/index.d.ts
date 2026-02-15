/**
 * WebGPU Phase 2 Trusted Setup Ceremony for BN254.
 *
 * @module webgpu-phase2
 */
export { FP_MODULUS, FR_MODULUS, CURVE_B, G1_GENERATOR_X, G1_GENERATOR_Y, FP_BYTES, FR_BYTES, G1_UNCOMPRESSED_BYTES, G2_UNCOMPRESSED_BYTES, LIMBS_PER_FIELD, LIMBS_PER_G1, } from './constants.js';
export type { G1Affine, G2Affine, Fp2Element, UpdateProof, Phase2Parameters, Phase2, } from './phase2/types.js';
export { G1_INFINITY, G2_INFINITY } from './phase2/types.js';
export { fpAdd, fpSub, fpMul, fpSquare, fpNeg, fpPow, fpInv, fpSqrt, fpLexLargest, fp2Add, fp2Sub, fp2Mul, fp2Square, fp2Neg, fp2Inv, fp2IsZero, fp2Sqrt, fp2LexLargest, frInv, frMul, frNormalize, g1IsInfinity, g1Neg, g1ScalarMul, scaleG1Slice, g2IsInfinity, g2Neg, g2ScalarMul, } from './crypto.js';
export { beFieldToBigInt, bigIntToBeField, bigIntToU32Array, u32ArrayToBigInt, beBytesToU32, u32ToBeBytes, gnarkG1ToU32, u32ToGnarkG1, gnarkG1BatchToU32, u32BatchToGnarkG1, } from './bindings/endian.js';
export { parsePhase2 } from './phase2/parse.js';
export { serializePhase2, serializePhase2Raw } from './phase2/serialize.js';
export { phase2UpdateCPU, phase2UpdateGPU, computeChallenge, } from './phase2/update.js';
export { requestDevice, getCapabilities, computeBatchSize } from './webgpu/device.js';
export { scaleG1SliceBatched, scaleG1SliceCPU, scaleG1SliceGPU, } from './webgpu/scaleG1Slice.js';
export { createStorageBuffer, createStagingBuffer, readBuffer, readBufferU32, } from './webgpu/buffers.js';
export { gpuBatchScalarMul } from './webgpu/pipeline.js';
export { WORKGROUP_SIZE } from './webgpu/shaders.js';
