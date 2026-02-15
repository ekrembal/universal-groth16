/**
 * Phase 2 update orchestration.
 *
 * Replicates gnark's Phase2.update() logic:
 *   1. Scale G2.Sigma[i] and G1.SigmaCKK[i] by sigma[i]
 *   2. Scale G1/G2 Delta by delta
 *   3. Invert delta → scale G1.Z and G1.PKK by delta⁻¹
 *
 * The batch G1 scaling (step 3) is the hot path and can be GPU-accelerated.
 */
import type { Phase2 } from './types.js';
/**
 * Apply a Phase 2 parameter update using CPU arithmetic.
 *
 * This replicates gnark's Phase2.update() exactly.
 * Mutates `p.parameters` in place.
 *
 * @param p Phase2 state to update
 * @param delta delta contribution (Fr element)
 * @param sigmas sigma contributions (one per commitment)
 */
export declare function phase2UpdateCPU(p: Phase2, delta: bigint, sigmas: bigint[]): void;
/**
 * Apply a Phase 2 parameter update using GPU acceleration for batch G1 ops.
 *
 * Uses WebGPU for the large G1 slice scaling (Z, PKK) and CPU for the rest.
 *
 * @param p Phase2 state to update
 * @param delta delta contribution (Fr element)
 * @param sigmas sigma contributions (one per commitment)
 * @param device WebGPU device for GPU-accelerated batch ops
 */
export declare function phase2UpdateGPU(p: Phase2, delta: bigint, sigmas: bigint[], device?: GPUDevice): Promise<void>;
/**
 * Compute the SHA-256 challenge hash for the current Phase2 state.
 *
 * This is used as input to Fiat–Shamir for deriving contribution randomness.
 *
 * @param data serialized Phase2 bytes
 * @returns 32-byte SHA-256 hash
 */
export declare function computeChallenge(data: Uint8Array): Promise<Uint8Array>;
