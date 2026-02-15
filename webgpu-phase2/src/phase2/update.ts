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
import {
  g1ScalarMul,
  g2ScalarMul,
  scaleG1Slice,
  frInv,
} from '../crypto.js';
import { scaleG1SliceBatched } from '../webgpu/scaleG1Slice.js';

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
export function phase2UpdateCPU(
  p: Phase2,
  delta: bigint,
  sigmas: bigint[],
): void {
  // 1. Scale sigma-related parameters
  for (let i = 0; i < sigmas.length; i++) {
    p.parameters.g2.sigma[i] = g2ScalarMul(
      p.parameters.g2.sigma[i],
      sigmas[i],
    );
    p.parameters.g1.sigmaCKK[i] = scaleG1Slice(
      p.parameters.g1.sigmaCKK[i],
      sigmas[i],
    );
  }

  // 2. Scale delta
  p.parameters.g2.delta = g2ScalarMul(p.parameters.g2.delta, delta);
  p.parameters.g1.delta = g1ScalarMul(p.parameters.g1.delta, delta);

  // 3. Invert delta and scale Z, PKK
  const deltaInv = frInv(delta);
  p.parameters.g1.z = scaleG1Slice(p.parameters.g1.z, deltaInv);
  p.parameters.g1.pkk = scaleG1Slice(p.parameters.g1.pkk, deltaInv);
}

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
export async function phase2UpdateGPU(
  p: Phase2,
  delta: bigint,
  sigmas: bigint[],
  device?: GPUDevice,
): Promise<void> {
  // 1. Scale sigma-related parameters (CPU — few points)
  for (let i = 0; i < sigmas.length; i++) {
    p.parameters.g2.sigma[i] = g2ScalarMul(
      p.parameters.g2.sigma[i],
      sigmas[i],
    );
    // SigmaCKK might be large — use GPU if available
    p.parameters.g1.sigmaCKK[i] = await scaleG1SliceBatched(
      p.parameters.g1.sigmaCKK[i],
      sigmas[i],
      device,
    );
  }

  // 2. Scale delta (CPU — single points)
  p.parameters.g2.delta = g2ScalarMul(p.parameters.g2.delta, delta);
  p.parameters.g1.delta = g1ScalarMul(p.parameters.g1.delta, delta);

  // 3. Invert delta and scale Z, PKK (GPU — large slices, the hot path)
  const deltaInv = frInv(delta);
  p.parameters.g1.z = await scaleG1SliceBatched(
    p.parameters.g1.z,
    deltaInv,
    device,
  );
  p.parameters.g1.pkk = await scaleG1SliceBatched(
    p.parameters.g1.pkk,
    deltaInv,
    device,
  );
}

/**
 * Compute the SHA-256 challenge hash for the current Phase2 state.
 *
 * This is used as input to Fiat–Shamir for deriving contribution randomness.
 *
 * @param data serialized Phase2 bytes
 * @returns 32-byte SHA-256 hash
 */
export async function computeChallenge(
  data: Uint8Array,
): Promise<Uint8Array> {
  // Use Web Crypto API (available in browsers and Node 15+)
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const cryptoObj = (globalThis as any).crypto as { subtle?: { digest(alg: string, data: ArrayBufferView | ArrayBuffer): Promise<ArrayBuffer> } } | undefined;
  if (cryptoObj?.subtle) {
    const hash = await cryptoObj.subtle.digest('SHA-256', data);
    return new Uint8Array(hash);
  }

  // Fallback: use @noble/hashes if available
  try {
    const { sha256 } = await import('@noble/hashes/sha256');
    return sha256(data);
  } catch {
    throw new Error(
      'No SHA-256 implementation available. ' +
        'Use a browser with Web Crypto API or install @noble/hashes.',
    );
  }
}
