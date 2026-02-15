/**
 * Phase 2 Trusted Setup Ceremony — browser contribution logic.
 *
 * Replicates gnark's Phase2.Contribute() flow:
 *   1. Hash the current state to produce the challenge
 *   2. Generate random delta and sigma scalars
 *   3. Create update proofs (commitment + PoK)
 *   4. Apply the parameter update (the expensive WebGPU-accelerable part)
 *   5. Serialize the updated state
 */

import {
  parsePhase2,
  serializePhase2Raw,
  phase2UpdateCPU,
  phase2UpdateGPU,
  g1ScalarMul,
  g2ScalarMul,
  FR_MODULUS,
  G1_GENERATOR_X,
  G1_GENERATOR_Y,
} from 'webgpu-phase2';
import type { Phase2, G1Affine, G2Affine } from 'webgpu-phase2';

// DST constants matching gnark's phase2.go
const DST_DELTA = 0;
const DST_SIGMA = 1;

/** Summary of a parsed Phase 2 file */
export interface CeremonyInfo {
  phase2: Phase2;
  raw: Uint8Array;
  g1ZCount: number;
  g1PKKCount: number;
  commitments: number;
  sigmaCKKCounts: number[];
  totalG1Points: number;
  fileSizeBytes: number;
}

/** Progress callback for long-running operations */
export type ProgressCallback = (stage: string, detail: string, progress: number) => void;

/** Timing breakdown of a contribution */
export interface ContributionTiming {
  parseMs: number;
  challengeMs: number;
  randomGenMs: number;
  proofGenMs: number;
  paramUpdateMs: number;
  serializeMs: number;
  totalMs: number;
}

/** Result of a contribution */
export interface ContributionResult {
  data: Uint8Array;
  timing: ContributionTiming;
  phase2: Phase2;
}

/**
 * Parse a Phase 2 binary file and return ceremony info.
 */
export function parseCeremonyFile(data: Uint8Array): CeremonyInfo {
  const phase2 = parsePhase2(data);

  const g1ZCount = phase2.parameters.g1.z.length;
  const g1PKKCount = phase2.parameters.g1.pkk.length;
  const commitments = phase2.parameters.g2.sigma.length;
  const sigmaCKKCounts = phase2.parameters.g1.sigmaCKK.map(s => s.length);

  let totalG1Points = 1 + g1ZCount + g1PKKCount; // delta + Z + PKK
  for (const count of sigmaCKKCounts) {
    totalG1Points += count;
  }

  return {
    phase2,
    raw: data,
    g1ZCount,
    g1PKKCount,
    commitments,
    sigmaCKKCounts,
    totalG1Points,
    fileSizeBytes: data.length,
  };
}

/**
 * Compute SHA-256 challenge hash of the Phase 2 state.
 */
async function computeChallenge(data: Uint8Array): Promise<Uint8Array> {
  // Copy into a plain ArrayBuffer to satisfy strict TypeScript typing
  const buf = new ArrayBuffer(data.byteLength);
  new Uint8Array(buf).set(data);
  const hash = await crypto.subtle.digest('SHA-256', buf);
  return new Uint8Array(hash);
}

/**
 * Generate a cryptographically random scalar in Fr (non-zero).
 */
function generateRandomFr(): bigint {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);

  // Convert to bigint
  let scalar = 0n;
  for (let i = 0; i < 32; i++) {
    scalar = (scalar << 8n) | BigInt(bytes[i]);
  }

  // Reduce modulo Fr and ensure non-zero
  scalar = scalar % FR_MODULUS;
  if (scalar === 0n) {
    scalar = 1n; // Extremely unlikely, but handle it
  }

  return scalar;
}

/**
 * Compute the PoK base point in G2: Hash(commitment.Marshal() || challenge, [dst])
 *
 * This replicates gnark-crypto's HashToG2. Since HashToG2 is complex
 * (hash-to-curve standard), we use a simplified approach for the contribution.
 * The commitment and PoK will still be structurally valid for the ceremony file.
 *
 * NOTE: For a production ceremony, this should use the exact same HashToG2
 * algorithm as gnark-crypto (RFC 9380 / Shallue-van de Woestijne for BN254 G2).
 * For performance testing, the simplified proofs are sufficient.
 */
function computeSimplifiedPoK(
  scalar: bigint,
  _challenge: Uint8Array,
  _dst: number,
): { commitment: G1Affine; pok: G2Affine } {
  const g1Gen: G1Affine = { x: G1_GENERATOR_X, y: G1_GENERATOR_Y };

  // commitment = [scalar]G1
  const commitment = g1ScalarMul(g1Gen, scalar);

  // For the PoK, we need HashToG2(commitment.Marshal() || challenge, [dst]).
  // Since we don't have a full HashToG2 implementation, we use a simplified
  // approach: pok = [scalar]G2_gen. This is NOT cryptographically valid for
  // verification but produces a well-formed G2 point in the ceremony file.
  // The parameter update itself is the important part for performance testing.
  //
  // TODO: Implement proper BN254 HashToG2 for production ceremony support.
  const g2Gen: G2Affine = {
    x: {
      c0: 10857046999023057135944570762232829481370756359578518086990519993285655852781n,
      c1: 11559732032986387107991004021392285783925812861821192530917403151452391805634n,
    },
    y: {
      c0: 8495653923123431417604973247489272438418190587263600148770280649306958101930n,
      c1: 4082367875863433681332203403145435568316851327593401208105741076214120093531n,
    },
  };
  const pok = g2ScalarMul(g2Gen, scalar);

  return { commitment, pok };
}

/**
 * Check if WebGPU is available in the current browser.
 * Does NOT hold a persistent device reference — devices are created on demand
 * via requestFreshDevice() to avoid stale GPU instance errors.
 */
export async function checkWebGPU(): Promise<{
  available: boolean;
  adapterInfo?: string;
}> {
  try {
    const gpu = (navigator as unknown as { gpu?: GPU }).gpu;
    if (!gpu) {
      return { available: false };
    }

    const adapter = await gpu.requestAdapter({ powerPreference: 'high-performance' });
    if (!adapter) {
      return { available: false };
    }

    // requestAdapterInfo may not exist in all WebGPU type versions
    let adapterInfo = 'Unknown adapter';
    try {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const info = await (adapter as any).requestAdapterInfo?.();
      if (info) {
        adapterInfo = `${info.vendor || ''} ${info.architecture || ''} (${info.description || 'unknown'})`.trim();
      }
    } catch {
      // Ignore — some browsers don't support requestAdapterInfo
    }

    return { available: true, adapterInfo };
  } catch {
    return { available: false };
  }
}

/**
 * Request a fresh GPUDevice right before use.
 *
 * This avoids the "A valid external Instance reference no longer exists" error
 * that occurs when a stale device reference is used after the GPU process has
 * been recycled (sleep/wake, tab backgrounding, resource pressure, etc.).
 *
 * @returns a fresh GPUDevice, or undefined if WebGPU is unavailable
 */
export async function requestFreshDevice(): Promise<GPUDevice | undefined> {
  try {
    const gpu = (navigator as unknown as { gpu?: GPU }).gpu;
    if (!gpu) return undefined;

    const adapter = await gpu.requestAdapter({ powerPreference: 'high-performance' });
    if (!adapter) return undefined;

    const device = await adapter.requestDevice({
      requiredLimits: {
        maxStorageBufferBindingSize: adapter.limits.maxStorageBufferBindingSize,
        maxBufferSize: adapter.limits.maxBufferSize,
        maxComputeWorkgroupsPerDimension: adapter.limits.maxComputeWorkgroupsPerDimension,
      },
    });

    return device;
  } catch {
    return undefined;
  }
}

/**
 * Perform a Phase 2 contribution.
 *
 * This is the main entry point for the ceremony frontend.
 * When useGPU is true, a fresh GPUDevice is requested right before use
 * to avoid stale instance errors from long-lived device references.
 */
export async function contribute(
  info: CeremonyInfo,
  useGPU: boolean,
  onProgress?: ProgressCallback,
): Promise<ContributionResult> {
  const totalStart = performance.now();
  const timing: ContributionTiming = {
    parseMs: 0,
    challengeMs: 0,
    randomGenMs: 0,
    proofGenMs: 0,
    paramUpdateMs: 0,
    serializeMs: 0,
    totalMs: 0,
  };

  // Use the raw input bytes for the challenge hash (matches gnark's behavior)
  onProgress?.('Preparing', 'Computing challenge hash...', 0);

  let start = performance.now();
  const challenge = await computeChallenge(info.raw);
  timing.challengeMs = performance.now() - start;

  onProgress?.('Generating', 'Generating random contributions...', 0.05);

  // 2. Generate random scalars
  start = performance.now();
  const delta = generateRandomFr();
  const nbCommitments = info.phase2.parameters.g2.sigma.length;
  const sigmas: bigint[] = [];
  for (let i = 0; i < nbCommitments; i++) {
    sigmas.push(generateRandomFr());
  }
  timing.randomGenMs = performance.now() - start;

  // 3. Generate update proofs
  onProgress?.('Proofs', 'Generating update proofs...', 0.1);
  start = performance.now();

  // Delta proof
  const deltaProof = computeSimplifiedPoK(delta, challenge, DST_DELTA);
  info.phase2.delta = {
    contributionCommitment: deltaProof.commitment,
    contributionPok: deltaProof.pok,
  };

  // Sigma proofs
  for (let i = 0; i < nbCommitments; i++) {
    const sigmaProof = computeSimplifiedPoK(sigmas[i], challenge, DST_SIGMA + i);
    info.phase2.sigmas[i] = {
      contributionCommitment: sigmaProof.commitment,
      contributionPok: sigmaProof.pok,
    };
  }
  timing.proofGenMs = performance.now() - start;

  // 4. Apply parameter update (THE HOT PATH)
  // Request a fresh GPU device right before use to avoid stale references
  let gpuDevice: GPUDevice | undefined;
  if (useGPU) {
    onProgress?.('Updating', 'Requesting GPU device...', 0.13);
    gpuDevice = await requestFreshDevice();
    if (!gpuDevice) {
      onProgress?.('Updating', 'GPU unavailable, using CPU...', 0.14);
    }
  }

  onProgress?.('Updating', `Applying parameter update (${gpuDevice ? 'GPU' : 'CPU'})...`, 0.15);
  start = performance.now();

  if (gpuDevice) {
    try {
      await phase2UpdateGPU(info.phase2, delta, sigmas, gpuDevice);
    } catch (gpuErr) {
      // GPU failed mid-operation — this shouldn't happen because
      // scaleG1SliceBatched already has CPU fallback, but just in case
      // re-run the entire update on CPU with a clean Phase2 state.
      // Since phase2UpdateGPU mutates in-place, we can't simply retry;
      // re-throw and let the user try again.
      throw new Error(
        `GPU update failed: ${gpuErr instanceof Error ? gpuErr.message : String(gpuErr)}. ` +
        `Try again with CPU mode.`
      );
    } finally {
      gpuDevice.destroy();
    }
  } else {
    phase2UpdateCPU(info.phase2, delta, sigmas);
  }
  timing.paramUpdateMs = performance.now() - start;

  // 5. Update the challenge
  onProgress?.('Finalizing', 'Updating challenge hash...', 0.9);
  info.phase2.challenge = challenge;

  // 6. Serialize the result
  onProgress?.('Serializing', 'Writing output file...', 0.95);
  start = performance.now();
  const result = serializePhase2Raw(info.phase2);
  timing.serializeMs = performance.now() - start;

  timing.totalMs = performance.now() - totalStart;

  onProgress?.('Done', 'Contribution complete!', 1.0);

  return {
    data: result,
    timing,
    phase2: info.phase2,
  };
}

/**
 * Format a byte count as a human-readable string.
 */
export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

/**
 * Format milliseconds as a human-readable duration.
 */
export function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms.toFixed(0)}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  const minutes = Math.floor(ms / 60000);
  const seconds = ((ms % 60000) / 1000).toFixed(0);
  return `${minutes}m ${seconds}s`;
}
