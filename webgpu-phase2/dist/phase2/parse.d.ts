/**
 * Parse gnark Phase2 binary format.
 *
 * Binary layout (gnark-crypto default encoder: uncompressed, big-endian):
 *
 *   1. uint16 BE: nbCommitments
 *   2. Parameters (refsSlice order):
 *      - G1.Delta:    64 bytes  (single G1Affine)
 *      - G1.PKK:      4-byte uint32 len + N × 64 bytes
 *      - G1.Z:        4-byte uint32 len + M × 64 bytes
 *      - G2.Delta:    128 bytes (single G2Affine)
 *      - For each commitment i:
 *          G1.SigmaCKK[i]: 4-byte uint32 len + P_i × 64 bytes
 *      - For each commitment i:
 *          G2.Sigma[i]: 128 bytes (single G2Affine)
 *   3. Proofs:
 *      - Delta UpdateProof:  G1(64) + G2(128) = 192 bytes
 *      - For each commitment i:
 *          Sigmas[i] UpdateProof: 192 bytes
 *   4. Challenge:
 *      - uint16 BE length + data bytes
 */
import type { Phase2 } from './types.js';
/**
 * Parse a gnark Phase2 binary blob into the Phase2 structure.
 *
 * Supports both compressed (gnark default, 32B G1 / 64B G2) and
 * uncompressed/raw (64B G1 / 128B G2) point encodings. The format
 * is auto-detected per-point from the MSB flag bits.
 *
 * @param data raw bytes from gnark Phase2.WriteTo() or writePhase2Raw()
 * @returns parsed Phase2 object
 * @throws on truncated or malformed data
 */
export declare function parsePhase2(data: Uint8Array): Phase2;
