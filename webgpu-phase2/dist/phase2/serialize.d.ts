/**
 * Serialize Phase2 back to gnark binary format.
 *
 * Produces bytes compatible with gnark's Phase2.ReadFrom().
 */
import type { Phase2 } from './types.js';
/**
 * Serialize a Phase2 object to gnark-compatible binary format.
 *
 * The output can be read by gnark's Phase2.ReadFrom().
 *
 * @param p the Phase2 state to serialize
 * @returns raw bytes
 */
export declare function serializePhase2(p: Phase2): Uint8Array;
/**
 * Serialize a Phase2 object in uncompressed (raw) format.
 *
 * Uses 64-byte G1 and 128-byte G2 points for the parameter slices (the bulk
 * of the data). Proofs are still written compressed (only a few points).
 * The output can be read by gnark's Phase2.ReadFrom() which auto-detects
 * compressed vs uncompressed per-point.
 *
 * Use this for large files to avoid slow fpSqrt decompression when re-parsing.
 */
export declare function serializePhase2Raw(p: Phase2): Uint8Array;
