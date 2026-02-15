/**
 * Tests for Phase2 binary parse and serialize.
 *
 * Uses gnark-serialized Phase2 binary from test vectors.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';
import { parsePhase2 } from '../src/phase2/parse.js';
import { serializePhase2 } from '../src/phase2/serialize.js';
import { beFieldToBigInt } from '../src/bindings/endian.js';
import type { G1Affine, G2Affine } from '../src/phase2/types.js';

// Load test vectors
const vectorsPath = join(__dirname, '..', 'testvectors', 'phase2_vectors.json');
const vectors = JSON.parse(readFileSync(vectorsPath, 'utf-8'));

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function hexToBytes(hex: string): Uint8Array {
  const h = hex.startsWith('0x') ? hex.slice(2) : hex;
  const bytes = new Uint8Array(h.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function parseG1Hex(hex: string): G1Affine {
  const bytes = hexToBytes(hex);
  return {
    x: beFieldToBigInt(bytes, 0),
    y: beFieldToBigInt(bytes, 32),
  };
}

function parseG2Hex(hex: string): G2Affine {
  const bytes = hexToBytes(hex);
  // gnark-crypto G2 serialization: A1 | A0 (imaginary first!)
  return {
    x: { c0: beFieldToBigInt(bytes, 32), c1: beFieldToBigInt(bytes, 0) },
    y: { c0: beFieldToBigInt(bytes, 96), c1: beFieldToBigInt(bytes, 64) },
  };
}

function g1Eq(a: G1Affine, b: G1Affine): boolean {
  return a.x === b.x && a.y === b.y;
}

function g2Eq(a: G2Affine, b: G2Affine): boolean {
  return (
    a.x.c0 === b.x.c0 &&
    a.x.c1 === b.x.c1 &&
    a.y.c0 === b.y.c0 &&
    a.y.c1 === b.y.c1
  );
}

// ---------------------------------------------------------------------------
// Parse Phase2 binary
// ---------------------------------------------------------------------------

describe('parsePhase2', () => {
  const binaryBase64 = vectors.phase2_binary_before as string;
  const binary = Uint8Array.from(atob(binaryBase64), (c) =>
    c.charCodeAt(0),
  );

  it('should parse without error', () => {
    const p = parsePhase2(binary);
    expect(p).toBeDefined();
    expect(p.parameters).toBeDefined();
  });

  it('should parse G1.Delta matching test vector', () => {
    const p = parsePhase2(binary);
    const expected = parseG1Hex(vectors.phase2_before.g1_delta);
    expect(g1Eq(p.parameters.g1.delta, expected)).toBe(true);
  });

  it('should parse G2.Delta matching test vector', () => {
    const p = parsePhase2(binary);
    const expected = parseG2Hex(vectors.phase2_before.g2_delta);
    expect(g2Eq(p.parameters.g2.delta, expected)).toBe(true);
  });

  it('should parse G1.Z with correct length and values', () => {
    const p = parsePhase2(binary);
    const expectedZ = (vectors.phase2_before.g1_z as string[]).map(parseG1Hex);
    expect(p.parameters.g1.z.length).toBe(expectedZ.length);
    for (let i = 0; i < expectedZ.length; i++) {
      expect(g1Eq(p.parameters.g1.z[i], expectedZ[i])).toBe(true);
    }
  });

  it('should parse G1.PKK correctly (empty for tiny circuit)', () => {
    const p = parsePhase2(binary);
    const expectedPKK = (vectors.phase2_before.g1_pkk as string[]).map(parseG1Hex);
    expect(p.parameters.g1.pkk.length).toBe(expectedPKK.length);
  });

  it('should parse commitment count', () => {
    const p = parsePhase2(binary);
    expect(p.parameters.g2.sigma.length).toBe(
      (vectors.phase2_before.g2_sigma as string[]).length,
    );
  });

  it('should have a challenge', () => {
    const p = parsePhase2(binary);
    expect(p.challenge).toBeDefined();
    expect(p.challenge.length).toBeGreaterThanOrEqual(0);
  });
});

// ---------------------------------------------------------------------------
// Serialize → Parse roundtrip
// ---------------------------------------------------------------------------

describe('serializePhase2 → parsePhase2 roundtrip', () => {
  const binaryBase64 = vectors.phase2_binary_before as string;
  const binary = Uint8Array.from(atob(binaryBase64), (c) =>
    c.charCodeAt(0),
  );

  it('should produce byte-identical output', () => {
    const p = parsePhase2(binary);
    const reserialized = serializePhase2(p);
    expect(reserialized.length).toBe(binary.length);
    expect(reserialized).toEqual(binary);
  });

  it('should roundtrip correctly through multiple cycles', () => {
    const p1 = parsePhase2(binary);
    const bytes1 = serializePhase2(p1);
    const p2 = parsePhase2(bytes1);
    const bytes2 = serializePhase2(p2);
    expect(bytes2).toEqual(bytes1);
  });
});
