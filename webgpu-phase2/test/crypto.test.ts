/**
 * Tests for BN254 crypto primitives against gnark test vectors.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';
import { g1ScalarMul, g2ScalarMul, frInv, scaleG1Slice } from '../src/crypto.js';
import { FP_MODULUS, FR_MODULUS } from '../src/constants.js';
import type { G1Affine, G2Affine } from '../src/phase2/types.js';
import { beFieldToBigInt } from '../src/bindings/endian.js';

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
// G1 scalar multiplication
// ---------------------------------------------------------------------------

describe('G1 scalar multiplication', () => {
  const testCases = vectors.g1_scalar_mul as Array<{
    point: string;
    scalar: string;
    result: string;
  }>;

  for (const tc of testCases) {
    it(`[${tc.scalar}] * point`, () => {
      const point = parseG1Hex(tc.point);
      const scalar = BigInt(tc.scalar);
      const expected = parseG1Hex(tc.result);
      const actual = g1ScalarMul(point, scalar);
      expect(g1Eq(actual, expected)).toBe(true);
    });
  }

  it('should return infinity for scalar 0', () => {
    const g1 = parseG1Hex(vectors.g1_generator);
    const result = g1ScalarMul(g1, 0n);
    expect(result.x).toBe(0n);
    expect(result.y).toBe(0n);
  });

  it('should return the point for scalar 1', () => {
    const g1 = parseG1Hex(vectors.g1_generator);
    const result = g1ScalarMul(g1, 1n);
    expect(g1Eq(result, g1)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// G2 scalar multiplication
// ---------------------------------------------------------------------------

describe('G2 scalar multiplication', () => {
  const testCases = vectors.g2_scalar_mul as Array<{
    point: string;
    scalar: string;
    result: string;
  }>;

  for (const tc of testCases) {
    it(`[${tc.scalar}] * G2 point`, () => {
      const point = parseG2Hex(tc.point);
      const scalar = BigInt(tc.scalar);
      const expected = parseG2Hex(tc.result);
      const actual = g2ScalarMul(point, scalar);
      expect(g2Eq(actual, expected)).toBe(true);
    });
  }
});

// ---------------------------------------------------------------------------
// Fr inverse
// ---------------------------------------------------------------------------

describe('Fr inverse', () => {
  const testCases = vectors.fr_inverse as Array<{
    input: string;
    result: string;
  }>;

  for (const tc of testCases) {
    it(`inv(${tc.input})`, () => {
      const input = BigInt(tc.input);
      const expected = BigInt(tc.result);
      const actual = frInv(input);
      expect(actual).toBe(expected);
    });
  }

  it('should satisfy a * inv(a) = 1 mod r', () => {
    const a = 42n;
    const aInv = frInv(a);
    expect((a * aInv) % FR_MODULUS).toBe(1n);
  });
});

// ---------------------------------------------------------------------------
// Batch G1 scaling
// ---------------------------------------------------------------------------

describe('scaleG1Slice (batch)', () => {
  it('should match gnark batch_scale_g1 test vector', () => {
    const batchData = vectors.batch_scale_g1;
    const points = (batchData.points as string[]).map(parseG1Hex);
    const scalar = BigInt(batchData.scalar);
    const expected = (batchData.expected as string[]).map(parseG1Hex);

    const actual = scaleG1Slice(points, scalar);

    expect(actual.length).toBe(expected.length);
    for (let i = 0; i < actual.length; i++) {
      expect(g1Eq(actual[i], expected[i])).toBe(true);
    }
  });
});
