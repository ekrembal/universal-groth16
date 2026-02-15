/**
 * Tests for Phase 2 update logic.
 *
 * Verifies that phase2UpdateCPU matches gnark's Phase2.update() output.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';
import { parsePhase2 } from '../src/phase2/parse.js';
import { phase2UpdateCPU } from '../src/phase2/update.js';
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
// Phase 2 update
// ---------------------------------------------------------------------------

describe('phase2UpdateCPU', () => {
  it('should produce G1.Delta matching gnark after update', () => {
    const binaryBase64 = vectors.phase2_binary_before as string;
    const binary = Uint8Array.from(atob(binaryBase64), (c) =>
      c.charCodeAt(0),
    );
    const p = parsePhase2(binary);

    const delta = BigInt(vectors.phase2_after.delta_scalar);
    const sigmas = (vectors.phase2_after.sigma_scalars as string[]).map(
      (s: string) => BigInt(s),
    );

    phase2UpdateCPU(p, delta, sigmas);

    const expectedDelta = parseG1Hex(vectors.phase2_after.g1_delta);
    expect(g1Eq(p.parameters.g1.delta, expectedDelta)).toBe(true);
  });

  it('should produce G2.Delta matching gnark after update', () => {
    const binaryBase64 = vectors.phase2_binary_before as string;
    const binary = Uint8Array.from(atob(binaryBase64), (c) =>
      c.charCodeAt(0),
    );
    const p = parsePhase2(binary);

    const delta = BigInt(vectors.phase2_after.delta_scalar);
    const sigmas = (vectors.phase2_after.sigma_scalars as string[]).map(
      (s: string) => BigInt(s),
    );

    phase2UpdateCPU(p, delta, sigmas);

    const expectedG2Delta = parseG2Hex(vectors.phase2_after.g2_delta);
    expect(g2Eq(p.parameters.g2.delta, expectedG2Delta)).toBe(true);
  });

  it('should produce G1.Z matching gnark after update', () => {
    const binaryBase64 = vectors.phase2_binary_before as string;
    const binary = Uint8Array.from(atob(binaryBase64), (c) =>
      c.charCodeAt(0),
    );
    const p = parsePhase2(binary);

    const delta = BigInt(vectors.phase2_after.delta_scalar);
    const sigmas = (vectors.phase2_after.sigma_scalars as string[]).map(
      (s: string) => BigInt(s),
    );

    phase2UpdateCPU(p, delta, sigmas);

    const expectedZ = (vectors.phase2_after.g1_z as string[]).map(parseG1Hex);
    expect(p.parameters.g1.z.length).toBe(expectedZ.length);
    for (let i = 0; i < expectedZ.length; i++) {
      expect(
        g1Eq(p.parameters.g1.z[i], expectedZ[i]),
      ).toBe(true);
    }
  });

  it('should produce G1.PKK matching gnark after update', () => {
    const binaryBase64 = vectors.phase2_binary_before as string;
    const binary = Uint8Array.from(atob(binaryBase64), (c) =>
      c.charCodeAt(0),
    );
    const p = parsePhase2(binary);

    const delta = BigInt(vectors.phase2_after.delta_scalar);
    const sigmas = (vectors.phase2_after.sigma_scalars as string[]).map(
      (s: string) => BigInt(s),
    );

    phase2UpdateCPU(p, delta, sigmas);

    const expectedPKK = (vectors.phase2_after.g1_pkk as string[]).map(
      parseG1Hex,
    );
    expect(p.parameters.g1.pkk.length).toBe(expectedPKK.length);
    for (let i = 0; i < expectedPKK.length; i++) {
      expect(
        g1Eq(p.parameters.g1.pkk[i], expectedPKK[i]),
      ).toBe(true);
    }
  });

  it('should produce G2.Sigma matching gnark after update', () => {
    const binaryBase64 = vectors.phase2_binary_before as string;
    const binary = Uint8Array.from(atob(binaryBase64), (c) =>
      c.charCodeAt(0),
    );
    const p = parsePhase2(binary);

    const delta = BigInt(vectors.phase2_after.delta_scalar);
    const sigmas = (vectors.phase2_after.sigma_scalars as string[]).map(
      (s: string) => BigInt(s),
    );

    phase2UpdateCPU(p, delta, sigmas);

    const expectedSigma = (vectors.phase2_after.g2_sigma as string[]).map(
      parseG2Hex,
    );
    expect(p.parameters.g2.sigma.length).toBe(expectedSigma.length);
    for (let i = 0; i < expectedSigma.length; i++) {
      expect(
        g2Eq(p.parameters.g2.sigma[i], expectedSigma[i]),
      ).toBe(true);
    }
  });

  it('should handle SigmaCKK matching gnark after update', () => {
    const binaryBase64 = vectors.phase2_binary_before as string;
    const binary = Uint8Array.from(atob(binaryBase64), (c) =>
      c.charCodeAt(0),
    );
    const p = parsePhase2(binary);

    const delta = BigInt(vectors.phase2_after.delta_scalar);
    const sigmas = (vectors.phase2_after.sigma_scalars as string[]).map(
      (s: string) => BigInt(s),
    );

    phase2UpdateCPU(p, delta, sigmas);

    const expectedSigmaCKK = vectors.phase2_after.g1_sigma_ckk as string[][];
    expect(p.parameters.g1.sigmaCKK.length).toBe(expectedSigmaCKK.length);
    for (let i = 0; i < expectedSigmaCKK.length; i++) {
      const expected = expectedSigmaCKK[i].map(parseG1Hex);
      expect(p.parameters.g1.sigmaCKK[i].length).toBe(expected.length);
      for (let j = 0; j < expected.length; j++) {
        expect(
          g1Eq(p.parameters.g1.sigmaCKK[i][j], expected[j]),
        ).toBe(true);
      }
    }
  });
});
