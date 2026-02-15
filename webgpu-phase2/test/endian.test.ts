/**
 * Tests for endian conversion utilities.
 */

import { describe, it, expect } from 'vitest';
import {
  beFieldToBigInt,
  bigIntToBeField,
  bigIntToU32Array,
  u32ArrayToBigInt,
  beBytesToU32,
  u32ToBeBytes,
  gnarkG1ToU32,
  u32ToGnarkG1,
} from '../src/bindings/endian.js';

describe('beFieldToBigInt / bigIntToBeField', () => {
  it('should round-trip zero', () => {
    const bytes = new Uint8Array(32);
    expect(beFieldToBigInt(bytes)).toBe(0n);
    const out = new Uint8Array(32);
    bigIntToBeField(0n, out);
    expect(out).toEqual(bytes);
  });

  it('should round-trip one', () => {
    const bytes = new Uint8Array(32);
    bytes[31] = 1;
    expect(beFieldToBigInt(bytes)).toBe(1n);
    const out = new Uint8Array(32);
    bigIntToBeField(1n, out);
    expect(out).toEqual(bytes);
  });

  it('should round-trip two', () => {
    const bytes = new Uint8Array(32);
    bytes[31] = 2;
    expect(beFieldToBigInt(bytes)).toBe(2n);
    const out = new Uint8Array(32);
    bigIntToBeField(2n, out);
    expect(out).toEqual(bytes);
  });

  it('should round-trip a large value', () => {
    const value = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
    const out = new Uint8Array(32);
    bigIntToBeField(value, out);
    expect(beFieldToBigInt(out)).toBe(value);
  });

  it('should parse G1 generator x-coordinate', () => {
    // G1 generator: x=1, y=2
    const bytes = new Uint8Array(32);
    bytes[31] = 1;
    expect(beFieldToBigInt(bytes)).toBe(1n);
  });
});

describe('bigIntToU32Array / u32ArrayToBigInt', () => {
  it('should round-trip zero', () => {
    const limbs = bigIntToU32Array(0n);
    expect(limbs.length).toBe(8);
    expect(u32ArrayToBigInt(limbs)).toBe(0n);
  });

  it('should round-trip one', () => {
    const limbs = bigIntToU32Array(1n);
    expect(limbs[7]).toBe(1);
    expect(limbs[0]).toBe(0);
    expect(u32ArrayToBigInt(limbs)).toBe(1n);
  });

  it('should round-trip a large value', () => {
    const value = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
    const limbs = bigIntToU32Array(value);
    expect(u32ArrayToBigInt(limbs)).toBe(value);
  });
});

describe('beBytesToU32 / u32ToBeBytes', () => {
  it('should convert BE bytes to u32 limbs and back', () => {
    // Value "1" in 32 BE bytes
    const bytes = new Uint8Array(32);
    bytes[31] = 1;

    const limbs = beBytesToU32(bytes);
    expect(limbs[7]).toBe(1);
    expect(limbs[0]).toBe(0);

    const out = new Uint8Array(32);
    u32ToBeBytes(limbs, 0, out, 0);
    expect(out).toEqual(bytes);
  });

  it('should handle multi-byte values', () => {
    const bytes = new Uint8Array(32);
    bytes[28] = 0x12;
    bytes[29] = 0x34;
    bytes[30] = 0x56;
    bytes[31] = 0x78;

    const limbs = beBytesToU32(bytes);
    expect(limbs[7]).toBe(0x12345678);

    const out = new Uint8Array(32);
    u32ToBeBytes(limbs, 0, out, 0);
    expect(out).toEqual(bytes);
  });
});

describe('gnarkG1ToU32 / u32ToGnarkG1', () => {
  it('should round-trip G1 generator', () => {
    // G1 = (1, 2) as 64 BE bytes
    const g1Bytes = new Uint8Array(64);
    g1Bytes[31] = 1; // x = 1
    g1Bytes[63] = 2; // y = 2

    const limbs = gnarkG1ToU32(g1Bytes);
    expect(limbs.length).toBe(16);
    expect(limbs[7]).toBe(1);  // x = 1 (last u32)
    expect(limbs[15]).toBe(2); // y = 2 (last u32)

    const back = u32ToGnarkG1(limbs);
    expect(back).toEqual(g1Bytes);
  });
});
