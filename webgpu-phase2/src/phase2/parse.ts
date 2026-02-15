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

import { FP_BYTES } from '../constants.js';
import { beFieldToBigInt } from '../bindings/endian.js';
import { fpSqrt, fp2Sqrt, fpLexLargest, fp2LexLargest } from '../crypto.js';
import { FP_MODULUS, CURVE_B } from '../constants.js';
import type {
  G1Affine,
  G2Affine,
  Fp2Element,
  UpdateProof,
  Phase2,
} from './types.js';

// gnark-crypto point sizes
const G1_COMPRESSED = 32;
const G1_UNCOMPRESSED = 64;
const G2_COMPRESSED = 64;
const G2_UNCOMPRESSED = 128;

// MSB flag bits for gnark-crypto point serialization
// The top 2 bits of the first byte encode the format:
//   0b00 = uncompressed (raw)
//   0b01 = compressed infinity
//   0b10 = compressed, smallest y
//   0b11 = compressed, largest y
const mUncompressed = 0x00;
const mCompressedSmallest = 0x80; // 0b10 << 6
const mCompressedLargest = 0xC0;  // 0b11 << 6
const mCompressedInfinity = 0x40; // 0b01 << 6
const mFlagMask = 0xC0;           // top 2 bits

// ===========================================================================
// Binary reader
// ===========================================================================

class BinaryReader {
  private offset = 0;

  constructor(private readonly data: Uint8Array) {}

  get position(): number {
    return this.offset;
  }

  get remaining(): number {
    return this.data.length - this.offset;
  }

  private ensureAvailable(n: number): void {
    if (this.remaining < n) {
      throw new Error(
        `Unexpected end of data at offset ${this.offset}: need ${n} bytes, have ${this.remaining}`,
      );
    }
  }

  readUint16(): number {
    this.ensureAvailable(2);
    const view = new DataView(
      this.data.buffer,
      this.data.byteOffset + this.offset,
      2,
    );
    this.offset += 2;
    return view.getUint16(0, false); // big-endian
  }

  readUint32(): number {
    this.ensureAvailable(4);
    const view = new DataView(
      this.data.buffer,
      this.data.byteOffset + this.offset,
      4,
    );
    this.offset += 4;
    return view.getUint32(0, false); // big-endian
  }

  readBytes(n: number): Uint8Array {
    this.ensureAvailable(n);
    const result = this.data.slice(this.offset, this.offset + n);
    this.offset += n;
    return result;
  }

  readFieldElement(): bigint {
    this.ensureAvailable(FP_BYTES);
    const value = beFieldToBigInt(this.data, this.offset);
    this.offset += FP_BYTES;
    return value;
  }

  /**
   * Read a G1 point (auto-detects compressed 32 bytes vs uncompressed 64 bytes).
   *
   * Format detection via MSB flag bits of first byte:
   *   0x00 = uncompressed (64 bytes: x BE | y BE)
   *   0x40 = compressed infinity (32 bytes)
   *   0x80 = compressed, smallest y (32 bytes)
   *   0xC0 = compressed, largest y (32 bytes)
   */
  readG1(): G1Affine {
    this.ensureAvailable(G1_COMPRESSED); // read at least 32 bytes
    const flags = this.data[this.offset] & mFlagMask;

    // ── Uncompressed (raw): 64 bytes ────────────────────────────────
    if (flags === mUncompressed) {
      this.ensureAvailable(G1_UNCOMPRESSED);
      const x = beFieldToBigInt(this.data, this.offset);
      const y = beFieldToBigInt(this.data, this.offset + FP_BYTES);
      this.offset += G1_UNCOMPRESSED;
      // Infinity is (0, 0) with no special flag in raw mode
      return { x, y };
    }

    // ── Compressed: 32 bytes ────────────────────────────────────────
    // Read x coordinate (clear flag bits from first byte)
    const xBytes = this.data.slice(this.offset, this.offset + FP_BYTES);
    xBytes[0] &= ~mFlagMask;
    const x = beFieldToBigInt(xBytes, 0);
    this.offset += G1_COMPRESSED;

    // Handle infinity
    if (flags === mCompressedInfinity) {
      return { x: 0n, y: 0n };
    }

    // Decompress: y² = x³ + 3
    const x3 = (x * x % FP_MODULUS) * x % FP_MODULUS;
    const rhs = (x3 + CURVE_B) % FP_MODULUS;
    let y = fpSqrt(rhs);

    // Choose correct y based on flag
    const yIsLargest = fpLexLargest(y);
    const wantLargest = flags === mCompressedLargest;
    if (yIsLargest !== wantLargest) {
      y = FP_MODULUS - y;
    }

    return { x, y };
  }

  /**
   * Read a G2 point (auto-detects compressed 64 bytes vs uncompressed 128 bytes).
   *
   * gnark-crypto G2 serialization order: X.A1 | X.A0 (imaginary first!)
   */
  readG2(): G2Affine {
    this.ensureAvailable(G2_COMPRESSED); // read at least 64 bytes
    const flags = this.data[this.offset] & mFlagMask;

    // ── Uncompressed (raw): 128 bytes ───────────────────────────────
    // Layout: X.A1(32) | X.A0(32) | Y.A1(32) | Y.A0(32)
    if (flags === mUncompressed) {
      this.ensureAvailable(G2_UNCOMPRESSED);
      const xA1 = beFieldToBigInt(this.data, this.offset);
      const xA0 = beFieldToBigInt(this.data, this.offset + FP_BYTES);
      const yA1 = beFieldToBigInt(this.data, this.offset + 2 * FP_BYTES);
      const yA0 = beFieldToBigInt(this.data, this.offset + 3 * FP_BYTES);
      this.offset += G2_UNCOMPRESSED;
      return {
        x: { c0: xA0, c1: xA1 },
        y: { c0: yA0, c1: yA1 },
      };
    }

    // ── Compressed: 64 bytes ────────────────────────────────────────
    const buf = this.data.slice(this.offset, this.offset + G2_COMPRESSED);
    buf[0] &= ~mFlagMask;
    const xA1 = beFieldToBigInt(buf, 0);
    const xA0 = beFieldToBigInt(buf, FP_BYTES);
    this.offset += G2_COMPRESSED;

    // Handle infinity
    if (flags === mCompressedInfinity) {
      return {
        x: { c0: 0n, c1: 0n },
        y: { c0: 0n, c1: 0n },
      };
    }

    // Decompress: y² = x³ + b' (twist curve)
    const xFp2: Fp2Element = { c0: xA0, c1: xA1 };
    const x2 = fp2SquareLocal(xFp2);
    const x3 = fp2MulLocal(x2, xFp2);
    const bTwist = getBTwist();
    const rhs = fp2AddLocal(x3, bTwist);
    let y = fp2Sqrt(rhs);

    // Choose correct y based on flag
    const yIsLargest = fp2LexLargest(y);
    const wantLargest = flags === mCompressedLargest;
    if (yIsLargest !== wantLargest) {
      y = { c0: y.c0 === 0n ? 0n : FP_MODULUS - y.c0, c1: y.c1 === 0n ? 0n : FP_MODULUS - y.c1 };
    }

    return {
      x: { c0: xA0, c1: xA1 },
      y: { c0: y.c0, c1: y.c1 },
    };
  }

  readG1Slice(): G1Affine[] {
    const count = this.readUint32();
    const result: G1Affine[] = new Array(count);
    for (let i = 0; i < count; i++) {
      result[i] = this.readG1();
    }
    return result;
  }

  readUpdateProof(): UpdateProof {
    return {
      contributionCommitment: this.readG1(),
      contributionPok: this.readG2(),
    };
  }

  /** Read a short byte slice: uint8 length prefix + data (gnark io.WriteBytesShort). */
  readBytesShort(): Uint8Array {
    this.ensureAvailable(1);
    const len = this.data[this.offset];
    this.offset += 1;
    if (len === 0) return new Uint8Array(0);
    return this.readBytes(len);
  }
}

// ===========================================================================
// Public API
// ===========================================================================

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
export function parsePhase2(data: Uint8Array): Phase2 {
  const reader = new BinaryReader(data);

  // 1. Number of commitments
  const nbCommitments = reader.readUint16();

  // 2. Parameters (refsSlice order)
  const g1Delta = reader.readG1();
  const g1PKK = reader.readG1Slice();
  const g1Z = reader.readG1Slice();
  const g2Delta = reader.readG2();

  const sigmaCKK: G1Affine[][] = new Array(nbCommitments);
  for (let i = 0; i < nbCommitments; i++) {
    sigmaCKK[i] = reader.readG1Slice();
  }

  const g2Sigma: G2Affine[] = new Array(nbCommitments);
  for (let i = 0; i < nbCommitments; i++) {
    g2Sigma[i] = reader.readG2();
  }

  // 3. Proofs (always compressed — only a few points)
  const deltaProof = reader.readUpdateProof();
  const sigmaProofs: UpdateProof[] = new Array(nbCommitments);
  for (let i = 0; i < nbCommitments; i++) {
    sigmaProofs[i] = reader.readUpdateProof();
  }

  // 4. Challenge
  const challenge = reader.readBytesShort();

  return {
    parameters: {
      g1: {
        delta: g1Delta,
        z: g1Z,
        pkk: g1PKK,
        sigmaCKK,
      },
      g2: {
        delta: g2Delta,
        sigma: g2Sigma,
      },
    },
    delta: deltaProof,
    sigmas: sigmaProofs,
    challenge,
  };
}

// ===========================================================================
// Local Fp2 helpers (avoid circular imports with crypto.ts)
// ===========================================================================

function fpMod(a: bigint): bigint {
  return ((a % FP_MODULUS) + FP_MODULUS) % FP_MODULUS;
}

function fp2AddLocal(a: Fp2Element, b: Fp2Element): Fp2Element {
  return {
    c0: (a.c0 + b.c0) % FP_MODULUS,
    c1: (a.c1 + b.c1) % FP_MODULUS,
  };
}

function fp2MulLocal(a: Fp2Element, b: Fp2Element): Fp2Element {
  const t0 = a.c0 * b.c0 % FP_MODULUS;
  const t1 = a.c1 * b.c1 % FP_MODULUS;
  const sum_a = (a.c0 + a.c1) % FP_MODULUS;
  const sum_b = (b.c0 + b.c1) % FP_MODULUS;
  return {
    c0: fpMod(t0 - t1),
    c1: fpMod(sum_a * sum_b % FP_MODULUS - t0 - t1),
  };
}

function fp2SquareLocal(a: Fp2Element): Fp2Element {
  return fp2MulLocal(a, a);
}

/**
 * Get the BN254 twist constant b' = b/ξ where ξ = 9 + u.
 * Precomputed: 3 / (9 + u) in Fp2.
 */
let _bTwist: Fp2Element | null = null;
function getBTwist(): Fp2Element {
  if (_bTwist) return _bTwist;
  // b' = 3 / (9+u) = 3(9-u) / (81+1) = 3(9-u) / 82
  // = (27/82) + (-3/82)*u
  function modPow(base: bigint, exp: bigint, m: bigint): bigint {
    let r = 1n;
    base = ((base % m) + m) % m;
    while (exp > 0n) {
      if (exp & 1n) r = (r * base) % m;
      exp >>= 1n;
      base = (base * base) % m;
    }
    return r;
  }
  const inv82 = modPow(82n, FP_MODULUS - 2n, FP_MODULUS);
  _bTwist = {
    c0: (27n * inv82) % FP_MODULUS,
    c1: fpMod(-3n * inv82),
  };
  return _bTwist;
}
