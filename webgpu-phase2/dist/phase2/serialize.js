/**
 * Serialize Phase2 back to gnark binary format.
 *
 * Produces bytes compatible with gnark's Phase2.ReadFrom().
 */
import { FP_BYTES } from '../constants.js';
import { bigIntToBeField } from '../bindings/endian.js';
import { fpLexLargest, fp2LexLargest } from '../crypto.js';
// Point sizes
const G1_COMPRESSED = 32;
const G1_UNCOMPRESSED = 64;
const G2_COMPRESSED = 64;
const G2_UNCOMPRESSED = 128;
// MSB flag bits
const mCompressedSmallest = 0x80; // 0b10 << 6
const mCompressedLargest = 0xC0; // 0b11 << 6
const mCompressedInfinity = 0x40; // 0b01 << 6
// ===========================================================================
// Binary writer
// ===========================================================================
class BinaryWriter {
    chunks = [];
    totalSize = 0;
    writeUint16(value) {
        const buf = new Uint8Array(2);
        new DataView(buf.buffer).setUint16(0, value, false);
        this.append(buf);
    }
    writeUint32(value) {
        const buf = new Uint8Array(4);
        new DataView(buf.buffer).setUint32(0, value, false);
        this.append(buf);
    }
    writeBytes(data) {
        this.append(data);
    }
    /** Write compressed G1 point (32 bytes). */
    writeG1(point) {
        const buf = new Uint8Array(G1_COMPRESSED);
        if (point.x === 0n && point.y === 0n) {
            buf[0] = mCompressedInfinity;
            this.append(buf);
            return;
        }
        bigIntToBeField(point.x, buf, 0);
        buf[0] |= fpLexLargest(point.y) ? mCompressedLargest : mCompressedSmallest;
        this.append(buf);
    }
    /**
     * Write compressed G2 point (64 bytes).
     * gnark-crypto order: X.A1 | X.A0 (imaginary first!)
     */
    writeG2(point) {
        const buf = new Uint8Array(G2_COMPRESSED);
        if (point.x.c0 === 0n && point.x.c1 === 0n && point.y.c0 === 0n && point.y.c1 === 0n) {
            buf[0] = mCompressedInfinity;
            this.append(buf);
            return;
        }
        // Write X.A1 (c1/imaginary) first, then X.A0 (c0/real)
        bigIntToBeField(point.x.c1, buf, 0);
        bigIntToBeField(point.x.c0, buf, FP_BYTES);
        buf[0] |= fp2LexLargest(point.y) ? mCompressedLargest : mCompressedSmallest;
        this.append(buf);
    }
    /** Write uncompressed (raw) G1 point (64 bytes: x BE | y BE). */
    writeG1Raw(point) {
        const buf = new Uint8Array(G1_UNCOMPRESSED);
        bigIntToBeField(point.x, buf, 0);
        bigIntToBeField(point.y, buf, FP_BYTES);
        this.append(buf);
    }
    /** Write uncompressed (raw) G2 point (128 bytes: X.A1 | X.A0 | Y.A1 | Y.A0). */
    writeG2Raw(point) {
        const buf = new Uint8Array(G2_UNCOMPRESSED);
        bigIntToBeField(point.x.c1, buf, 0); // A1 (imaginary)
        bigIntToBeField(point.x.c0, buf, FP_BYTES); // A0 (real)
        bigIntToBeField(point.y.c1, buf, 2 * FP_BYTES); // A1 (imaginary)
        bigIntToBeField(point.y.c0, buf, 3 * FP_BYTES); // A0 (real)
        this.append(buf);
    }
    writeG1Slice(points) {
        this.writeUint32(points.length);
        for (const p of points) {
            this.writeG1(p);
        }
    }
    writeG1SliceRaw(points) {
        this.writeUint32(points.length);
        for (const p of points) {
            this.writeG1Raw(p);
        }
    }
    writeUpdateProof(proof) {
        this.writeG1(proof.contributionCommitment);
        this.writeG2(proof.contributionPok);
    }
    /** Write a short byte slice: uint8 length prefix + data (gnark io.WriteBytesShort). */
    writeBytesShort(data) {
        if (data.length > 255) {
            throw new Error(`WriteBytesShort: data too long (${data.length} > 255)`);
        }
        const lenBuf = new Uint8Array(1);
        lenBuf[0] = data.length;
        this.append(lenBuf);
        if (data.length > 0) {
            this.append(data);
        }
    }
    finish() {
        const result = new Uint8Array(this.totalSize);
        let offset = 0;
        for (const chunk of this.chunks) {
            result.set(chunk, offset);
            offset += chunk.length;
        }
        return result;
    }
    append(data) {
        this.chunks.push(data);
        this.totalSize += data.length;
    }
}
// ===========================================================================
// Public API
// ===========================================================================
/**
 * Serialize a Phase2 object to gnark-compatible binary format.
 *
 * The output can be read by gnark's Phase2.ReadFrom().
 *
 * @param p the Phase2 state to serialize
 * @returns raw bytes
 */
export function serializePhase2(p) {
    const writer = new BinaryWriter();
    const nbCommitments = p.parameters.g2.sigma.length;
    // 1. Number of commitments
    writer.writeUint16(nbCommitments);
    // 2. Parameters (refsSlice order)
    writer.writeG1(p.parameters.g1.delta);
    writer.writeG1Slice(p.parameters.g1.pkk);
    writer.writeG1Slice(p.parameters.g1.z);
    writer.writeG2(p.parameters.g2.delta);
    for (let i = 0; i < nbCommitments; i++) {
        writer.writeG1Slice(p.parameters.g1.sigmaCKK[i]);
    }
    for (let i = 0; i < nbCommitments; i++) {
        writer.writeG2(p.parameters.g2.sigma[i]);
    }
    // 3. Proofs
    writer.writeUpdateProof(p.delta);
    for (let i = 0; i < nbCommitments; i++) {
        writer.writeUpdateProof(p.sigmas[i]);
    }
    // 4. Challenge
    writer.writeBytesShort(p.challenge);
    return writer.finish();
}
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
export function serializePhase2Raw(p) {
    const writer = new BinaryWriter();
    const nbCommitments = p.parameters.g2.sigma.length;
    // 1. Number of commitments
    writer.writeUint16(nbCommitments);
    // 2. Parameters — uncompressed (raw)
    writer.writeG1Raw(p.parameters.g1.delta);
    writer.writeG1SliceRaw(p.parameters.g1.pkk);
    writer.writeG1SliceRaw(p.parameters.g1.z);
    writer.writeG2Raw(p.parameters.g2.delta);
    for (let i = 0; i < nbCommitments; i++) {
        writer.writeG1SliceRaw(p.parameters.g1.sigmaCKK[i]);
    }
    for (let i = 0; i < nbCommitments; i++) {
        writer.writeG2Raw(p.parameters.g2.sigma[i]);
    }
    // 3. Proofs — compressed (only a few points, fast)
    writer.writeUpdateProof(p.delta);
    for (let i = 0; i < nbCommitments; i++) {
        writer.writeUpdateProof(p.sigmas[i]);
    }
    // 4. Challenge
    writer.writeBytesShort(p.challenge);
    return writer.finish();
}
//# sourceMappingURL=serialize.js.map