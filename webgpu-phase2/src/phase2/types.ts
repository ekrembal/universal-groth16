/**
 * Type definitions for Phase 2 Trusted Setup Ceremony data structures.
 *
 * These mirror gnark's bn254/mpcsetup.Phase2 struct and related types.
 */

/** G1 affine point: (x, y) over Fp, each coordinate a 254-bit field element. */
export interface G1Affine {
  x: bigint;
  y: bigint;
}

/** Fp2 element: a + b·i where i² = −1. */
export interface Fp2Element {
  c0: bigint; // real part
  c1: bigint; // imaginary part
}

/** G2 affine point: (x, y) over Fp2. */
export interface G2Affine {
  x: Fp2Element;
  y: Fp2Element;
}

/**
 * Update proof for a Phase 2 contribution.
 *
 * Proves knowledge of the scalar used to update the parameters.
 * - contributionCommitment = [x]₁  (x·G1)
 * - contributionPok = x·R ∈ G2     (proof of knowledge)
 */
export interface UpdateProof {
  contributionCommitment: G1Affine;
  contributionPok: G2Affine;
}

/**
 * Phase 2 parameters — the SRS components that get updated per contribution.
 */
export interface Phase2Parameters {
  g1: {
    /** G1 delta point */
    delta: G1Affine;
    /** Private witness coefficients (denominator δ) */
    pkk: G1Affine[];
    /** Vanishing polynomial coefficients: xⁱ·t(x)/δ for 0 ≤ i ≤ N−2 */
    z: G1Affine[];
    /** Commitment proof bases: σᵢ·Cᵢⱼ per commitment */
    sigmaCKK: G1Affine[][];
  };
  g2: {
    /** G2 delta point */
    delta: G2Affine;
    /** Secret σ values for each commitment */
    sigma: G2Affine[];
  };
}

/**
 * Full Phase 2 state, matching gnark's mpcsetup.Phase2 serialization.
 */
export interface Phase2 {
  parameters: Phase2Parameters;
  /** Proof of delta update correctness */
  delta: UpdateProof;
  /** Proofs of sigma update correctness (one per commitment) */
  sigmas: UpdateProof[];
  /** SHA-256 hash of the previous contribution */
  challenge: Uint8Array;
}

/**
 * A zero (infinity) G1 point — used as identity element.
 */
export const G1_INFINITY: G1Affine = { x: 0n, y: 0n };

/**
 * A zero (infinity) G2 point — used as identity element.
 */
export const G2_INFINITY: G2Affine = {
  x: { c0: 0n, c1: 0n },
  y: { c0: 0n, c1: 0n },
};
