/**
 * BN254 curve constants.
 *
 * Curve equation: y² = x³ + 3 over Fp
 * Embedding degree: 12
 */

/** Base field modulus (Fp) — 254 bits */
export const FP_MODULUS =
  21888242871839275222246405745257275088696311157297823662689037894645226208583n;

/** Scalar field modulus (Fr) — also the group order */
export const FR_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/** Curve coefficient b (y² = x³ + b) */
export const CURVE_B = 3n;

/** G1 generator in affine coordinates */
export const G1_GENERATOR_X = 1n;
export const G1_GENERATOR_Y = 2n;

/** G2 generator twist parameter: y² = x³ + b/ξ where ξ = 9 + u */
export const TWIST_B_C0 =
  19485874751759354771024239261021720505790618469301721065564631296452457478373n;
export const TWIST_B_C1 =
  266929791119991161246907387137283842545076965332900288569378510910307636690n;

/**
 * G2 generator coordinates (affine over Fp2).
 * Convention: element = c0 + c1·u where u² = −1.
 * Values from gnark-crypto: X.A0, X.A1, Y.A0, Y.A1.
 *
 * Note: gnark-crypto serializes G2 as A1|A0 (imaginary first), but
 * here we store as (c0=A0, c1=A1) in the natural algebraic order.
 */
export const G2_GENERATOR_X_C0 =
  10857046999023057135944570762232829481370756359578518086990519993285655852781n;
export const G2_GENERATOR_X_C1 =
  11559732032986387107991004021392285783925812861821192530917403151452391805634n;
export const G2_GENERATOR_Y_C0 =
  8495653923123431417604973247489272438418190587263600148770280649306958101930n;
export const G2_GENERATOR_Y_C1 =
  4082367875863433681332203403145435568316851327593401208105741076214120093531n;

/** Size constants (bytes) */
export const FP_BYTES = 32;
export const FR_BYTES = 32;
export const G1_UNCOMPRESSED_BYTES = 64;
export const G2_UNCOMPRESSED_BYTES = 128;

/** Size constants (u32 limbs) — for WebGPU buffers */
export const LIMBS_PER_FIELD = 8; // 32 bytes / 4 bytes per u32
export const LIMBS_PER_G1 = 16; // 2 fields × 8 limbs
