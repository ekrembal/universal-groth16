//! Verification function for the verifiable encryption pipeline.
//!
//! Given the final Groth16 proof and raw input data, the verifier:
//! 1. Recomputes the accumulator hash from (a_i, h(b_i), c_i)
//! 2. Verifies the Groth16 proof against the expected public inputs
//!
//! Note: The Groth16 proof verification itself requires a BN254 verifier.
//! For Rust, this uses the groth16 verification from the arkworks or
//! sp1-verifier crate. For Go, gnark's native verifier is used.

use verenc_common::{recompute_accumulator, Element};

/// Verify that a set of raw inputs produces the expected accumulator hash.
///
/// This is the "off-chain" verification that doesn't require a Groth16 verifier.
/// It checks that the claimed `(a_i, h(b_i), c_i)` values produce the given
/// accumulator hash.
///
/// Returns `true` if the accumulator matches.
pub fn verify_accumulator(
    a_values: &[Element],
    hb_values: &[Element],
    c_values: &[Element],
    expected_accumulator: &Element,
) -> bool {
    let computed = recompute_accumulator(a_values, hb_values, c_values);
    computed == *expected_accumulator
}

/// Verify consistency: for each triple, check that c_i could be a_i XOR something
/// whose hash is hb_i. This doesn't reveal b_i but checks structural correctness.
///
/// Specifically, we verify:
/// - All arrays have the same length
/// - The accumulator recomputes correctly
///
/// Note: We CANNOT verify c_i = a_i XOR b_i without knowing b_i.
/// The h(b_i) commitment prevents us from recovering b_i.
/// This is by design — the verifier learns the encryption but not the plaintext.
pub fn verify_full(
    a_values: &[Element],
    hb_values: &[Element],
    c_values: &[Element],
    expected_accumulator: &Element,
) -> Result<(), VerifyError> {
    if a_values.len() != hb_values.len() || a_values.len() != c_values.len() {
        return Err(VerifyError::LengthMismatch);
    }
    if a_values.is_empty() {
        return Err(VerifyError::EmptyInput);
    }

    let computed = recompute_accumulator(a_values, hb_values, c_values);
    if computed != *expected_accumulator {
        return Err(VerifyError::AccumulatorMismatch {
            expected: hex::encode(expected_accumulator),
            computed: hex::encode(computed),
        });
    }

    Ok(())
}

/// Parse hex-encoded elements from the bridge export format.
pub fn parse_elements(hex_strings: &[String]) -> Result<Vec<Element>, VerifyError> {
    hex_strings
        .iter()
        .map(|s| {
            let bytes = hex::decode(s).map_err(|_| VerifyError::InvalidHex(s.clone()))?;
            if bytes.len() != 32 {
                return Err(VerifyError::InvalidElementSize(bytes.len()));
            }
            let mut elem = [0u8; 32];
            elem.copy_from_slice(&bytes);
            Ok(elem)
        })
        .collect()
}

#[derive(Debug)]
pub enum VerifyError {
    LengthMismatch,
    EmptyInput,
    AccumulatorMismatch { expected: String, computed: String },
    InvalidHex(String),
    InvalidElementSize(usize),
    Groth16VerifyFailed(String),
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LengthMismatch => write!(f, "input array lengths do not match"),
            Self::EmptyInput => write!(f, "input arrays are empty"),
            Self::AccumulatorMismatch { expected, computed } => {
                write!(f, "accumulator mismatch: expected={}, computed={}", expected, computed)
            }
            Self::InvalidHex(s) => write!(f, "invalid hex: {}", s),
            Self::InvalidElementSize(n) => write!(f, "invalid element size: {} (expected 32)", n),
            Self::Groth16VerifyFailed(msg) => write!(f, "groth16 verification failed: {}", msg),
        }
    }
}

impl std::error::Error for VerifyError {}
