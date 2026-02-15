//! Bridge module for exporting proof artifacts in a format readable by
//! the Go gnark pipeline.
//!
//! # Formats
//!
//! ## RISC0 Groth16
//! The RISC0 Groth16 seal is exported as a JSON file with hex-encoded
//! BN254 curve points (uncompressed). The Go side parses these and
//! constructs gnark `groth16.Proof` and `groth16.VerifyingKey` objects.
//!
//! ## SP1 PlonK
//! SP1 uses gnark internally, so the PlonK proof is already in gnark's
//! binary format. We extract the raw bytes from SP1's proof structure.

use serde::{Deserialize, Serialize};
use verenc_common::Element;

/// Exported proof bundle — everything the Go pipeline needs.
#[derive(Serialize, Deserialize)]
pub struct ExportedProofs {
    /// Number of pairs proven.
    pub num_pairs: usize,
    /// The accumulator hash (expected public output).
    pub accumulator_hash: String,
    /// RISC0 artifacts.
    pub risc0: Risc0Export,
    /// SP1 artifacts.
    pub sp1: Sp1Export,
    /// Raw input data for the verifier.
    pub verification_data: VerificationData,
}

/// RISC0 Groth16 proof export.
#[derive(Serialize, Deserialize)]
pub struct Risc0Export {
    /// RISC0 image ID (method ID), hex-encoded.
    pub image_id: String,
    /// Groth16 seal bytes, hex-encoded.
    pub seal_hex: String,
    /// Journal bytes (public output), hex-encoded.
    pub journal_hex: String,
    /// Claim digest, hex-encoded.
    pub claim_hex: String,
}

/// SP1 PlonK proof export.
#[derive(Serialize, Deserialize)]
pub struct Sp1Export {
    /// SP1 vkey hash (method ID).
    pub vkey_hash: String,
    /// Full serialized proof (bincode of SP1ProofWithPublicValues), hex-encoded.
    pub proof_hex: String,
}

/// Raw data for the verification function.
#[derive(Serialize, Deserialize)]
pub struct VerificationData {
    /// a_i values, hex-encoded.
    pub a_values: Vec<String>,
    /// h(b_i) values, hex-encoded.
    pub hb_values: Vec<String>,
    /// c_i values, hex-encoded.
    pub c_values: Vec<String>,
}

/// Create verification data from pairs.
pub fn create_verification_data(
    pairs: &[verenc_common::Pair],
) -> (Element, VerificationData) {
    let (acc, cs, hbs) = verenc_common::accumulate(pairs);

    let a_values: Vec<String> = pairs.iter().map(|p| hex::encode(p.a)).collect();
    let hb_values: Vec<String> = hbs.iter().map(|h| hex::encode(h)).collect();
    let c_values: Vec<String> = cs.iter().map(|c| hex::encode(c)).collect();

    (acc, VerificationData {
        a_values,
        hb_values,
        c_values,
    })
}
