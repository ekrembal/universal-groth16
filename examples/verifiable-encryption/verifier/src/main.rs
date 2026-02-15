//! CLI verifier for the verifiable encryption pipeline.
//!
//! Usage:
//!   cargo run -- --proofs-json ./proofs/export.json

use std::fs;
use verenc_bridge::ExportedProofs;
use verenc_verifier::{parse_elements, verify_full};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let path = args.get(1).expect("Usage: verenc-verifier <proofs.json>");

    println!("Loading proofs from: {}", path);
    let data = fs::read_to_string(path).expect("failed to read file");
    let proofs: ExportedProofs = serde_json::from_str(&data).expect("failed to parse JSON");

    println!("Pairs: {}", proofs.num_pairs);
    println!("Expected accumulator: 0x{}", proofs.accumulator_hash);

    // Parse verification data.
    let a_values = parse_elements(&proofs.verification_data.a_values)
        .expect("failed to parse a values");
    let hb_values = parse_elements(&proofs.verification_data.hb_values)
        .expect("failed to parse hb values");
    let c_values = parse_elements(&proofs.verification_data.c_values)
        .expect("failed to parse c values");

    // Parse expected accumulator.
    let acc_bytes = hex::decode(&proofs.accumulator_hash).expect("invalid accumulator hex");
    let mut expected_acc = [0u8; 32];
    expected_acc.copy_from_slice(&acc_bytes);

    // Verify accumulator.
    match verify_full(&a_values, &hb_values, &c_values, &expected_acc) {
        Ok(()) => println!("Accumulator hash verification: PASSED"),
        Err(e) => {
            eprintln!("Accumulator hash verification: FAILED - {}", e);
            std::process::exit(1);
        }
    }

    // Print method IDs.
    println!("\nRISC0 Image ID: 0x{}", proofs.risc0.image_id);
    println!("SP1 VKey Hash: {}", proofs.sp1.vkey_hash);

    println!("\nVerification complete.");
    println!("The accumulator hash matches the raw inputs.");
    println!("Groth16 proof verification requires the Go pipeline.");
}
