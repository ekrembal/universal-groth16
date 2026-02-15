//! Orchestrator that generates test data, produces proof artifacts from both
//! RISC0 and SP1, and exports everything for the Go pipeline.
//!
//! This is a lightweight coordinator — actual proving is done by running the
//! RISC0 and SP1 hosts separately. This tool generates test data and the
//! verification export file.
//!
//! Usage:
//!   cargo run -- --num-pairs 10 --output-dir ./proofs

use clap::Parser;
use verenc_bridge::{create_verification_data, ExportedProofs, Risc0Export, Sp1Export};
use verenc_common::generate_test_pairs;

#[derive(Parser, Debug)]
#[command(author, version, about = "Verifiable encryption orchestrator")]
struct Args {
    /// Number of pairs to encrypt.
    #[arg(long, default_value = "10")]
    num_pairs: usize,

    /// Output directory for proof artifacts.
    #[arg(long, default_value = "./proofs")]
    output_dir: String,

    /// RISC0 image ID (hex). Set after running risc0 host.
    #[arg(long, default_value = "")]
    risc0_image_id: String,

    /// SP1 vkey hash. Set after running sp1 host.
    #[arg(long, default_value = "")]
    sp1_vkey_hash: String,

    /// Path to RISC0 seal.bin (set after running risc0 --prove-groth16).
    #[arg(long, default_value = "")]
    risc0_seal: String,

    /// Path to RISC0 journal.bin.
    #[arg(long, default_value = "")]
    risc0_journal: String,

    /// Path to RISC0 claim.bin.
    #[arg(long, default_value = "")]
    risc0_claim: String,

    /// Path to SP1 proof.bin.
    #[arg(long, default_value = "")]
    sp1_proof: String,
}

fn main() {
    let args = Args::parse();

    // Generate test pairs.
    let pairs = generate_test_pairs(args.num_pairs);
    println!("Generated {} pairs", args.num_pairs);

    // Compute accumulator and verification data.
    let (acc, vdata) = create_verification_data(&pairs);
    println!("Accumulator: 0x{}", hex::encode(acc));

    // Read proof artifacts if provided.
    let risc0_seal_hex = if !args.risc0_seal.is_empty() {
        let data = std::fs::read(&args.risc0_seal).expect("failed to read risc0 seal");
        hex::encode(&data)
    } else {
        String::new()
    };

    let risc0_journal_hex = if !args.risc0_journal.is_empty() {
        let data = std::fs::read(&args.risc0_journal).expect("failed to read risc0 journal");
        hex::encode(&data)
    } else {
        String::new()
    };

    let risc0_claim_hex = if !args.risc0_claim.is_empty() {
        let data = std::fs::read(&args.risc0_claim).expect("failed to read risc0 claim");
        hex::encode(&data)
    } else {
        String::new()
    };

    let sp1_proof_hex = if !args.sp1_proof.is_empty() {
        let data = std::fs::read(&args.sp1_proof).expect("failed to read sp1 proof");
        hex::encode(&data)
    } else {
        String::new()
    };

    let export = ExportedProofs {
        num_pairs: args.num_pairs,
        accumulator_hash: hex::encode(acc),
        risc0: Risc0Export {
            image_id: args.risc0_image_id,
            seal_hex: risc0_seal_hex,
            journal_hex: risc0_journal_hex,
            claim_hex: risc0_claim_hex,
        },
        sp1: Sp1Export {
            vkey_hash: args.sp1_vkey_hash,
            proof_hex: sp1_proof_hex,
        },
        verification_data: vdata,
    };

    // Write export file.
    std::fs::create_dir_all(&args.output_dir).unwrap();
    let path = format!("{}/export.json", args.output_dir);
    let json = serde_json::to_string_pretty(&export).unwrap();
    std::fs::write(&path, &json).unwrap();
    println!("Export written to {} ({} bytes)", path, json.len());

    // Also export pairs for reference.
    let pairs_json = serde_json::to_string_pretty(&pairs).unwrap();
    std::fs::write(format!("{}/pairs.json", args.output_dir), &pairs_json).unwrap();
    println!("Pairs written to {}/pairs.json", args.output_dir);
}
