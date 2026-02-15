//! RISC0 host for verifiable encryption.
//!
//! Usage:
//!   RUST_LOG=info cargo run --release -- --execute         # execute only
//!   RUST_LOG=info cargo run --release -- --prove           # STARK proof
//!   RUST_LOG=info cargo run --release -- --prove-groth16   # full Groth16 proof

use clap::Parser;
use methods::{VERENC_GUEST_ELF, VERENC_GUEST_ID};
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts};
use std::time::Instant;
use verenc_common::{generate_test_pairs, VerencOutput};

#[derive(Parser, Debug)]
#[command(author, version, about = "Verifiable encryption RISC0 prover")]
struct Args {
    #[arg(long)]
    execute: bool,

    #[arg(long)]
    prove: bool,

    #[arg(long)]
    prove_groth16: bool,

    /// Generate succinct proof and export seal + witness for PlonK pipeline.
    #[arg(long)]
    export_seal: bool,

    /// Number of pairs to encrypt.
    #[arg(long, default_value = "10")]
    num_pairs: usize,

    /// Directory to export proof artifacts.
    #[arg(long, default_value = "./proofs/risc0")]
    output_dir: String,
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();

    // Generate deterministic test pairs.
    let pairs = generate_test_pairs(args.num_pairs);
    println!("Generated {} pairs", pairs.len());

    // Compute expected output natively.
    let (expected_acc, _cs, _hbs) = verenc_common::accumulate(&pairs);
    println!("Expected accumulator: 0x{}", hex::encode(expected_acc));

    // Print image ID (method ID).
    println!("RISC0 Image ID: 0x{}", hex::encode(
        VERENC_GUEST_ID.iter()
            .flat_map(|w| w.to_le_bytes())
            .collect::<Vec<u8>>()
    ));

    // Build executor environment with the pairs as input.
    let env = ExecutorEnv::builder()
        .write(&pairs)
        .unwrap()
        .build()
        .unwrap();

    let prover = default_prover();

    if args.execute {
        println!("\n=== Executing (no proof) ===");
        let t = Instant::now();
        let prove_info = prover.prove(env, VERENC_GUEST_ELF).unwrap();
        let elapsed = t.elapsed();
        let receipt = prove_info.receipt;
        let output: VerencOutput = receipt.journal.decode().unwrap();
        println!("Execution + proof time: {:.2?}", elapsed);
        println!("Accumulator: 0x{}", hex::encode(output.accumulator));
        assert_eq!(output.accumulator, expected_acc, "accumulator mismatch!");
        receipt.verify(VERENC_GUEST_ID).unwrap();
        println!("Receipt verified!");
        return;
    }

    if args.prove {
        println!("\n=== Generating STARK proof (succinct) ===");
        let t = Instant::now();
        let prove_info = prover
            .prove_with_opts(env, VERENC_GUEST_ELF, &ProverOpts::succinct())
            .unwrap();
        let elapsed = t.elapsed();
        let receipt = prove_info.receipt;
        println!("STARK proof time: {:.2?}", elapsed);

        let output: VerencOutput = receipt.journal.decode().unwrap();
        println!("Accumulator: 0x{}", hex::encode(output.accumulator));
        assert_eq!(output.accumulator, expected_acc, "accumulator mismatch!");
        receipt.verify(VERENC_GUEST_ID).unwrap();
        println!("STARK proof verified!");
    } else if args.export_seal {
        println!("\n=== Generating succinct proof and exporting seal for PlonK pipeline ===");
        let t = Instant::now();
        let prove_info = prover
            .prove_with_opts(env, VERENC_GUEST_ELF, &ProverOpts::succinct())
            .unwrap();
        let elapsed = t.elapsed();
        let receipt = prove_info.receipt;
        println!("Succinct proof time: {:.2?}", elapsed);

        let output: VerencOutput = receipt.journal.decode().unwrap();
        println!("Accumulator: 0x{}", hex::encode(output.accumulator));
        assert_eq!(output.accumulator, expected_acc, "accumulator mismatch!");
        receipt.verify(VERENC_GUEST_ID).unwrap();
        println!("Succinct proof verified!");

        // Export artifacts for the PlonK pipeline.
        std::fs::create_dir_all(&args.output_dir).unwrap();

        // Export the succinct receipt seal (raw bytes).
        if let risc0_zkvm::InnerReceipt::Succinct(ref succinct) = receipt.inner {
            let seal_bytes: Vec<u8> = succinct.seal.iter()
                .flat_map(|w| w.to_le_bytes())
                .collect();
            std::fs::write(format!("{}/seal.bin", args.output_dir), &seal_bytes).unwrap();
            println!("Seal exported ({} bytes, {} u32 words)", seal_bytes.len(), succinct.seal.len());

            // Also export the seal as JSON using RISC0's format.
            // This is the format expected by the Circom witness generator.
            let seal_json = risc0_groth16::prove::to_json(&seal_bytes).unwrap();
            std::fs::write(format!("{}/seal_input.json", args.output_dir), &seal_json).unwrap();
            println!("Seal JSON exported for witness generator");
        } else {
            eprintln!("Expected succinct receipt, got {:?}", receipt.inner);
            std::process::exit(1);
        }

        // Export the journal.
        std::fs::write(format!("{}/journal.bin", args.output_dir), receipt.journal.bytes.as_slice()).unwrap();

        // Export image ID.
        let image_id_hex = hex::encode(
            VERENC_GUEST_ID.iter()
                .flat_map(|w| w.to_le_bytes())
                .collect::<Vec<u8>>()
        );
        std::fs::write(format!("{}/image_id.txt", args.output_dir), &image_id_hex).unwrap();
        println!("Image ID: 0x{}", image_id_hex);

        // Export public outputs for gnark.
        let pub_outputs: Vec<String> = vec![
            format!("0x{}", hex::encode(output.accumulator)),
        ];
        let pub_json = serde_json::to_string_pretty(&pub_outputs).unwrap();
        std::fs::write(format!("{}/public_outputs.json", args.output_dir), &pub_json).unwrap();
        println!("Public outputs exported");

        println!("\nTo generate the Circom witness, run:");
        println!("  circom-witnesscalc <graph.bin> <seal_input.json> <output.wtns>");
        println!("Or use the witness generation pipeline in the Go code.");
    } else if args.prove_groth16 {
        println!("\n=== Generating Groth16 proof (RISC0 standard flow) ===");
        let t = Instant::now();
        let prove_info = prover
            .prove_with_opts(env, VERENC_GUEST_ELF, &ProverOpts::groth16())
            .unwrap();
        let elapsed = t.elapsed();
        let receipt = prove_info.receipt;
        println!("Groth16 proof time: {:.2?}", elapsed);

        let output: VerencOutput = receipt.journal.decode().unwrap();
        println!("Accumulator: 0x{}", hex::encode(output.accumulator));
        assert_eq!(output.accumulator, expected_acc, "accumulator mismatch!");
        receipt.verify(VERENC_GUEST_ID).unwrap();
        println!("Groth16 proof verified!");

        // Export proof artifacts.
        std::fs::create_dir_all(&args.output_dir).unwrap();

        // Serialize the receipt.
        let receipt_bytes = bincode::serialize(&receipt).unwrap();
        std::fs::write(format!("{}/receipt.bin", args.output_dir), &receipt_bytes).unwrap();
        println!("Receipt exported ({} bytes)", receipt_bytes.len());

        // Export the journal separately.
        std::fs::write(format!("{}/journal.bin", args.output_dir), receipt.journal.bytes.as_slice()).unwrap();

        // Export image ID.
        let image_id_hex = hex::encode(
            VERENC_GUEST_ID.iter()
                .flat_map(|w| w.to_le_bytes())
                .collect::<Vec<u8>>()
        );
        std::fs::write(format!("{}/image_id.txt", args.output_dir), &image_id_hex).unwrap();
        println!("Image ID: 0x{}", image_id_hex);

        // Export the seal (Groth16 proof bytes).
        if let risc0_zkvm::InnerReceipt::Groth16(ref groth16_receipt) = receipt.inner {
            let seal_bytes = &groth16_receipt.seal;
            std::fs::write(format!("{}/seal.bin", args.output_dir), seal_bytes).unwrap();
            println!("Seal exported ({} bytes)", seal_bytes.len());

            // Export claim digest.
            let claim = receipt.claim().unwrap();
            let claim_bytes = bincode::serialize(&claim).unwrap();
            std::fs::write(format!("{}/claim.bin", args.output_dir), &claim_bytes).unwrap();
        }
    } else {
        eprintln!("Specify --execute, --prove, or --prove-groth16");
        std::process::exit(1);
    }
}
