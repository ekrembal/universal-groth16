//! SP1 host script for verifiable encryption.
//!
//! Usage:
//!   RUST_LOG=info cargo run --release -- --execute       # execute only
//!   RUST_LOG=info cargo run --release -- --prove         # STARK proof (compressed)
//!   RUST_LOG=info cargo run --release -- --prove-plonk   # full PlonK proof
//!   RUST_LOG=info cargo run --release -- --prove-groth16 # full Groth16 proof

use clap::Parser;
use sp1_sdk::{
    blocking::{ProveRequest, Prover, ProverClient},
    include_elf, Elf, HashableKey, ProvingKey, SP1Stdin,
};
use std::time::Instant;
use verenc_sp1_lib::{generate_test_pairs, VerencOutput};

/// The ELF for the verifiable encryption SP1 program.
const VERENC_ELF: Elf = include_elf!("verenc-sp1-program");

#[derive(Parser, Debug)]
#[command(author, version, about = "Verifiable encryption SP1 prover")]
struct Args {
    #[arg(long)]
    execute: bool,

    #[arg(long)]
    prove: bool,

    #[arg(long)]
    prove_plonk: bool,

    #[arg(long)]
    prove_groth16: bool,

    /// Number of pairs to encrypt.
    #[arg(long, default_value = "10")]
    num_pairs: usize,

    /// Directory to export proof artifacts.
    #[arg(long, default_value = "./proofs/sp1")]
    output_dir: String,
}

fn main() {
    sp1_sdk::utils::setup_logger();
    dotenv::dotenv().ok();

    let args = Args::parse();

    // Generate deterministic test pairs.
    let pairs = generate_test_pairs(args.num_pairs);
    println!("Generated {} pairs", pairs.len());

    // Compute expected output natively for verification.
    let (expected_acc, _cs, _hbs) = verenc_sp1_lib::accumulate(&pairs);
    println!("Expected accumulator: 0x{}", hex::encode(expected_acc));

    // Setup inputs.
    let mut stdin = SP1Stdin::new();
    stdin.write(&pairs);

    // Setup the prover client.
    let client = ProverClient::from_env();

    if args.execute {
        println!("\n=== Executing (no proof) ===");
        let t = Instant::now();
        let (output, report) = client.execute(VERENC_ELF, stdin).run().unwrap();
        let elapsed = t.elapsed();
        println!("Execution time: {:.2?}", elapsed);
        println!("Cycles: {}", report.total_instruction_count());

        let result: VerencOutput = bincode::deserialize(output.as_slice())
            .expect("failed to deserialize output");
        println!("Accumulator: 0x{}", hex::encode(result.accumulator));
        assert_eq!(result.accumulator, expected_acc, "accumulator mismatch!");
        println!("Output verified!");
        return;
    }

    // Setup proving key.
    let pk = client.setup(VERENC_ELF).expect("failed to setup");
    let vk = pk.verifying_key().clone();

    // Print vkey hash.
    println!("SP1 VKey hash: {}", vk.bytes32());

    if args.prove {
        println!("\n=== Generating STARK proof (compressed) ===");
        let t = Instant::now();
        let proof = client.prove(&pk, stdin).compressed().run().unwrap();
        let elapsed = t.elapsed();
        println!("STARK proof time: {:.2?}", elapsed);

        client.verify(&proof, &vk, None).unwrap();
        println!("STARK proof verified!");
    } else if args.prove_plonk {
        println!("\n=== Generating PlonK proof ===");
        let t = Instant::now();
        let proof = client.prove(&pk, stdin).plonk().run().unwrap();
        let elapsed = t.elapsed();
        println!("PlonK proof time: {:.2?}", elapsed);

        client.verify(&proof, &vk, None).unwrap();
        println!("PlonK proof verified!");

        // Export proof artifacts.
        std::fs::create_dir_all(&args.output_dir).unwrap();
        let proof_bytes = bincode::serialize(&proof).unwrap();
        std::fs::write(format!("{}/proof.bin", args.output_dir), &proof_bytes).unwrap();
        println!("Proof exported to {}/proof.bin ({} bytes)", args.output_dir, proof_bytes.len());

        // Export vkey hash.
        std::fs::write(
            format!("{}/vkey_hash.txt", args.output_dir),
            vk.bytes32(),
        ).unwrap();
        println!("VKey hash exported");
    } else if args.prove_groth16 {
        println!("\n=== Generating Groth16 proof (SP1 standard flow) ===");
        let t = Instant::now();
        let proof = client.prove(&pk, stdin).groth16().run().unwrap();
        let elapsed = t.elapsed();
        println!("Groth16 proof time: {:.2?}", elapsed);

        client.verify(&proof, &vk, None).unwrap();
        println!("Groth16 proof verified!");

        // Export proof.
        std::fs::create_dir_all(&args.output_dir).unwrap();
        let proof_bytes = bincode::serialize(&proof).unwrap();
        std::fs::write(format!("{}/groth16_proof.bin", args.output_dir), &proof_bytes).unwrap();
        println!("Groth16 proof exported ({} bytes)", proof_bytes.len());
    } else {
        eprintln!("Specify --execute, --prove, --prove-plonk, or --prove-groth16");
        std::process::exit(1);
    }
}
