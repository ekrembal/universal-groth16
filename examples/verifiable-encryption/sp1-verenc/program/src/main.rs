//! SP1 guest program for verifiable encryption.
//!
//! Identical computation to the RISC0 guest: reads pairs, computes XOR
//! ciphertexts, and commits the accumulator hash as public output.

#![no_main]
sp1_zkvm::entrypoint!(main);

use verenc_common::{accumulate, Pair, VerencOutput};

pub fn main() {
    // Read the pairs from the host (private input).
    let pairs: Vec<Pair> = sp1_zkvm::io::read();

    // Compute the accumulator hash.
    let (accumulator, _cs, _hbs) = accumulate(&pairs);

    let output = VerencOutput {
        accumulator,
        num_pairs: pairs.len() as u32,
    };

    // Commit the output (public values).
    sp1_zkvm::io::commit(&output);
}
