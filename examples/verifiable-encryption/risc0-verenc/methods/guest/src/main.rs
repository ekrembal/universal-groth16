use risc0_zkvm::guest::env;
use verenc_common::{accumulate, Pair, VerencOutput};

fn main() {
    // Read the pairs from the host (private input).
    let pairs: Vec<Pair> = env::read();

    // Compute the accumulator hash.
    let (accumulator, _cs, _hbs) = accumulate(&pairs);

    let output = VerencOutput {
        accumulator,
        num_pairs: pairs.len() as u32,
    };

    // Commit the output to the journal (public output).
    env::commit(&output);
}
