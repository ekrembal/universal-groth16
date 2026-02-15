//! Common types and functions for the verifiable encryption pipeline.
//!
//! This crate is `no_std` compatible so it can be used inside RISC0 and SP1
//! guest programs (both patch `sha2` with hardware-accelerated precompiles).
//!
//! # Verifiable Encryption Scheme
//!
//! Given pairs `(a_i, b_i)` of 32-byte elements:
//! - `c_i = a_i XOR b_i` (ciphertext — knowing `a_i` reveals `b_i`)
//! - `h(b_i) = SHA256(b_i)` (commitment to `b_i`)
//! - `inner_i = SHA256(a_i || h(b_i) || c_i)` (binds key, commitment, ciphertext)
//! - `accumulator = fold(inner_0, inner_1, ..., inner_n)` where
//!   `fold(x, y) = SHA256(x || y)` applied left-to-right
//!
//! The accumulator hash is the public output proven by both RISC0 and SP1.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};

/// A 32-byte element (key, plaintext, ciphertext, or hash).
pub type Element = [u8; 32];

/// A pair of elements to be encrypted.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Pair {
    pub a: Element,
    pub b: Element,
}

/// The public output of the verifiable encryption computation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerencOutput {
    /// The accumulator hash over all pairs.
    pub accumulator: Element,
    /// Number of pairs processed.
    pub num_pairs: u32,
}

/// Bitwise XOR of two 32-byte elements.
pub fn xor(a: &Element, b: &Element) -> Element {
    let mut c = [0u8; 32];
    for i in 0..32 {
        c[i] = a[i] ^ b[i];
    }
    c
}

/// Hash a single element: `h(b) = SHA256(b)`.
pub fn hash_element(b: &Element) -> Element {
    let mut hasher = Sha256::new();
    hasher.update(b);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Hash a triple: `H(a, hb, c) = SHA256(a || hb || c)` (96 bytes input).
pub fn hash_triple(a: &Element, hb: &Element, c: &Element) -> Element {
    let mut hasher = Sha256::new();
    hasher.update(a);
    hasher.update(hb);
    hasher.update(c);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Fold two hashes: `SHA256(left || right)`.
pub fn hash_fold(left: &Element, right: &Element) -> Element {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Compute the full accumulator hash over a list of pairs.
///
/// For each pair `(a_i, b_i)`:
/// 1. `c_i = a_i XOR b_i`
/// 2. `hb_i = SHA256(b_i)`
/// 3. `inner_i = SHA256(a_i || hb_i || c_i)`
///
/// Then left-fold: `acc = inner[0]; for i in 1..n: acc = SHA256(acc || inner[i])`
///
/// Returns `(accumulator, vec_of_c, vec_of_hb)` for verification purposes.
pub fn accumulate(pairs: &[Pair]) -> (Element, Vec<Element>, Vec<Element>) {
    assert!(!pairs.is_empty(), "must have at least one pair");

    let mut cs = Vec::with_capacity(pairs.len());
    let mut hbs = Vec::with_capacity(pairs.len());
    let mut inners = Vec::with_capacity(pairs.len());

    for pair in pairs {
        let c = xor(&pair.a, &pair.b);
        let hb = hash_element(&pair.b);
        let inner = hash_triple(&pair.a, &hb, &c);
        cs.push(c);
        hbs.push(hb);
        inners.push(inner);
    }

    // Left-fold the inner hashes.
    let mut acc = inners[0];
    for inner in &inners[1..] {
        acc = hash_fold(&acc, inner);
    }

    (acc, cs, hbs)
}

/// Recompute the accumulator hash from raw inputs (for verification).
///
/// This is what the verifier calls — it does NOT know `b_i`, only `h(b_i)`.
pub fn recompute_accumulator(
    a_values: &[Element],
    hb_values: &[Element],
    c_values: &[Element],
) -> Element {
    assert!(!a_values.is_empty(), "must have at least one element");
    assert_eq!(a_values.len(), hb_values.len());
    assert_eq!(a_values.len(), c_values.len());

    let mut inners = Vec::with_capacity(a_values.len());
    for i in 0..a_values.len() {
        inners.push(hash_triple(&a_values[i], &hb_values[i], &c_values[i]));
    }

    let mut acc = inners[0];
    for inner in &inners[1..] {
        acc = hash_fold(&acc, inner);
    }
    acc
}

/// Generate deterministic test pairs for benchmarking.
///
/// Uses SHA256-based PRNG seeded from pair index.
pub fn generate_test_pairs(n: usize) -> Vec<Pair> {
    let mut pairs = Vec::with_capacity(n);
    for i in 0..n {
        let mut seed_a = [0u8; 32];
        let mut seed_b = [0u8; 32];
        // Deterministic generation from index
        let idx_bytes = (i as u64).to_le_bytes();
        seed_a[..8].copy_from_slice(&idx_bytes);
        seed_a[8] = 0xAA; // tag for 'a'
        seed_b[..8].copy_from_slice(&idx_bytes);
        seed_b[8] = 0xBB; // tag for 'b'

        let a = hash_element(&seed_a);
        let b = hash_element(&seed_b);
        pairs.push(Pair { a, b });
    }
    pairs
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn test_xor_inverse() {
        let a = hash_element(&[1u8; 32]);
        let b = hash_element(&[2u8; 32]);
        let c = xor(&a, &b);
        // a XOR c should give b
        let recovered_b = xor(&a, &c);
        assert_eq!(recovered_b, b);
    }

    #[test]
    fn test_accumulate_deterministic() {
        let pairs = generate_test_pairs(5);
        let (acc1, _, _) = accumulate(&pairs);
        let (acc2, _, _) = accumulate(&pairs);
        assert_eq!(acc1, acc2);
    }

    #[test]
    fn test_recompute_matches_accumulate() {
        let pairs = generate_test_pairs(10);
        let (acc, cs, hbs) = accumulate(&pairs);

        let a_values: Vec<Element> = pairs.iter().map(|p| p.a).collect();
        let recomputed = recompute_accumulator(&a_values, &hbs, &cs);
        assert_eq!(acc, recomputed);
    }

    #[test]
    fn test_single_pair() {
        let pairs = generate_test_pairs(1);
        let (acc, cs, hbs) = accumulate(&pairs);
        // For a single pair, acc = inner[0] = H(a, h(b), c)
        let expected = hash_triple(&pairs[0].a, &hbs[0], &cs[0]);
        assert_eq!(acc, expected);
    }
}
