//! Generates the seed corpus file for `harness-cuda-scalars`.
//!
//! The scalars harness takes raw bytes (no ProvenCompactCiphertextList, no ZK proof),
//! so the seed is just a fixed buffer of entropy sized to cover one full scalar pass
//! through every supported fhevm type without cycling.

use std::fs::File;
use std::io::Write;

use fuzz_utils::CorpusDir;

/// Size of the seed buffer. One full `generate_scalar_ops_gpu` pass consumes roughly
/// 8 × (16 for the OPRF seed + ~16 for the trivial value + 1 for the `random_bits` byte),
/// so 512 bytes is comfortably above that and leaves AFL room to mutate.
const SEED_BYTES: usize = 512;

fn main() {
    let corpus_dir = CorpusDir::new();
    std::fs::create_dir_all(&corpus_dir).unwrap();

    // A simple incrementing pattern: deterministic and non-uniform enough that the first
    // run exercises the whole ScalarSource range without producing all-zero scalars.
    let seed: Vec<u8> = (0..SEED_BYTES).map(|i| (i & 0xff) as u8).collect();

    let mut f = File::create(corpus_dir.gpu_scalars_input_path()).unwrap();
    f.write_all(&seed).unwrap();
}
