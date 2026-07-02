//! CPU benchmarks for the bit-sliced shortint AES-128 transciphering pipeline
//! (`tfhe::transciphering::ciphers::aes`).
//!
//! Available cases (filter with criterion's `--bench` arg or via the Makefile's
//! `BENCH_FILTER`):
//!   * `key_expansion`        : one-time `AesFheKey::new` cost per key.
//!   * `keystream_1_block`    : single CTR block (128 bits) without `apply_keystream`; the unit hot
//!     path.
//!   * `keystream_16_blocks`  : 16 CTR blocks (cheap multi-block measurement).
//!   * `transcipher_16_blocks` : end-to-end `transcipher` over 16 blocks (`next_keystream_bits` +
//!     `apply_keystream_2_2`).
//!
//! Run with:
//! ```sh
//! cargo bench --features=shortint,internal-keycache \
//!     --bench shortint-aes-transciphering
//! ```

use benchmark::params_aliases::BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
use benchmark::utilities::{write_to_json_unchecked, OperatorType};
use criterion::measurement::WallTime;
use criterion::{criterion_group, Bencher, BenchmarkGroup, Criterion};
use rand::{Rng, SeedableRng};
use std::hint::black_box;
use tfhe::keycache::NamedParam;
use tfhe::shortint::prelude::*;
use tfhe::shortint::AtomicPatternParameters;
use tfhe::transciphering::ciphers::aes::{
    AesFheRoundKeys, AesFheState, AesPlainKey, AesPlainState,
};
use tfhe::transciphering::{StreamCipher, Transcipherer};

const N_BLOCKS: usize = 16;
const BLOCK_BITS: usize = 128;
const BLOCK_BYTES: usize = 16;

fn bench_and_record<F>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    id: &str,
    param_name: &str,
    display_name: &str,
    bit_size: u32,
    decomposition_basis: Vec<u32>,
    mut routine: F,
) where
    F: FnMut(&mut Bencher<'_, WallTime>),
{
    let recorded = std::sync::Once::new();
    group.bench_function(id, |b| {
        routine(b);
        recorded.call_once(|| {
            write_to_json_unchecked(
                id,
                param_name,
                display_name,
                &OperatorType::Atomic,
                bit_size,
                decomposition_basis.clone(),
            );
        });
    });
}

pub fn cpu_aes_transciphering(c: &mut Criterion) {
    let bench_name = "transciphering::cpu::aes";

    let seed: u64 = rand::thread_rng().gen();
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);

    let key: u128 = rng.gen();
    let iv: u128 = rng.gen();

    let mut group = c.benchmark_group(bench_name);
    group
        .sample_size(10)
        .measurement_time(std::time::Duration::from_secs(60))
        .warm_up_time(std::time::Duration::from_secs(5));

    let params = BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    let param_name = params.name();
    let atomic_param: AtomicPatternParameters = params.into();
    let log2_msg = atomic_param.message_modulus().0.ilog2();

    let (cks, sks) = gen_keys(params);
    let enc_key = AesPlainKey::from(key).encrypt(&cks);

    // ---- key_expansion ----
    let id = format!("{bench_name}::{}::key_expansion", &param_name);
    bench_and_record(
        &mut group,
        &id,
        &param_name,
        "aes_key_expansion",
        BLOCK_BITS as u32,
        vec![log2_msg; BLOCK_BITS],
        |b| {
            b.iter(|| {
                black_box(AesFheRoundKeys::new(&sks, &enc_key));
            })
        },
    );

    // ---- key_expansion_plus_1_block ----
    // Cold-start cost: fresh key schedule + one CTR block keystream per iter.
    let id = format!("{bench_name}::{}::key_expansion_plus_1_block", &param_name);
    bench_and_record(
        &mut group,
        &id,
        &param_name,
        "aes_key_expansion_plus_1_block",
        BLOCK_BITS as u32,
        vec![log2_msg; BLOCK_BITS],
        |b| {
            b.iter(|| {
                let fhe_key = AesFheRoundKeys::new(&sks, &enc_key);
                let mut stream = AesFheState::new(fhe_key, iv);
                black_box(stream.next_keystream_bits(&sks, BLOCK_BITS));
            })
        },
    );

    // Single stream reused across the remaining benches via `seek(_, 0)`.
    let fhe_key = AesFheRoundKeys::new(&sks, &enc_key);
    let mut stream = AesFheState::new(fhe_key, iv);

    // ---- keystream_1_block ----
    let id = format!("{bench_name}::{}::keystream_1_block", &param_name);
    bench_and_record(
        &mut group,
        &id,
        &param_name,
        "aes_keystream_1_block",
        BLOCK_BITS as u32,
        vec![log2_msg; BLOCK_BITS],
        |b| {
            b.iter(|| {
                stream.seek(&sks, 0);
                black_box(stream.next_keystream_bits(&sks, BLOCK_BITS));
            })
        },
    );

    // ---- keystream_16_blocks ----
    let total_bits = BLOCK_BITS * N_BLOCKS;
    let id = format!("{bench_name}::{}::keystream_16_blocks", &param_name);
    bench_and_record(
        &mut group,
        &id,
        &param_name,
        "aes_keystream_16_blocks",
        total_bits as u32,
        vec![log2_msg; total_bits],
        |b| {
            b.iter(|| {
                stream.seek(&sks, 0);
                black_box(stream.next_keystream_bits(&sks, total_bits));
            })
        },
    );

    // ---- transcipher_16_blocks ----
    // Pre-compute the symmetric ciphertext so the bench only times the FHE
    // side. The clear `AesPlainStream` starts at counter 0, matching our
    // `seek(&sks, 0)` reset below.
    let total_bytes = BLOCK_BYTES * N_BLOCKS;
    let message = vec![0u8; total_bytes];
    let sym_cipher = AesPlainState::new(key, iv).encrypt(&message);

    let id = format!("{bench_name}::{}::transcipher_16_blocks", &param_name);
    bench_and_record(
        &mut group,
        &id,
        &param_name,
        "aes_transcipher_16_blocks",
        total_bits as u32,
        vec![log2_msg; total_bits],
        |b| {
            b.iter(|| {
                stream.seek(&sks, 0);
                black_box(stream.transcipher(&sks, &sym_cipher).unwrap());
            })
        },
    );

    group.finish();
}

criterion_group!(cpu_aes, cpu_aes_transciphering);

fn main() {
    cpu_aes();
    Criterion::default().configure_from_args().final_summary();
}
