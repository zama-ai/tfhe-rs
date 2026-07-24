//! CPU benchmarks for the shortint Kreyvium transciphering pipeline
//! (`tfhe::transciphering::ciphers::kreyvium`).
//!
//! Available cases (filter with criterion's `--bench` arg or via the Makefile's
//! `BENCH_FILTER`):
//!   * `warmup`             : the 1152 (= 18*64) mixing rounds run by `KreyviumFheState::new`
//!     before any keystream is produced.
//!   * `keystream_64bits`   : 64 keystream bits from an already-warmed state. 64 is Kreyvium's
//!     parallel round-batch size (`next_64`).
//!   * `transcipher_64bits` : end-to-end `transcipher` over 64 bits (`next_keystream_bits` +
//!     `apply_keystream_2_2`).
//!
//! Run with:
//! ```sh
//! cargo bench --features=shortint,internal-keycache \
//!     --bench transciphering-kreyvium
//! ```

use benchmark::params_aliases::BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
use benchmark::utilities::bench_and_record;
use benchmark_spec::tfhe::transciphering::kreyvium::KreyviumFlavor;
use benchmark_spec::tfhe::transciphering::TranscipheringBench;
use benchmark_spec::{BenchmarkMetric, BenchmarkSpec};
use criterion::{criterion_group, BatchSize, Criterion};
use rand::{Rng, SeedableRng};
use std::hint::black_box;
use tfhe::keycache::NamedParam;
use tfhe::shortint::prelude::*;
use tfhe::shortint::AtomicPatternParameters;
use tfhe::transciphering::ciphers::kreyvium::{
    KreyviumFheState, KreyviumIV, KreyviumPlainKey, KreyviumPlainState,
};
use tfhe::transciphering::{StreamCipher, Transcipherer};

const KEY_BITS: usize = 128;
const KEYSTREAM_BITS: usize = 64;
const KEYSTREAM_BYTES: usize = KEYSTREAM_BITS / 8;
// 512 bits = 256 output ciphertexts, enough `apply_keystream_2_2` pairs to exercise its
// parallelism (the 64-bit case has too few pairs for scheduling to matter).
const KEYSTREAM_BITS_LARGE: usize = 512;
const KEYSTREAM_BYTES_LARGE: usize = KEYSTREAM_BITS_LARGE / 8;

pub fn cpu_kreyvium_transciphering(c: &mut Criterion) {
    let bench_name = "transciphering::cpu::kreyvium";

    let seed: u64 = rand::thread_rng().gen();
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);

    let key_bytes: [u8; 16] = rng.gen();
    let iv_bytes: [u8; 16] = rng.gen();

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
    let plain_key = KreyviumPlainKey::from(key_bytes);

    // ---- warmup ----
    let benchmark_spec = BenchmarkSpec::<str>::new_transciphering(
        TranscipheringBench::Kreyvium(KreyviumFlavor::Warmup),
        &param_name,
        BenchmarkMetric::Latency,
    );
    bench_and_record(
        &mut group,
        &benchmark_spec,
        "kreyvium_warmup",
        KEY_BITS as u32,
        vec![log2_msg; KEY_BITS],
        |b| {
            b.iter_batched(
                || KreyviumPlainKey::from(key_bytes).encrypt(&cks),
                |fhe_key| {
                    black_box(KreyviumFheState::new(fhe_key, iv_bytes, &sks));
                },
                BatchSize::SmallInput,
            )
        },
    );

    // Pre-warmed state cloned per iter for the remaining benches.
    let warm_state = {
        let fhe_key = plain_key.encrypt(&cks);
        KreyviumFheState::new(fhe_key, iv_bytes, &sks)
    };

    // ---- keystream_64bits ----
    let benchmark_spec = BenchmarkSpec::<str>::new_transciphering(
        TranscipheringBench::Kreyvium(KreyviumFlavor::Keystream64Bits),
        &param_name,
        BenchmarkMetric::Latency,
    );
    bench_and_record(
        &mut group,
        &benchmark_spec,
        &format!("kreyvium_keystream_{KEYSTREAM_BITS}bits"),
        KEYSTREAM_BITS as u32,
        vec![log2_msg; KEYSTREAM_BITS],
        |b| {
            b.iter_batched(
                || warm_state.clone(),
                |mut stream| {
                    black_box(stream.next_keystream_bits(&sks, KEYSTREAM_BITS));
                },
                BatchSize::SmallInput,
            )
        },
    );

    // ---- transcipher_64bits ----
    let message = vec![0u8; KEYSTREAM_BYTES];
    let sym_cipher = {
        let mut plain_stream = KreyviumPlainState::new(
            KreyviumPlainKey::from(key_bytes),
            KreyviumIV::from(iv_bytes),
        );
        plain_stream.encrypt(&message)
    };

    let benchmark_spec = BenchmarkSpec::<str>::new_transciphering(
        TranscipheringBench::Kreyvium(KreyviumFlavor::Transcipher64Bits),
        &param_name,
        BenchmarkMetric::Latency,
    );
    bench_and_record(
        &mut group,
        &benchmark_spec,
        &format!("kreyvium_transcipher_{KEYSTREAM_BITS}bits"),
        KEYSTREAM_BITS as u32,
        vec![log2_msg; KEYSTREAM_BITS],
        |b| {
            b.iter_batched(
                || warm_state.clone(),
                |mut stream| {
                    black_box(stream.transcipher(&sks, &sym_cipher).unwrap());
                },
                BatchSize::SmallInput,
            )
        },
    );

    // ---- transcipher_512bits ----
    let message_large = vec![0u8; KEYSTREAM_BYTES_LARGE];
    let sym_cipher_large = {
        let mut plain_stream = KreyviumPlainState::new(
            KreyviumPlainKey::from(key_bytes),
            KreyviumIV::from(iv_bytes),
        );
        plain_stream.encrypt(&message_large)
    };

    let benchmark_spec = BenchmarkSpec::<str>::new_transciphering(
        TranscipheringBench::Kreyvium(KreyviumFlavor::Transcipher512Bits),
        &param_name,
        BenchmarkMetric::Latency,
    );
    bench_and_record(
        &mut group,
        &benchmark_spec,
        &format!("kreyvium_transcipher_{KEYSTREAM_BITS_LARGE}bits"),
        KEYSTREAM_BITS_LARGE as u32,
        vec![log2_msg; KEYSTREAM_BITS_LARGE],
        |b| {
            b.iter_batched(
                || warm_state.clone(),
                |mut stream| {
                    black_box(stream.transcipher(&sks, &sym_cipher_large).unwrap());
                },
                BatchSize::SmallInput,
            )
        },
    );

    group.finish();
}

criterion_group!(cpu_kreyvium, cpu_kreyvium_transciphering);

fn main() {
    cpu_kreyvium();
    Criterion::default().configure_from_args().final_summary();
}
