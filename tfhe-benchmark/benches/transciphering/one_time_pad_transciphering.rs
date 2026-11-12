//! Server side of the one time pad through the high level API, on CPU, or on GPU with the gpu
//! feature. Both use the CPU key set, classical 2_2 with a dedicated OPRF, which fhevm also runs
//! on GPU.
//!
//! Two cases, new_random for a 64 bits mask and transcipher for a FheUint64. Run with
//! make bench_one_time_pad_transciphering or its _gpu variant, BENCH_FILTER picks a case.

use benchmark::params_aliases::BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
use benchmark::utilities::bench_and_record;
use benchmark_spec::tfhe::transciphering::one_time_pad::OneTimePadFlavor;
use benchmark_spec::tfhe::transciphering::TranscipheringBench;
use benchmark_spec::{BenchmarkMetric, BenchmarkSpec, PrecisionTag};
use criterion::{criterion_group, BatchSize, Criterion};
use rand::Rng;
use std::hint::black_box;
use tfhe::keycache::NamedParam;
use tfhe::prelude::*;
use tfhe::shortint::parameters::v1_9::transciphering::V1_9_TRANSCIPHERING_PARAM_DEDICATED_OPRF;
use tfhe::transciphering::OneTimePadPlainState;
use tfhe::{
    set_server_key, ClientKey, ConfigBuilder, FheUint64, HlStreamCipher, HlTranscipherer,
    OneTimePadFheSecretMask, Seed, TranscipherSession,
};

const N_BITS: u32 = 64;

fn one_time_pad_bench(c: &mut Criterion, cks: &ClientKey) {
    let mut group = c.benchmark_group("transciphering::one_time_pad");
    group
        .sample_size(15)
        .measurement_time(std::time::Duration::from_secs(30));

    let param_name = cks.computation_parameters().name();
    // Not a production seed, a seed must never encrypt two different data
    let new_mask = || OneTimePadFheSecretMask::new_random(Seed(0), N_BITS.into()).unwrap();

    let spec = |flavor| {
        BenchmarkSpec::new_transciphering(
            TranscipheringBench::OneTimePad(flavor),
            &param_name,
            Some(PrecisionTag::Bits(N_BITS).into()),
            BenchmarkMetric::Latency,
            None,
        )
    };

    bench_and_record(
        &mut group,
        &spec(OneTimePadFlavor::NewRandom),
        "one_time_pad_new_random",
        N_BITS.into(),
        vec![],
        |b| b.iter(|| black_box(new_mask())),
    );

    let mut client = OneTimePadPlainState::new(new_mask().decrypt(cks));
    let input = client.try_encrypt(rand::thread_rng().gen::<u64>()).unwrap();

    // A session consumes its mask, so each iteration gets a new one, outside of the measure
    bench_and_record(
        &mut group,
        &spec(OneTimePadFlavor::Transcipher),
        "one_time_pad_transcipher",
        N_BITS.into(),
        vec![],
        |b| {
            b.iter_batched(
                || TranscipherSession::one_time_pad(new_mask()).unwrap(),
                |mut session| {
                    let output: FheUint64 = session.transcipher(&input).unwrap();
                    black_box(output)
                },
                BatchSize::SmallInput,
            )
        },
    );

    group.finish();
}

fn client_key() -> ClientKey {
    let config =
        ConfigBuilder::with_custom_parameters(BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128)
            .enable_transciphering(V1_9_TRANSCIPHERING_PARAM_DEDICATED_OPRF)
            .build();
    ClientKey::generate(config)
}

#[cfg(not(feature = "gpu"))]
fn one_time_pad_cpu(c: &mut Criterion) {
    let cks = client_key();
    let sks = tfhe::ServerKey::new(&cks);

    rayon::broadcast(|_| set_server_key(sks.clone()));
    set_server_key(sks);

    one_time_pad_bench(c, &cks);
}

#[cfg(feature = "gpu")]
fn one_time_pad_gpu(c: &mut Criterion) {
    let cks = client_key();
    set_server_key(tfhe::CompressedServerKey::new(&cks).decompress_to_gpu());

    one_time_pad_bench(c, &cks);
}

// The backend of the spec ids comes from the features, so a build runs a single backend
#[cfg(not(feature = "gpu"))]
criterion_group!(one_time_pad, one_time_pad_cpu);
#[cfg(feature = "gpu")]
criterion_group!(one_time_pad, one_time_pad_gpu);

fn main() {
    one_time_pad();
    Criterion::default().configure_from_args().final_summary();
}
