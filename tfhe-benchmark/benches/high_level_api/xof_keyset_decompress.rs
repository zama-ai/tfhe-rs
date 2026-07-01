//! Sanity-check microbench for selective decompression of a `CompressedXofKeySet`.
//!
//! `full` decompresses the whole key set; `all_parts_one_by_one` fetches every part through the
//! selective API; `kms_subset` fetches only what `NoiseFloodSmall` needs. The `_parallel` variants
//! fetch concurrently via rayon — the independent per-part walks need no coordination.

use benchmark::params_aliases::{
    BENCH_COMP_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    BENCH_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    BENCH_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    BENCH_PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    BENCH_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use tfhe::core_crypto::prelude::NormalizedHammingWeightBound;
use tfhe::integer::ciphertext::NoiseSquashingCompressionKey;
use tfhe::integer::compression_keys::{CompressionKey, DecompressionKey};
use tfhe::integer::key_switching_key::KeySwitchingKeyMaterial;
use tfhe::integer::noise_squashing::NoiseSquashingKey;
use tfhe::integer::oprf::OprfServerKey;
use tfhe::integer::ServerKey;
use tfhe::xof_key_set::CompressedXofKeySet;
use tfhe::{CompactPublicKey, ConfigBuilder, ReRandomizationKey, Tag};

fn xof_keyset_decompress(c: &mut Criterion) {
    let config =
        ConfigBuilder::with_custom_parameters(BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128)
            .use_dedicated_compact_public_key_parameters((
                BENCH_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
                BENCH_PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            ))
            .enable_compression(BENCH_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128)
            .enable_noise_squashing(
                BENCH_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            )
            .enable_noise_squashing_compression(
                BENCH_COMP_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            )
            .build();

    let (_client_key, key_set) = CompressedXofKeySet::generate(
        config,
        vec![0u8; 32],
        128,
        NormalizedHammingWeightBound::new(0.8).unwrap(),
        Tag::default(),
    )
    .unwrap();
    let key_set = black_box(key_set);

    let mut group = c.benchmark_group("xof_keyset_decompress");

    group.bench_function("full", |b| b.iter(|| key_set.decompress()));

    group.bench_function("all_parts_one_by_one", |b| {
        b.iter(|| {
            (
                key_set.decompress_parts::<CompactPublicKey>(),
                key_set.decompress_parts::<ServerKey>(),
                key_set.decompress_parts::<Option<KeySwitchingKeyMaterial>>(),
                key_set.decompress_parts::<Option<CompressionKey>>(),
                key_set.decompress_parts::<Option<DecompressionKey>>(),
                key_set.decompress_parts::<Option<NoiseSquashingKey>>(),
                key_set.decompress_parts::<Option<NoiseSquashingCompressionKey>>(),
                key_set.decompress_parts::<Option<ReRandomizationKey>>(),
                key_set.decompress_parts::<Option<OprfServerKey>>(),
            )
        })
    });

    group.bench_function("kms_subset", |b| {
        b.iter(|| {
            key_set.decompress_parts::<(
                ServerKey,
                Option<DecompressionKey>,
                Option<NoiseSquashingKey>,
            )>()
        })
    });

    // The `_parallel` variants fetch their parts concurrently: each part walks the seed
    // independently, so the tasks need no coordination.
    group.bench_function("all_parts_parallel", |b| {
        b.iter(|| {
            rayon::scope(|s| {
                s.spawn(|_| {
                    black_box(key_set.decompress_parts::<CompactPublicKey>());
                });
                s.spawn(|_| {
                    black_box(key_set.decompress_parts::<ServerKey>());
                });
                s.spawn(|_| {
                    black_box(key_set.decompress_parts::<Option<KeySwitchingKeyMaterial>>());
                });
                s.spawn(|_| {
                    black_box(key_set.decompress_parts::<Option<CompressionKey>>());
                });
                s.spawn(|_| {
                    black_box(key_set.decompress_parts::<Option<DecompressionKey>>());
                });
                s.spawn(|_| {
                    black_box(key_set.decompress_parts::<Option<NoiseSquashingKey>>());
                });
                s.spawn(|_| {
                    black_box(key_set.decompress_parts::<Option<NoiseSquashingCompressionKey>>());
                });
                s.spawn(|_| {
                    black_box(key_set.decompress_parts::<Option<ReRandomizationKey>>());
                });
                s.spawn(|_| {
                    black_box(key_set.decompress_parts::<Option<OprfServerKey>>());
                });
            });
        })
    });

    group.bench_function("kms_subset_parallel", |b| {
        b.iter(|| {
            rayon::join(
                || key_set.decompress_parts::<ServerKey>(),
                || {
                    rayon::join(
                        || key_set.decompress_parts::<Option<DecompressionKey>>(),
                        || key_set.decompress_parts::<Option<NoiseSquashingKey>>(),
                    )
                },
            )
        })
    });

    group.finish();
}

criterion_group!(benches, xof_keyset_decompress);
criterion_main!(benches);
