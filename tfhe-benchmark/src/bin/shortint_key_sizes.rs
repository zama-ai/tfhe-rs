use benchmark::params::get_classical_tuniform_groups;
use benchmark::params_aliases::*;
use benchmark::utilities::{write_to_json, OperatorType};
use benchmark_spec::{BenchmarkMetric, BenchmarkSpec, CsvResultWriter, KeyKind, ShortintBench};
use std::path::Path;
use tfhe::keycache::NamedParam;
use tfhe::shortint::atomic_pattern::compressed::CompressedAtomicPatternServerKey;
use tfhe::shortint::atomic_pattern::AtomicPatternServerKey;
use tfhe::shortint::keycache::KEY_CACHE;
use tfhe::shortint::list_compression::{
    NoiseSquashingCompressionKey, NoiseSquashingCompressionPrivateKey,
};
use tfhe::shortint::noise_squashing::{NoiseSquashingKey, NoiseSquashingPrivateKey};
use tfhe::shortint::server_key::StandardServerKeyView;
use tfhe::shortint::{
    ClientKey, CompactPrivateKey, CompressedCompactPublicKey, CompressedKeySwitchingKey,
    CompressedServerKey, PBSParameters, ServerKey,
};

fn key_size_spec(key: KeyKind, param_name: &str) -> BenchmarkSpec {
    BenchmarkSpec::new_shortint(
        ShortintBench::Keys(key),
        param_name,
        BenchmarkMetric::KeySize,
    )
}

fn client_server_key_sizes(results_file: &Path) {
    let shortint_params_vec: Vec<PBSParameters> = vec![
        BENCH_PARAM_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M128.into(),
        BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into(),
        BENCH_PARAM_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M128.into(),
        BENCH_PARAM_MESSAGE_4_CARRY_4_KS_PBS_TUNIFORM_2M128.into(),
        BENCH_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128.into(),
        BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128.into(),
        BENCH_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128.into(),
        BENCH_PARAM_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M128.into(),
        BENCH_PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M128.into(),
        BENCH_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into(),
        BENCH_PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M128.into(),
        BENCH_PARAM_MULTI_BIT_GROUP_2_MESSAGE_4_CARRY_4_KS_PBS_TUNIFORM_2M128.into(),
        BENCH_PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M128.into(),
        BENCH_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into(),
        BENCH_PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M128.into(),
        BENCH_PARAM_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_4_KS_PBS_TUNIFORM_2M128.into(),
        BENCH_PARAM_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M128.into(),
        BENCH_PARAM_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into(),
        BENCH_PARAM_MULTI_BIT_GROUP_4_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M128.into(),
        BENCH_PARAM_MULTI_BIT_GROUP_4_MESSAGE_4_CARRY_4_KS_PBS_TUNIFORM_2M128.into(),
        BENCH_PARAM_GPU_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M128.into(),
        BENCH_PARAM_GPU_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into(),
        BENCH_PARAM_GPU_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M128.into(),
        BENCH_PARAM_GPU_MULTI_BIT_GROUP_2_MESSAGE_4_CARRY_4_KS_PBS_TUNIFORM_2M128.into(),
        BENCH_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M128.into(),
        BENCH_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into(),
        BENCH_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M128.into(),
        BENCH_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_4_KS_PBS_TUNIFORM_2M128.into(),
        BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M128.into(),
        BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into(),
        BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M128.into(),
        BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_4_CARRY_4_KS_PBS_TUNIFORM_2M128.into(),
    ];

    let mut benchmark_test_result = CsvResultWriter::from_path(results_file);

    let operator = OperatorType::Atomic;

    println!("Generating shortint (ClientKey, ServerKey)");
    for (i, params) in shortint_params_vec.iter().copied().enumerate() {
        println!(
            "Generating [{} / {}] : {}",
            i + 1,
            shortint_params_vec.len(),
            params.name().to_lowercase()
        );

        let keys = KEY_CACHE.get_from_param(params);

        let cks = keys.client_key();
        let sks = StandardServerKeyView::try_from(keys.server_key().as_view()).unwrap();
        let ksk_size = sks.key_switching_key_size_bytes();
        let spec = key_size_spec(KeyKind::Ksk, &params.name());

        benchmark_test_result.write_result(&spec.to_string(), ksk_size);

        write_to_json(&spec, "KSK", &operator, 0, vec![]);

        println!(
            "Element in KSK: {}, size in bytes: {}",
            sks.key_switching_key_size_elements(),
            ksk_size,
        );

        let bsk_size = sks.bootstrapping_key_size_bytes();
        let spec = key_size_spec(KeyKind::Bsk, &params.name());

        benchmark_test_result.write_result(&spec.to_string(), bsk_size);

        write_to_json(&spec, "BSK", &operator, 0, vec![]);

        println!(
            "Element in BSK: {}, size in bytes: {}",
            sks.bootstrapping_key_size_elements(),
            bsk_size,
        );

        let sks_compressed = CompressedServerKey::new(cks);
        let bsk_compressed_size = sks_compressed.bootstrapping_key_size_bytes();
        let spec = key_size_spec(KeyKind::BskCompressed, &params.name());

        benchmark_test_result.write_result(&spec.to_string(), bsk_compressed_size);

        write_to_json(&spec, "BSK", &operator, 0, vec![]);

        println!(
            "Element in BSK compressed: {}, size in bytes: {}",
            sks_compressed.bootstrapping_key_size_elements(),
            bsk_compressed_size,
        );

        // Clear keys as we go to avoid filling the RAM
        KEY_CACHE.clear_in_memory_cache()
    }
}

fn measure_serialized_size<T: serde::Serialize>(
    to_serialize: &T,
    param_name: &str,
    key: KeyKind,
    display_name: &str,
    file: &mut CsvResultWriter,
) {
    let serialized = bincode::serialize(to_serialize).unwrap();
    let size = serialized.len();
    let spec = key_size_spec(key, param_name);
    file.write_result(&spec.to_string(), size);
    write_to_json(&spec, display_name, &OperatorType::Atomic, 0, vec![]);

    println!("{key} {param_name} -> size: {size} bytes",);
}

fn tuniform_key_set_sizes(results_file: &Path) {
    let mut benchmark_test_result = CsvResultWriter::from_path(results_file);

    println!("Measuring shortint key sizes:");

    for meta_params in get_classical_tuniform_groups().iter() {
        let compute_param = meta_params.compute_parameters;
        println!(
            "---- Base parameters set : {}",
            compute_param.name().to_lowercase()
        );

        let param_fhe_name = compute_param.name();
        let cks = ClientKey::new(compute_param);
        let compressed_sks = CompressedServerKey::new(&cks);
        let sks = ServerKey::try_from(compressed_sks.decompress()).unwrap();

        match &sks.atomic_pattern {
            AtomicPatternServerKey::Standard(ap) => {
                measure_serialized_size(
                    &ap.key_switching_key,
                    &param_fhe_name,
                    KeyKind::Ksk,
                    "KSK",
                    &mut benchmark_test_result,
                );
                measure_serialized_size(
                    &ap.bootstrapping_key,
                    &param_fhe_name,
                    KeyKind::Bsk,
                    "BSK",
                    &mut benchmark_test_result,
                );
            }
            AtomicPatternServerKey::KeySwitch32(ap) => {
                measure_serialized_size(
                    &ap.key_switching_key,
                    &param_fhe_name,
                    KeyKind::Ksk,
                    "KSK",
                    &mut benchmark_test_result,
                );
                measure_serialized_size(
                    &ap.bootstrapping_key,
                    &param_fhe_name,
                    KeyKind::Bsk,
                    "BSK",
                    &mut benchmark_test_result,
                );
            }
            AtomicPatternServerKey::Dynamic(_) => panic!("Dynamic atomic pattern not supported"),
        }

        match &compressed_sks.compressed_ap_server_key {
            CompressedAtomicPatternServerKey::Standard(comp_ap) => {
                measure_serialized_size(
                    comp_ap.key_switching_key(),
                    &param_fhe_name,
                    KeyKind::KskCompressed,
                    "KSK",
                    &mut benchmark_test_result,
                );
                measure_serialized_size(
                    &comp_ap.bootstrapping_key(),
                    &param_fhe_name,
                    KeyKind::BskCompressed,
                    "BSK",
                    &mut benchmark_test_result,
                );
            }
            CompressedAtomicPatternServerKey::KeySwitch32(comp_ap) => {
                measure_serialized_size(
                    comp_ap.key_switching_key(),
                    &param_fhe_name,
                    KeyKind::KskCompressed,
                    "KSK",
                    &mut benchmark_test_result,
                );
                measure_serialized_size(
                    &comp_ap.bootstrapping_key(),
                    &param_fhe_name,
                    KeyKind::BskCompressed,
                    "BSK",
                    &mut benchmark_test_result,
                );
            }
        }

        if let Some(dedicated_pke_params) = meta_params.dedicated_compact_public_key_parameters {
            let pke_param = dedicated_pke_params.pke_params;
            let param_pke_name = pke_param.name();
            let compact_private_key = CompactPrivateKey::new(pke_param);
            let compressed_pk = CompressedCompactPublicKey::new(&compact_private_key);
            let pk = compressed_pk.decompress();

            measure_serialized_size(
                &pk,
                &param_pke_name,
                KeyKind::Cpk,
                "CPK",
                &mut benchmark_test_result,
            );
            measure_serialized_size(
                &compressed_pk,
                &param_pke_name,
                KeyKind::CpkCompressed,
                "CPK",
                &mut benchmark_test_result,
            );

            let casting_param = dedicated_pke_params.ksk_params;
            let param_casting_name = casting_param.name();
            let compressed_casting_key = CompressedKeySwitchingKey::new(
                (&compact_private_key, None),
                (&cks, &compressed_sks),
                casting_param,
            );
            let casting_key = compressed_casting_key.decompress();

            measure_serialized_size(
                &casting_key.into_raw_parts().0,
                &param_casting_name,
                KeyKind::CastingKey,
                "CastKey",
                &mut benchmark_test_result,
            );
            measure_serialized_size(
                &compressed_casting_key.into_raw_parts().0,
                &param_casting_name,
                KeyKind::CastingKeyCompressed,
                "CastKey",
                &mut benchmark_test_result,
            );
        }

        if let Some(compression_param) = meta_params.compression_parameters {
            let param_compression_name = compression_param.name();

            let private_compression_key = cks.new_compression_private_key(compression_param);
            let (compression_key, decompression_key) =
                cks.new_compression_decompression_keys(&private_compression_key);

            measure_serialized_size(
                &compression_key,
                &param_compression_name,
                KeyKind::CompressionKey,
                "CompressionKey",
                &mut benchmark_test_result,
            );
            measure_serialized_size(
                &decompression_key,
                &param_compression_name,
                KeyKind::DecompressionKey,
                "CompressionKey",
                &mut benchmark_test_result,
            );

            let (compressed_compression_key, compressed_decompression_key) =
                cks.new_compressed_compression_decompression_keys(&private_compression_key);

            measure_serialized_size(
                &compressed_compression_key,
                &param_compression_name,
                KeyKind::CompressedCompressionKey,
                "CompressedCompressionKey",
                &mut benchmark_test_result,
            );
            measure_serialized_size(
                &compressed_decompression_key,
                &param_compression_name,
                KeyKind::CompressedDecompressionKey,
                "CompressedCompressionKey",
                &mut benchmark_test_result,
            );
        }

        if let Some(meta_noise_squashing_param) = meta_params.noise_squashing_parameters {
            let noise_squashing_param = meta_noise_squashing_param.parameters;
            let noise_squash_private_key = NoiseSquashingPrivateKey::new(noise_squashing_param);
            let noise_squash_key = NoiseSquashingKey::new(&cks, &noise_squash_private_key);

            measure_serialized_size(
                &noise_squash_key,
                &noise_squashing_param.name(),
                KeyKind::NoiseSquashingKey,
                "NoiseSquashingKey",
                &mut benchmark_test_result,
            );
            if let Some(noise_squashing_comp_param) =
                meta_noise_squashing_param.compression_parameters
            {
                let noise_squash_comp_private_key =
                    NoiseSquashingCompressionPrivateKey::new(noise_squashing_comp_param);
                let noise_squash_comp_key = NoiseSquashingCompressionKey::new(
                    &noise_squash_private_key,
                    &noise_squash_comp_private_key,
                );

                measure_serialized_size(
                    &noise_squash_comp_key,
                    &noise_squashing_comp_param.name(),
                    KeyKind::NoiseSquashingCompressionKey,
                    "NoiseSquashingCompressionKey",
                    &mut benchmark_test_result,
                );
            }
        }
    }
}

fn main() {
    let work_dir = std::env::current_dir().unwrap();
    println!("work_dir: {}", std::env::current_dir().unwrap().display());
    // Change workdir so that the location of the keycache matches the one for tests
    let mut new_work_dir = work_dir;
    new_work_dir.push("tfhe-benchmark");
    std::env::set_current_dir(new_work_dir).unwrap();

    let results_file = Path::new("shortint_key_sizes.csv");
    client_server_key_sizes(results_file);
    tuniform_key_set_sizes(results_file);
}
