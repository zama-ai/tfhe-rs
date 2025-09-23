use benchmark::params::get_classical_tuniform_groups;
use benchmark::params_aliases::*;
use benchmark::utilities::{write_to_json, CryptoParametersRecord, OperatorType};
use std::fs::{File, OpenOptions};
use std::io::Write;
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

fn write_result(file: &mut File, name: &str, value: usize) {
    let line = format!("{name},{value}\n");
    let error_message = format!("cannot write {name} result into file");
    file.write_all(line.as_bytes()).expect(&error_message);
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
    File::create(results_file).expect("create results file failed");
    let mut file = OpenOptions::new()
        .append(true)
        .open(results_file)
        .expect("cannot open results file");

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
        let test_name = format!("shortint_key_sizes_{}_ksk", params.name());

        write_result(&mut file, &test_name, ksk_size);
        write_to_json::<u64, _>(
            &test_name,
            params,
            params.name(),
            "KSK",
            &operator,
            0,
            vec![],
        );

        println!(
            "Element in KSK: {}, size in bytes: {}",
            sks.key_switching_key_size_elements(),
            ksk_size,
        );

        let bsk_size = sks.bootstrapping_key_size_bytes();
        let test_name = format!("shortint_key_sizes_{}_bsk", params.name());

        write_result(&mut file, &test_name, bsk_size);
        write_to_json::<u64, _>(
            &test_name,
            params,
            params.name(),
            "BSK",
            &operator,
            0,
            vec![],
        );

        println!(
            "Element in BSK: {}, size in bytes: {}",
            sks.bootstrapping_key_size_elements(),
            bsk_size,
        );

        let sks_compressed = CompressedServerKey::new(cks);
        let bsk_compressed_size = sks_compressed.bootstrapping_key_size_bytes();
        let test_name = format!("shortint_key_sizes_{}_bsk_compressed", params.name());

        write_result(&mut file, &test_name, bsk_compressed_size);
        write_to_json::<u64, _>(
            &test_name,
            params,
            params.name(),
            "BSK",
            &operator,
            0,
            vec![],
        );

        println!(
            "Element in BSK compressed: {}, size in bytes: {}",
            sks_compressed.bootstrapping_key_size_elements(),
            bsk_compressed_size,
        );

        // Clear keys as we go to avoid filling the RAM
        KEY_CACHE.clear_in_memory_cache()
    }
}

fn measure_serialized_size<T: serde::Serialize, P: Into<CryptoParametersRecord<u64>> + Clone>(
    to_serialize: &T,
    param: P,
    param_name: &str,
    test_name_suffix: &str,
    display_name: &str,
    file: &mut File,
) {
    let serialized = bincode::serialize(to_serialize).unwrap();
    let size = serialized.len();
    let test_name = format!("shortint_key_sizes_{param_name}_{test_name_suffix}");
    write_result(file, &test_name, size);
    write_to_json::<u64, _>(
        &test_name,
        param.clone(),
        param_name,
        display_name,
        &OperatorType::Atomic,
        0,
        vec![],
    );

    println!("{test_name_suffix} {param_name} -> size: {size} bytes",);
}

fn tuniform_key_set_sizes(results_file: &Path) {
    File::create(results_file).expect("create results file failed");
    let mut file = OpenOptions::new()
        .append(true)
        .open(results_file)
        .expect("cannot open results file");

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
                    compute_param,
                    &param_fhe_name,
                    "ksk",
                    "KSK",
                    &mut file,
                );
                measure_serialized_size(
                    &ap.bootstrapping_key,
                    compute_param,
                    &param_fhe_name,
                    "bsk",
                    "BSK",
                    &mut file,
                );
            }
            AtomicPatternServerKey::KeySwitch32(ap) => {
                measure_serialized_size(
                    &ap.key_switching_key,
                    compute_param,
                    &param_fhe_name,
                    "ksk",
                    "KSK",
                    &mut file,
                );
                measure_serialized_size(
                    &ap.bootstrapping_key,
                    compute_param,
                    &param_fhe_name,
                    "bsk",
                    "BSK",
                    &mut file,
                );
            }
            AtomicPatternServerKey::Dynamic(_) => panic!("Dynamic atomic pattern not supported"),
        }

        match &compressed_sks.compressed_ap_server_key {
            CompressedAtomicPatternServerKey::Standard(comp_ap) => {
                measure_serialized_size(
                    comp_ap.key_switching_key(),
                    compute_param,
                    &param_fhe_name,
                    "ksk_compressed",
                    "KSK",
                    &mut file,
                );
                measure_serialized_size(
                    &comp_ap.bootstrapping_key(),
                    compute_param,
                    &param_fhe_name,
                    "bsk_compressed",
                    "BSK",
                    &mut file,
                );
            }
            CompressedAtomicPatternServerKey::KeySwitch32(comp_ap) => {
                measure_serialized_size(
                    comp_ap.key_switching_key(),
                    compute_param,
                    &param_fhe_name,
                    "ksk_compressed",
                    "KSK",
                    &mut file,
                );
                measure_serialized_size(
                    &comp_ap.bootstrapping_key(),
                    compute_param,
                    &param_fhe_name,
                    "bsk_compressed",
                    "BSK",
                    &mut file,
                );
            }
        }

        if let Some(dedicated_pke_params) = meta_params.dedicated_compact_public_key_parameters {
            let pke_param = dedicated_pke_params.pke_params;
            let param_pke_name = pke_param.name();
            let compact_private_key = CompactPrivateKey::new(pke_param);
            let compressed_pk = CompressedCompactPublicKey::new(&compact_private_key);
            let pk = compressed_pk.decompress();

            measure_serialized_size(&pk, pke_param, &param_pke_name, "cpk", "CPK", &mut file);
            measure_serialized_size(
                &compressed_pk,
                pke_param,
                &param_pke_name,
                "cpk_compressed",
                "CPK",
                &mut file,
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
                casting_param,
                &param_casting_name,
                "casting_key",
                "CastKey",
                &mut file,
            );
            measure_serialized_size(
                &compressed_casting_key.into_raw_parts().0,
                casting_param,
                &param_casting_name,
                "casting_key_compressed",
                "CastKey",
                &mut file,
            );
        }

        if let Some(compression_param) = meta_params.compression_parameters {
            let param_compression_name = compression_param.name();
            let params_tuple = (compression_param, compute_param);

            let private_compression_key = cks.new_compression_private_key(compression_param);
            let (compression_key, decompression_key) =
                cks.new_compression_decompression_keys(&private_compression_key);

            measure_serialized_size(
                &compression_key,
                params_tuple,
                &param_compression_name,
                "compression_key",
                "CompressionKey",
                &mut file,
            );
            measure_serialized_size(
                &decompression_key,
                params_tuple,
                &param_compression_name,
                "decompression_key",
                "CompressionKey",
                &mut file,
            );

            let (compressed_compression_key, compressed_decompression_key) =
                cks.new_compressed_compression_decompression_keys(&private_compression_key);

            measure_serialized_size(
                &compressed_compression_key,
                params_tuple,
                &param_compression_name,
                "compressed_compression_key",
                "CompressedCompressionKey",
                &mut file,
            );
            measure_serialized_size(
                &compressed_decompression_key,
                params_tuple,
                &param_compression_name,
                "compressed_decompression_key",
                "CompressedCompressionKey",
                &mut file,
            );
        }

        if let Some(meta_noise_squashing_param) = meta_params.noise_squashing_parameters {
            let noise_squashing_param = meta_noise_squashing_param.parameters;
            let params_tuple = (noise_squashing_param, compute_param);
            let noise_squash_private_key = NoiseSquashingPrivateKey::new(noise_squashing_param);
            let noise_squash_key = NoiseSquashingKey::new(&cks, &noise_squash_private_key);

            measure_serialized_size(
                &noise_squash_key,
                params_tuple,
                &noise_squashing_param.name(),
                "noise_squashing_key",
                "NoiseSquashingKey",
                &mut file,
            );
            if let Some(noise_squashing_comp_param) =
                meta_noise_squashing_param.compression_parameters
            {
                let params_tuple = (noise_squashing_comp_param, compute_param);
                let noise_squash_comp_private_key =
                    NoiseSquashingCompressionPrivateKey::new(noise_squashing_comp_param);
                let noise_squash_comp_key = NoiseSquashingCompressionKey::new(
                    &noise_squash_private_key,
                    &noise_squash_comp_private_key,
                );

                measure_serialized_size(
                    &noise_squash_comp_key,
                    params_tuple,
                    &noise_squashing_comp_param.name(),
                    "noise_squashing_compression_key",
                    "NoiseSquashingCompressionKey",
                    &mut file,
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
