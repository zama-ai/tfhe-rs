use benchmark::params::{get_classical_tuniform_groups, get_multi_bit_tuniform_groups};
use benchmark::params_aliases::*;
use benchmark::utilities::{write_to_json, OperatorType};
use rand::Rng;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use tfhe::integer::U256;
use tfhe::keycache::NamedParam;
use tfhe::prelude::{FheEncrypt, SquashNoise};
use tfhe::shortint::PBSParameters;
use tfhe::{
    generate_keys, set_server_key, CompactCiphertextList, CompactPublicKey,
    CompressedCiphertextListBuilder, CompressedFheUint64, CompressedServerKey,
    CompressedSquashedNoiseCiphertextList, ConfigBuilder, FheUint64,
};

fn write_result(file: &mut File, name: &str, value: usize) {
    let line = format!("{name},{value}\n");
    let error_message = format!("cannot write {name} result into file");
    file.write_all(line.as_bytes()).expect(&error_message);
}

pub fn ct_sizes(results_file: &Path) {
    let mut rng = rand::rng();

    File::create(results_file).expect("create results file failed");
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(results_file)
        .expect("cannot open results file");

    let operator = OperatorType::Atomic;

    let meta_params = [
        get_classical_tuniform_groups(),
        get_multi_bit_tuniform_groups(),
    ]
    .concat();

    for meta_param in meta_params.iter() {
        let param_fhe = meta_param.compute_parameters;

        if param_fhe.message_modulus().0 > 4 {
            println!(
                "Skipping {} because message modulus is too large",
                param_fhe.name()
            );
            continue;
        }

        println!(
            "Ciphertext sizes for: {} and {} ciphertext",
            param_fhe.name(),
            stringify!(FheUint64)
        );

        let mut config = ConfigBuilder::default().use_custom_parameters(param_fhe);

        if let Some(comp_params) = meta_param.compression_parameters {
            config = config.enable_compression(comp_params);
        }
        if let Some(ns_meta_params) = meta_param.noise_squashing_parameters {
            config = config.enable_noise_squashing(ns_meta_params.parameters);

            if let Some(ns_comp_params) = ns_meta_params.compression_parameters {
                config = config.enable_noise_squashing_compression(ns_comp_params);
            }
        }
        if let Some(cpke_meta_params) = meta_param.dedicated_compact_public_key_parameters {
            config = config.use_dedicated_compact_public_key_parameters((
                cpke_meta_params.pke_params,
                cpke_meta_params.ksk_params,
            ));
        }

        let config = config.build();

        println!("Generating keys...");
        let (client_key, _) = generate_keys(config);

        let compressed_sks = CompressedServerKey::new(&client_key);
        set_server_key(compressed_sks.decompress());

        let params_record = param_fhe;

        let mut write_and_record_result = |res: usize, test_name: &str, display_name: &str| {
            write_result(&mut file, test_name, res);
            write_to_json::<u64, _>(
                test_name,
                params_record,
                param_fhe.name(),
                display_name,
                &operator,
                0,
                vec![],
            );
        };

        let plaintext = rng.gen::<u64>();

        let test_name = format!("hlapi_ct_size::{}", param_fhe.name());
        let regular_ct = FheUint64::encrypt(plaintext, &client_key);
        let regular_ct_size = bincode::serialize(&regular_ct).unwrap().len();
        println!("\t* Regular CT: {regular_ct_size} bytes");
        write_and_record_result(regular_ct_size, &test_name, "ct-size");

        let test_name = format!("hlapi_seeded_ct_size::{}", param_fhe.name());
        let seeded_ct = CompressedFheUint64::encrypt(plaintext, &client_key);
        let seeded_ct_size = bincode::serialize(&seeded_ct).unwrap().len();
        println!("\t* Seeded CT: {seeded_ct_size} bytes");
        write_and_record_result(seeded_ct_size, &test_name, "seeded-ct-size");

        let test_name = format!("hlapi_ms_compressed_ct_size::{}", param_fhe.name());
        let ms_compressed_ct = regular_ct.compress();
        let ms_compressed_ct_size = bincode::serialize(&ms_compressed_ct).unwrap().len();
        println!("\t* Compressed with ModSwitch only CT: {ms_compressed_ct_size} bytes");
        write_and_record_result(ms_compressed_ct_size, &test_name, "ms-compressed-ct-size");

        if meta_param.compression_parameters.is_some() {
            let test_name = format!("hlapi_compressed_ct_size::{}", param_fhe.name());
            let compressed_ct = CompressedCiphertextListBuilder::new()
                .push(regular_ct.clone())
                .build()
                .unwrap();
            let compressed_ct_size = bincode::serialize(&compressed_ct).unwrap().len();
            println!("\t* Compressed CT: {compressed_ct_size} bytes");
            write_and_record_result(compressed_ct_size, &test_name, "compressed-ct-size");
        }

        if meta_param.noise_squashing_parameters.is_some() {
            let test_name = format!("hlapi_sns_ct_size::{}", param_fhe.name());
            let sns_ct = regular_ct.squash_noise().unwrap();
            let sns_ct_size = bincode::serialize(&sns_ct).unwrap().len();
            println!("\t* SNS CT: {sns_ct_size} bytes");
            write_and_record_result(sns_ct_size, &test_name, "sns-ct-size");

            if let Some(ns_params) = meta_param.noise_squashing_parameters {
                if ns_params.compression_parameters.is_some() {
                    let test_name = format!("hlapi_compressed_sns_ct_size::{}", param_fhe.name());
                    let compressed_sns_ct = CompressedSquashedNoiseCiphertextList::builder()
                        .push(sns_ct)
                        .build()
                        .unwrap();
                    let compressed_sns_ct_size =
                        bincode::serialize(&compressed_sns_ct).unwrap().len();
                    println!("\t* Compressed SNS CT: {compressed_sns_ct_size} bytes");
                    write_and_record_result(
                        compressed_sns_ct_size,
                        &test_name,
                        "compressed-sns-ct-size",
                    );
                }
            }
        }

        if meta_param.dedicated_compact_public_key_parameters.is_some() {
            let test_name = format!("hlapi_cpk_ct_size::{}", param_fhe.name());
            let public_key = CompactPublicKey::new(&client_key);
            let cpk_ct = CompactCiphertextList::builder(&public_key)
                .push(plaintext)
                .build();
            let cpk_ct_size = bincode::serialize(&cpk_ct).unwrap().len();
            println!("\t* CPK CT: {cpk_ct_size} bytes");
            write_and_record_result(cpk_ct_size, &test_name, "cpk-ct-size");
        }
    }
}

pub fn cpk_and_cctl_sizes(results_file: &Path) {
    const NB_CTXT: usize = 5;

    let mut rng = rand::rng();

    File::create(results_file).expect("create results file failed");
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(results_file)
        .expect("cannot open results file");

    let operator = OperatorType::Atomic;

    {
        let params = BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let config = ConfigBuilder::default()
            .use_custom_parameters(params)
            .use_dedicated_compact_public_key_parameters((
                BENCH_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
                BENCH_PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            ))
            .build();
        let (client_key, _) = generate_keys(config);
        let test_name = format!("hlapi_sizes_{}_cpk", params.name());

        let params: PBSParameters = params.into();

        println!("Sizes for: {} and 32 bits", params.name());

        let public_key = CompactPublicKey::new(&client_key);

        let cpk_size = bincode::serialize(&public_key).unwrap().len();

        println!("PK size: {cpk_size} bytes");
        write_result(&mut file, &test_name, cpk_size);
        write_to_json::<u64, _>(
            &test_name,
            params,
            params.name(),
            "CPK",
            &operator,
            0,
            vec![],
        );

        let test_name = format!("hlapi_sizes_{}_cctl_{NB_CTXT}_len_32_bits", params.name());

        let vec_inputs: Vec<_> = (0..NB_CTXT).map(|_| rng.gen::<u32>()).collect();

        let encrypted_inputs = CompactCiphertextList::builder(&public_key)
            .extend(vec_inputs.iter().copied())
            .build();
        let cctl_size = bincode::serialize(&encrypted_inputs).unwrap().len();

        println!("Compact CT list for {NB_CTXT} CTs: {cctl_size} bytes");

        write_result(&mut file, &test_name, cctl_size);
        write_to_json::<u64, _>(
            &test_name,
            params,
            params.name(),
            "CCTL",
            &operator,
            0,
            vec![],
        );
    }

    // 256 bits
    {
        let params = BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let config = ConfigBuilder::default()
            .use_custom_parameters(params)
            .use_dedicated_compact_public_key_parameters((
                BENCH_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
                BENCH_PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            ))
            .build();
        let (client_key, _) = generate_keys(config);

        let params: PBSParameters = params.into();

        println!("Sizes for: {} and 256 bits", params.name());

        let public_key = CompactPublicKey::new(&client_key);

        println!(
            "PK size: {} bytes",
            bincode::serialize(&public_key).unwrap().len()
        );

        let test_name = format!("hlapi_sizes_{}_cctl_{NB_CTXT}_len_256_bits", params.name());

        let vec_inputs: Vec<_> = (0..NB_CTXT).map(|_| U256::from(rng.gen::<u32>())).collect();

        let encrypted_inputs = CompactCiphertextList::builder(&public_key)
            .extend(vec_inputs.iter().copied())
            .build();
        let cctl_size = bincode::serialize(&encrypted_inputs).unwrap().len();

        println!("Compact CT list for {NB_CTXT} CTs: {cctl_size} bytes");

        write_result(&mut file, &test_name, cctl_size);
        write_to_json::<u64, _>(
            &test_name,
            params,
            params.name(),
            "CCTL",
            &operator,
            0,
            vec![],
        );
    }
}

fn main() {
    let work_dir = std::env::current_dir().unwrap();
    println!("work_dir: {}", std::env::current_dir().unwrap().display());
    // Change workdir so that the location of the keycache matches the one for tests
    let mut new_work_dir = work_dir;
    new_work_dir.push("tfhe-benchmark");
    std::env::set_current_dir(new_work_dir).unwrap();

    let results_file = Path::new("hlapi_ct_key_sizes.csv");
    ct_sizes(results_file);
    cpk_and_cctl_sizes(results_file)
}
