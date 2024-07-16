#[path = "../../benches/utilities.rs"]
mod utilities;

use crate::utilities::{write_to_json, CryptoParametersRecord, OperatorType};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use tfhe::keycache::NamedParam;
use tfhe::shortint::keycache::KEY_CACHE;
use tfhe::shortint::parameters::compact_public_key_only::PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
use tfhe::shortint::parameters::key_switching::PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
use tfhe::shortint::parameters::list_compression::COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
use tfhe::shortint::parameters::{
    PARAM_MESSAGE_1_CARRY_1_KS_PBS, PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64, PARAM_MESSAGE_3_CARRY_3_KS_PBS,
    PARAM_MESSAGE_4_CARRY_4_KS_PBS, PARAM_MULTI_BIT_MESSAGE_1_CARRY_1_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_1_CARRY_1_GROUP_3_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS,
};
use tfhe::shortint::{
    ClassicPBSParameters, ClientKey, CompactPrivateKey, CompressedCompactPublicKey,
    CompressedKeySwitchingKey, CompressedServerKey, PBSParameters,
};

fn write_result(file: &mut File, name: &str, value: usize) {
    let line = format!("{name},{value}\n");
    let error_message = format!("cannot write {name} result into file");
    file.write_all(line.as_bytes()).expect(&error_message);
}

fn client_server_key_sizes(results_file: &Path) {
    let shortint_params_vec: Vec<PBSParameters> = vec![
        PARAM_MESSAGE_1_CARRY_1_KS_PBS.into(),
        PARAM_MESSAGE_2_CARRY_2_KS_PBS.into(),
        PARAM_MESSAGE_3_CARRY_3_KS_PBS.into(),
        PARAM_MESSAGE_4_CARRY_4_KS_PBS.into(),
        PARAM_MULTI_BIT_MESSAGE_1_CARRY_1_GROUP_2_KS_PBS.into(),
        PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS.into(),
        PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS.into(),
        PARAM_MULTI_BIT_MESSAGE_1_CARRY_1_GROUP_3_KS_PBS.into(),
        PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS.into(),
        PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS.into(),
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
        let sks = keys.server_key();
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
        let bsk_compressed_size = sks_compressed
            .bootstrapping_key
            .bootstrapping_key_size_bytes();
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
            sks_compressed
                .bootstrapping_key
                .bootstrapping_key_size_elements(),
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
    let test_name = format!("shortint_key_sizes_{}_{}", param_name, test_name_suffix);
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

    println!(
        "{} {} -> size: {} bytes",
        test_name_suffix, param_name, size,
    );
}

fn tuniform_key_set_sizes(results_file: &Path) {
    File::create(results_file).expect("create results file failed");
    let mut file = OpenOptions::new()
        .append(true)
        .open(results_file)
        .expect("cannot open results file");

    println!("Measuring shortint key sizes:");

    let param_fhe = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
    let param_fhe_name = param_fhe.name();
    let cks = ClientKey::new(param_fhe);
    let compressed_sks = CompressedServerKey::new(&cks);
    let sks = compressed_sks.decompress();

    measure_serialized_size(
        &sks.key_switching_key,
        <ClassicPBSParameters as Into<PBSParameters>>::into(param_fhe),
        &param_fhe_name,
        "ksk",
        "KSK",
        &mut file,
    );
    measure_serialized_size(
        &compressed_sks.key_switching_key,
        <ClassicPBSParameters as Into<PBSParameters>>::into(param_fhe),
        &param_fhe_name,
        "ksk_compressed",
        "KSK",
        &mut file,
    );

    measure_serialized_size(
        &sks.bootstrapping_key,
        <ClassicPBSParameters as Into<PBSParameters>>::into(param_fhe),
        &param_fhe_name,
        "bsk",
        "BSK",
        &mut file,
    );
    measure_serialized_size(
        &compressed_sks.bootstrapping_key,
        <ClassicPBSParameters as Into<PBSParameters>>::into(param_fhe),
        &param_fhe_name,
        "bsk_compressed",
        "BSK",
        &mut file,
    );

    let param_pke = PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
    let param_pke_name = stringify!(PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64);
    let compact_private_key = CompactPrivateKey::new(param_pke);
    let compressed_pk = CompressedCompactPublicKey::new(&compact_private_key);
    let pk = compressed_pk.decompress();

    measure_serialized_size(&pk, param_pke, param_pke_name, "cpk", "CPK", &mut file);
    measure_serialized_size(
        &compressed_pk,
        param_pke,
        param_pke_name,
        "cpk_compressed",
        "CPK",
        &mut file,
    );

    let param_compression = COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
    let param_compression_name = stringify!(COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64);

    let private_compression_key = cks.new_compression_private_key(param_compression);
    let (compression_key, decompression_key) =
        cks.new_compression_decompression_keys(&private_compression_key);

    measure_serialized_size(
        &compression_key,
        param_compression,
        param_compression_name,
        "compression_key",
        "CompressionKey",
        &mut file,
    );
    measure_serialized_size(
        &decompression_key,
        param_compression,
        param_compression_name,
        "decompression_key",
        "CompressionKey",
        &mut file,
    );

    let param_casting = PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
    let param_casting_name = stringify!(PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64);
    let compressed_casting_key = CompressedKeySwitchingKey::new(
        (&compact_private_key, None),
        (&cks, &compressed_sks),
        param_casting,
    );
    let casting_key = compressed_casting_key.decompress();

    measure_serialized_size(
        &casting_key.into_raw_parts().0,
        param_casting,
        param_casting_name,
        "casting_key",
        "CastKey",
        &mut file,
    );
    measure_serialized_size(
        &compressed_casting_key.into_raw_parts().0,
        param_casting,
        param_casting_name,
        "casting_key_compressed",
        "CastKey",
        &mut file,
    );
}

fn main() {
    let work_dir = std::env::current_dir().unwrap();
    println!("work_dir: {}", std::env::current_dir().unwrap().display());
    // Change workdir so that the location of the keycache matches the one for tests
    let mut new_work_dir = work_dir;
    new_work_dir.push("tfhe");
    std::env::set_current_dir(new_work_dir).unwrap();

    let results_file = Path::new("shortint_key_sizes.csv");
    client_server_key_sizes(results_file);
    tuniform_key_set_sizes(results_file);
}
