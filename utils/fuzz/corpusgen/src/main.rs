use std::fs::File;

use fuzz_utils::{
    AUX_MAX_SIZE, AuxDataDir, CorpusDir, FUZZ_DOMAIN_SEPARATOR, INSECURE_FUZZ_COMPRESSION_PARAMS,
    INSECURE_FUZZ_KS_PARAMS, INSECURE_FUZZ_PARAMS, INSECURE_FUZZ_PKE_PARAMS,
};
use tfhe::core_crypto::prelude::*;
use tfhe::safe_serialization::safe_serialize;
use tfhe::{CompactCiphertextList, CompactPublicKey, ConfigBuilder, generate_keys};

fn main() {
    let config = ConfigBuilder::with_custom_parameters(INSECURE_FUZZ_PARAMS)
        .use_dedicated_compact_public_key_parameters((
            INSECURE_FUZZ_PKE_PARAMS,
            INSECURE_FUZZ_KS_PARAMS,
        ))
        .enable_compression(INSECURE_FUZZ_COMPRESSION_PARAMS)
        .build();
    let (client_key, server_key) = generate_keys(config);
    let compact_pub_key = CompactPublicKey::new(&client_key);

    let mut compact_builder = CompactCiphertextList::builder(&compact_pub_key);
    compact_builder.push(1u8).push(2u8).push(137u8).push(54u8);

    let crs = CompactPkeCrs::from_config(config, 32).unwrap();

    let compact_list = compact_builder
        .build_with_proof_packed(&crs, FUZZ_DOMAIN_SEPARATOR, ZkComputeLoad::Verify)
        .unwrap();

    let corpus_dir = CorpusDir::new();
    std::fs::create_dir_all(&corpus_dir).unwrap();

    let f = File::create(corpus_dir.input_path()).unwrap();
    safe_serialize(&compact_list, f, AUX_MAX_SIZE).unwrap();

    let aux_dir = AuxDataDir::new();
    std::fs::create_dir_all(&aux_dir).unwrap();

    let f = File::create(aux_dir.server_key_path()).unwrap();
    safe_serialize(&server_key, f, AUX_MAX_SIZE).unwrap();

    let f = File::create(aux_dir.crs_path()).unwrap();
    safe_serialize(&crs, f, AUX_MAX_SIZE).unwrap();

    let f = File::create(aux_dir.public_key_path()).unwrap();
    safe_serialize(&compact_pub_key, f, AUX_MAX_SIZE).unwrap();
}
