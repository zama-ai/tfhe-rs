use std::fs::File;

use fuzz_utils::{
    AUX_MAX_SIZE, AuxDataDir, CorpusDir, FUZZ_DOMAIN_SEPARATOR, INSECURE_FUZZ_GPU_KS_PARAMS,
    INSECURE_FUZZ_GPU_PARAMS, INSECURE_FUZZ_GPU_PKE_PARAMS,
};
use tfhe::core_crypto::prelude::*;
use tfhe::safe_serialization::safe_serialize;
use tfhe::{CompactCiphertextList, CompactPublicKey, ConfigBuilder, generate_keys};

fn main() {
    let config = ConfigBuilder::with_custom_parameters(INSECURE_FUZZ_GPU_PARAMS)
        .use_dedicated_compact_public_key_parameters((
            INSECURE_FUZZ_GPU_PKE_PARAMS,
            INSECURE_FUZZ_GPU_KS_PARAMS,
        ))
        .build();
    let (client_key, _) = generate_keys(config);
    let compact_pub_key = CompactPublicKey::new(&client_key);

    let mut compact_builder = CompactCiphertextList::builder(&compact_pub_key);
    compact_builder.push(1u8).push(2u8).push(137u8).push(54u8);

    let crs = CompactPkeCrs::from_config(config, 32).unwrap();

    let compact_list = compact_builder
        .build_with_proof_packed(&crs, FUZZ_DOMAIN_SEPARATOR, ZkComputeLoad::Verify)
        .unwrap();

    let corpus_dir = CorpusDir::new();
    std::fs::create_dir_all(&corpus_dir).unwrap();
    let f = File::create(corpus_dir.gpu_input_path()).unwrap();
    safe_serialize(&compact_list, f, AUX_MAX_SIZE).unwrap();

    let aux_dir = AuxDataDir::new();
    std::fs::create_dir_all(&aux_dir).unwrap();

    let f = File::create(aux_dir.gpu_client_key_path()).unwrap();
    safe_serialize(&client_key, f, AUX_MAX_SIZE).unwrap();

    let f = File::create(aux_dir.gpu_crs_path()).unwrap();
    safe_serialize(&crs, f, AUX_MAX_SIZE).unwrap();

    let f = File::create(aux_dir.gpu_public_key_path()).unwrap();
    safe_serialize(&compact_pub_key, f, AUX_MAX_SIZE).unwrap();
}
