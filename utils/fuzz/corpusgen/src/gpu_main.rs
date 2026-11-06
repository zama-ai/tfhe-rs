use std::fs::File;

use fuzz_utils::{
    AUX_MAX_SIZE, AuxDataDir, CorpusDir, FUZZ_DOMAIN_SEPARATOR,
    INSECURE_FUZZ_GPU_COMPRESSION_PARAMS, INSECURE_FUZZ_GPU_KS_PARAMS, INSECURE_FUZZ_GPU_PARAMS,
    INSECURE_FUZZ_GPU_PKE_PARAMS,
};
use tfhe::core_crypto::prelude::*;
use tfhe::integer::U256;
use tfhe::integer::bigint::{U512, U1024, U2048};
use tfhe::safe_serialization::safe_serialize;
use tfhe::{CompactCiphertextList, CompactPublicKey, ConfigBuilder, generate_keys};

fn main() {
    let config = ConfigBuilder::with_custom_parameters(INSECURE_FUZZ_GPU_PARAMS)
        .use_dedicated_compact_public_key_parameters((
            INSECURE_FUZZ_GPU_PKE_PARAMS,
            INSECURE_FUZZ_GPU_KS_PARAMS,
        ))
        .enable_compression(INSECURE_FUZZ_GPU_COMPRESSION_PARAMS)
        .build();
    let (client_key, _) = generate_keys(config);
    let compact_pub_key = CompactPublicKey::new(&client_key);

    let mut compact_builder = CompactCiphertextList::builder(&compact_pub_key);

    // One ciphertext per fhevm backend-ciphertext variant: H (host-exposed) ∪ W (large wrappers).
    // U160 lives in a U256 container with the top 96 bits zero (fhevm eaddress encoding).
    let u160_val = U256::from((1u128, (1u128 << 32) - 1));
    let u256_val = U256::from((2u128, 3u128));
    let u512_val = U512::from([4u64; 8]);
    let u1024_val = U1024::from([5u64; 16]);
    let u2048_val = U2048::from([6u64; 32]);

    compact_builder
        .push(true)
        .push(137u8)
        .push(42069u16)
        .push(123_456_789u32)
        .push(9_876_543_210u64)
        .push(1_000_000_000_000_000_000u128);
    compact_builder.push_with_num_bits(u160_val, 160).unwrap();
    compact_builder
        .push(u256_val)
        .push(u512_val)
        .push(u1024_val)
        .push(u2048_val);

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
