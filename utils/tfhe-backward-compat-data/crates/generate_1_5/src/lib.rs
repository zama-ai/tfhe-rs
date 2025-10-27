mod utils;

use std::borrow::Cow;
use std::fs::create_dir_all;
use std::path::Path;
use tfhe::boolean::engine::BooleanEngine;
use tfhe::core_crypto::commons::generators::DeterministicSeeder;
use tfhe::core_crypto::prelude::DefaultRandomGenerator;
use tfhe::shortint::engine::ShortintEngine;
use tfhe::zk::{CompactPkeCrs, ZkComputeLoad};
use tfhe::{
    ClientKey, CompactPublicKey, CompressedServerKey, ProvenCompactCiphertextList, Seed, ServerKey,
    set_server_key,
};
use tfhe_backward_compat_data::generate::*;
use tfhe_backward_compat_data::*;
use utils::*;

const HL_CLIENTKEY_TEST: HlClientKeyTest = HlClientKeyTest {
    test_filename: Cow::Borrowed("client_key"),
    parameters: INSECURE_SMALL_TEST_PARAMS_MS_MEAN_COMPENSATION,
};

const HL_COMPRESSED_SERVERKEY_TEST: HlServerKeyTest = HlServerKeyTest {
    test_filename: Cow::Borrowed("compressed_server_key"),
    client_key_filename: Cow::Borrowed("client_key.cbor"),
    rerand_cpk_filename: None,
    compressed: true,
};

const HL_SERVERKEY_WITH_COMPRESSION_TEST: HlServerKeyTest = HlServerKeyTest {
    test_filename: Cow::Borrowed("server_key_with_compression"),
    client_key_filename: Cow::Borrowed("client_key.cbor"),
    rerand_cpk_filename: None,
    compressed: false,
};

// We have a proven list generated for 0.11, but since this version the hash modes have evolved so
// we re generate one
const HL_PROVEN_COMPACTLIST_TEST_ZKV2: HlHeterogeneousCiphertextListTest =
    HlHeterogeneousCiphertextListTest {
        test_filename: Cow::Borrowed("hl_proven_list_zkv2_1_5"),
        key_filename: Cow::Borrowed("client_key_for_zk"),
        clear_values: Cow::Borrowed(&[17u8 as u64]),
        data_kinds: Cow::Borrowed(&[DataKind::Unsigned]),
        compressed: false,
        proof_info: Some(PkeZkProofAuxiliaryInfo {
            public_key_filename: Cow::Borrowed("public_key"),
            params_filename: Cow::Borrowed("zk_pke_crs"),
            metadata: Cow::Borrowed("2vdrawkcab"),
        }),
    };

pub struct V1_5;

impl TfhersVersion for V1_5 {
    const VERSION_NUMBER: &'static str = "1.5";

    fn seed_prng(seed: u128) {
        let mut seeder = DeterministicSeeder::<DefaultRandomGenerator>::new(Seed(seed));
        let shortint_engine = ShortintEngine::new_from_seeder(&mut seeder);
        ShortintEngine::with_thread_local_mut(|local_engine| {
            let _ = std::mem::replace(local_engine, shortint_engine);
        });

        let boolean_engine = BooleanEngine::new_from_seeder(&mut seeder);
        BooleanEngine::replace_thread_local(boolean_engine);
    }

    fn gen_shortint_data<P: AsRef<Path>>(_base_data_dir: P) -> Vec<TestMetadata> {
        Vec::new()
    }

    fn gen_hl_data<P: AsRef<Path>>(base_data_dir: P) -> Vec<TestMetadata> {
        let dir = Self::data_dir(base_data_dir).join(HL_MODULE_NAME);
        create_dir_all(&dir).unwrap();

        {
            let config =
                tfhe::ConfigBuilder::with_custom_parameters(HL_CLIENTKEY_TEST.parameters.convert())
                    .enable_compression(
                        INSECURE_TEST_PARAMS_TUNIFORM_COMPRESSION_MULTIBIT.convert(),
                    )
                    .build();
            let (hl_client_key, hl_server_key) = tfhe::generate_keys(config);
            let compressed_server_key = CompressedServerKey::new(&hl_client_key);

            store_versioned_test(&hl_client_key, &dir, &HL_CLIENTKEY_TEST.test_filename);
            store_versioned_test(
                &compressed_server_key,
                &dir,
                &HL_COMPRESSED_SERVERKEY_TEST.test_filename,
            );
            store_versioned_test(
                &hl_server_key,
                &dir,
                &HL_SERVERKEY_WITH_COMPRESSION_TEST.test_filename,
            );
        }

        // Generate a zk proof with the new hash modes
        {
            let config = tfhe::ConfigBuilder::with_custom_parameters(
                INSECURE_SMALL_TEST_PARAMS_KS32.convert(),
            )
            .use_dedicated_compact_public_key_parameters((
                INSECURE_DEDICATED_CPK_TEST_PARAMS.convert(),
                KS_TO_SMALL_TEST_PARAMS.convert(),
            ))
            .build();
            let hl_client_key = ClientKey::generate(config);
            let hl_server_key = ServerKey::new(&hl_client_key);
            set_server_key(hl_server_key.clone());
            let compact_pub_key = CompactPublicKey::new(&hl_client_key);
            let crs = CompactPkeCrs::from_config(config, 64).unwrap();

            store_versioned_auxiliary(
                &crs,
                &dir,
                &HL_PROVEN_COMPACTLIST_TEST_ZKV2
                    .proof_info
                    .unwrap()
                    .params_filename,
            );

            // Store the associated client key to be able to decrypt the ciphertexts in the list
            store_versioned_auxiliary(
                &hl_client_key,
                &dir,
                &HL_PROVEN_COMPACTLIST_TEST_ZKV2.key_filename,
            );

            store_versioned_auxiliary(
                &compact_pub_key,
                &dir,
                &HL_PROVEN_COMPACTLIST_TEST_ZKV2
                    .proof_info
                    .unwrap()
                    .public_key_filename,
            );

            let mut proven_builder = ProvenCompactCiphertextList::builder(&compact_pub_key);
            proven_builder.push(HL_PROVEN_COMPACTLIST_TEST_ZKV2.clear_values[0] as u8);

            let proven_list_packed = proven_builder
                .build_with_proof_packed(
                    &crs,
                    HL_PROVEN_COMPACTLIST_TEST_ZKV2
                        .proof_info
                        .unwrap()
                        .metadata
                        .as_bytes(),
                    ZkComputeLoad::Proof,
                )
                .unwrap();

            store_versioned_test(
                &proven_list_packed,
                &dir,
                &HL_PROVEN_COMPACTLIST_TEST_ZKV2.test_filename,
            );
        }

        vec![
            TestMetadata::HlClientKey(HL_CLIENTKEY_TEST),
            TestMetadata::HlServerKey(HL_COMPRESSED_SERVERKEY_TEST),
            TestMetadata::HlServerKey(HL_SERVERKEY_WITH_COMPRESSION_TEST),
            TestMetadata::HlHeterogeneousCiphertextList(HL_PROVEN_COMPACTLIST_TEST_ZKV2),
        ]
    }
}
