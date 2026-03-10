mod utils;
use utils::*;

use std::borrow::Cow;
use std::fs::create_dir_all;
use std::path::Path;

use tfhe::boolean::engine::BooleanEngine;
use tfhe::core_crypto::commons::generators::DeterministicSeeder;
use tfhe::core_crypto::prelude::{DefaultRandomGenerator, NormalizedHammingWeightBound};
use tfhe::shortint::engine::ShortintEngine;
use tfhe::xof_key_set::CompressedXofKeySet;
use tfhe::zk::{CompactPkeCrs, ZkComputeLoad};
use tfhe::{
    set_server_key, ClientKey, CompactCiphertextList, CompactPublicKey, CompressedCompactPublicKey,
    CompressedServerKey, ProvenCompactCiphertextList, Seed, ServerKey, Tag,
};
use tfhe_backward_compat_data::generate::*;
use tfhe_backward_compat_data::*;

const HL_COMPRESSED_XOF_KEY_SET_TEST: HlCompressedXofKeySetTest = HlCompressedXofKeySetTest {
    compressed_xof_key_set_file_name: Cow::Borrowed("compressed_xof_key_set"),
    client_key_file_name: Cow::Borrowed("xof_client_key"),
};

const HL_SERVER_KEY_TEST: HlServerKeyTest = HlServerKeyTest {
    test_filename: Cow::Borrowed("server_key_complete"),
    client_key_filename: Cow::Borrowed("client_key_complete"),
    rerand_cpk_filename: Some(Cow::Borrowed("cpk_rerand_complete")),
    compressed: true,
};
const SEEDED_COMPACT_LIST_SEED: &[u8] = &167644343036794213320094654445260117732u128.to_le_bytes();

const HL_SEEDED_COMPACT_LIST_TEST: HlSeededCompactCiphertextListTest =
    HlSeededCompactCiphertextListTest {
        test_filename: Cow::Borrowed("hl_seeded_compact_list"),
        key_filename: Cow::Borrowed("seeded_client_key"),
        public_key_filename: Cow::Borrowed("seeded_compact_public_key"),
        clear_values: Cow::Borrowed(&[17u64, 255u64, 0u64]),
        data_kinds: Cow::Borrowed(&[DataKind::Unsigned, DataKind::Signed, DataKind::Bool]),
        seed: Cow::Borrowed(SEEDED_COMPACT_LIST_SEED),
    };

const HL_SEEDED_PROVEN_COMPACT_LIST_TEST: HlSeededProvenCompactCiphertextListTest =
    HlSeededProvenCompactCiphertextListTest {
        test_filename: Cow::Borrowed("hl_seeded_proven_compact_list"),
        key_filename: Cow::Borrowed("seeded_proven_client_key"),
        public_key_filename: Cow::Borrowed("seeded_proven_compact_public_key"),
        proof_info: ZkProofAuxiliaryInfo {
            params_filename: Cow::Borrowed("seeded_proven_zk_pke_crs"),
            metadata: Cow::Borrowed("backward_compat_seeded"),
        },
        clear_values: Cow::Borrowed(&[17u64, 255u64, 0u64]),
        data_kinds: Cow::Borrowed(&[DataKind::Unsigned, DataKind::Signed, DataKind::Bool]),
        seed: Cow::Borrowed(SEEDED_COMPACT_LIST_SEED),
    };

pub struct V1_6;

impl TfhersVersion for V1_6 {
    const VERSION_NUMBER: &'static str = "1.6";

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
            let seed_bytes = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
            let security_bits = 128;
            let max_norm_hwt = NormalizedHammingWeightBound::new(0.8).unwrap();
            let (hl_client_key, hl_xof_key_set) = CompressedXofKeySet::generate(
                INSECURE_TEST_NO_KS_RERAND_META_PARAMS.convert().into(),
                seed_bytes,
                security_bits,
                max_norm_hwt,
                Tag::default(),
            )
            .expect("Failed to generate xof key set");

            store_versioned_auxiliary(
                &hl_client_key,
                &dir,
                &HL_COMPRESSED_XOF_KEY_SET_TEST.client_key_file_name,
            );
            store_versioned_test(
                &hl_xof_key_set,
                &dir,
                &HL_COMPRESSED_XOF_KEY_SET_TEST.test_filename(),
            );
        }

        {
            // The CSPRNG had a bug fix in 1.6, so we generate a complete ServerKey
            let meta_params = INSECURE_TEST_NO_KS_RERAND_META_PARAMS.convert();
            let client_key = ClientKey::generate(meta_params);
            let compressed_server_key = CompressedServerKey::new(&client_key);
            let cpk = CompressedCompactPublicKey::new(&client_key);

            store_versioned_auxiliary(&client_key, &dir, &HL_SERVER_KEY_TEST.client_key_filename);
            store_versioned_auxiliary(&cpk, &dir, &HL_SERVER_KEY_TEST.rerand_cpk_filename.unwrap());
            store_versioned_test(
                &compressed_server_key,
                &dir,
                &HL_SERVER_KEY_TEST.test_filename(),
            );
        }

        // Generate seeded compact ciphertext list (no proof)
        {
            let config = tfhe::ConfigBuilder::with_custom_parameters(
                INSECURE_SMALL_TEST_PARAMS_MS_MEAN_COMPENSATION_LWE_DIM_64.convert(),
            )
            .build();
            let hl_client_key = ClientKey::generate(config);
            let hl_server_key = ServerKey::new(&hl_client_key);
            set_server_key(hl_server_key);
            let compact_pub_key = CompactPublicKey::new(&hl_client_key);

            store_versioned_auxiliary(
                &hl_client_key,
                &dir,
                &HL_SEEDED_COMPACT_LIST_TEST.key_filename,
            );
            store_versioned_auxiliary(
                &compact_pub_key,
                &dir,
                &HL_SEEDED_COMPACT_LIST_TEST.public_key_filename,
            );

            let mut builder = CompactCiphertextList::builder(&compact_pub_key);
            for (value, kind) in HL_SEEDED_COMPACT_LIST_TEST
                .clear_values
                .iter()
                .zip(HL_SEEDED_COMPACT_LIST_TEST.data_kinds.iter())
            {
                match kind {
                    DataKind::Unsigned => {
                        builder.push(*value as u8);
                    }
                    DataKind::Signed => {
                        builder.push(*value as i8);
                    }
                    DataKind::Bool => {
                        builder.push(*value != 0);
                    }
                }
            }

            let list = builder
                .build_packed_seeded(&HL_SEEDED_COMPACT_LIST_TEST.seed)
                .unwrap();
            store_versioned_test(&list, &dir, &HL_SEEDED_COMPACT_LIST_TEST.test_filename());
        }

        // Generate seeded proven compact ciphertext list
        {
            let config = tfhe::ConfigBuilder::with_custom_parameters(
                INSECURE_SMALL_TEST_PARAMS_MS_MEAN_COMPENSATION_LWE_DIM_64.convert(),
            )
            .use_dedicated_compact_public_key_parameters((
                INSECURE_DEDICATED_CPK_TEST_PARAMS.convert(),
                KS_TO_SMALL_TEST_PARAMS.convert(),
            ))
            .build();
            let hl_client_key = ClientKey::generate(config);
            let hl_server_key = ServerKey::new(&hl_client_key);
            set_server_key(hl_server_key);
            let compact_pub_key = CompactPublicKey::new(&hl_client_key);
            let crs = CompactPkeCrs::from_config(config, 64).unwrap();

            store_versioned_auxiliary(
                &hl_client_key,
                &dir,
                &HL_SEEDED_PROVEN_COMPACT_LIST_TEST.key_filename,
            );
            store_versioned_auxiliary(
                &compact_pub_key,
                &dir,
                &HL_SEEDED_PROVEN_COMPACT_LIST_TEST.public_key_filename,
            );
            store_versioned_auxiliary(
                &crs,
                &dir,
                &HL_SEEDED_PROVEN_COMPACT_LIST_TEST
                    .proof_info
                    .params_filename,
            );

            let mut proven_builder = ProvenCompactCiphertextList::builder(&compact_pub_key);
            for (value, kind) in HL_SEEDED_PROVEN_COMPACT_LIST_TEST
                .clear_values
                .iter()
                .zip(HL_SEEDED_PROVEN_COMPACT_LIST_TEST.data_kinds.iter())
            {
                match kind {
                    DataKind::Unsigned => {
                        proven_builder.push(*value as u8);
                    }
                    DataKind::Signed => {
                        proven_builder.push(*value as i8);
                    }
                    DataKind::Bool => {
                        proven_builder.push(*value != 0);
                    }
                }
            }

            let proven_list = proven_builder
                .build_with_proof_packed_seeded(
                    &crs,
                    HL_SEEDED_PROVEN_COMPACT_LIST_TEST
                        .proof_info
                        .metadata
                        .as_bytes(),
                    ZkComputeLoad::Proof,
                    &HL_SEEDED_PROVEN_COMPACT_LIST_TEST.seed,
                )
                .unwrap();

            store_versioned_test(
                &proven_list,
                &dir,
                &HL_SEEDED_PROVEN_COMPACT_LIST_TEST.test_filename(),
            );
        }

        vec![
            TestMetadata::HlCompressedXofKeySet(HL_COMPRESSED_XOF_KEY_SET_TEST),
            TestMetadata::HlServerKey(HL_SERVER_KEY_TEST),
            TestMetadata::HlSeededCompactCiphertextList(HL_SEEDED_COMPACT_LIST_TEST),
            TestMetadata::HlSeededProvenCompactCiphertextList(HL_SEEDED_PROVEN_COMPACT_LIST_TEST),
        ]
    }
}
