mod utils;
use tfhe::boolean::engine::BooleanEngine;
use tfhe::core_crypto::commons::generators::DeterministicSeeder;
use tfhe::core_crypto::prelude::DefaultRandomGenerator;
use tfhe::prelude::{FheEncrypt, SquashNoise};
use tfhe::shortint::engine::ShortintEngine;
use tfhe::{
    ClientKey, CompressedCompactPublicKey, CompressedServerKey, ConfigBuilder, FheUint32,
    FheUint64, KVStore, Seed, ServerKey, set_server_key,
};
use utils::*;

use std::borrow::Cow;
use std::collections::HashMap;
use std::fs::create_dir_all;
use std::path::Path;

use tfhe_backward_compat_data::generate::*;
use tfhe_backward_compat_data::*;

const TEST_FILENAME: Cow<'static, str> = Cow::Borrowed("client_key_with_noise_squashing");

const HL_CLIENTKEY_WITH_NOISE_SQUASHING_TEST: HlClientKeyTest = HlClientKeyTest {
    test_filename: TEST_FILENAME,
    parameters: INSECURE_SMALL_TEST_PARAMS_MULTI_BIT,
};

const HL_SERVERKEY_TEST: HlServerKeyTest = HlServerKeyTest {
    test_filename: Cow::Borrowed("server_key_with_noise_squashing"),
    client_key_filename: TEST_FILENAME,
    rerand_cpk_filename: None,
    compressed: false,
};

const HL_SQUASHED_NOISE_UNSIGNED_CIPHERTEXT_TEST: HlSquashedNoiseUnsignedCiphertextTest =
    HlSquashedNoiseUnsignedCiphertextTest {
        test_filename: Cow::Borrowed("squashed_noise_unsigned_ciphertext"),
        key_filename: TEST_FILENAME,
        clear_value: 42,
    };

const HL_SERVERKEY_RERAND_TEST: HlServerKeyTest = HlServerKeyTest {
    test_filename: Cow::Borrowed("server_key_for_rerand"),
    client_key_filename: Cow::Borrowed("client_key_for_rerand"),
    rerand_cpk_filename: Some(Cow::Borrowed("cpk_for_rerand")),
    compressed: false,
};

const HL_COMPRESSED_KV_STORE_TEST: HlCompressedKVStoreTest = HlCompressedKVStoreTest {
    kv_store_file_name: Cow::Borrowed("compressed_kv_store"),
    client_key_file_name: Cow::Borrowed("client_key_for_kv_store"),
    server_key_file_name: Cow::Borrowed("server_key_for_kv_store"),
    num_elements: 512,
};

const HL_SERVERKEY_KS32_NOISE_SQUASHING_TEST: HlServerKeyTest = HlServerKeyTest {
    test_filename: Cow::Borrowed("server_key_ks32_noise_squashing"),
    client_key_filename: Cow::Borrowed("client_key_ks32_noise_squashing"),
    rerand_cpk_filename: None,
    compressed: false,
};

const HL_COMPRESSED_SERVERKEY_KS32_NOISE_SQUASHING_TEST: HlServerKeyTest = HlServerKeyTest {
    test_filename: Cow::Borrowed("compressed_server_key_ks32_noise_squashing"),
    client_key_filename: Cow::Borrowed("client_key_ks32_noise_squashing"),
    rerand_cpk_filename: None,
    compressed: true,
};

pub struct V1_4;

impl TfhersVersion for V1_4 {
    const VERSION_NUMBER: &'static str = "1.4";

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

        // Test noise squahsing multibit
        {
            let config = ConfigBuilder::with_custom_parameters(
                HL_CLIENTKEY_WITH_NOISE_SQUASHING_TEST.parameters.convert(),
            )
            .enable_noise_squashing(INSECURE_SMALL_TEST_NOISE_SQUASHING_PARAMS_MULTI_BIT.convert())
            .build();
            let hl_client_key = ClientKey::generate(config);
            let hl_server_key = ServerKey::new(&hl_client_key);
            set_server_key(hl_server_key.clone());

            let input = FheUint32::encrypt(
                HL_SQUASHED_NOISE_UNSIGNED_CIPHERTEXT_TEST.clear_value as u32,
                &hl_client_key,
            );

            let ns = input.squash_noise().unwrap();

            store_versioned_test(
                &hl_client_key,
                &dir,
                &HL_CLIENTKEY_WITH_NOISE_SQUASHING_TEST.test_filename,
            );
            store_versioned_test(&hl_server_key, &dir, &HL_SERVERKEY_TEST.test_filename);

            store_versioned_test(
                &ns,
                &dir,
                &HL_SQUASHED_NOISE_UNSIGNED_CIPHERTEXT_TEST.test_filename,
            );
        }

        // Test re-randomization
        {
            let params = INSECURE_SMALL_TEST_PARAMS_MS_MEAN_COMPENSATION;
            let cpk_params = (
                INSECURE_DEDICATED_CPK_TEST_PARAMS.convert(),
                KS_TO_SMALL_TEST_PARAMS.convert(),
            );
            let re_rand_ks_params = KS_TO_BIG_TEST_PARAMS;

            let config = ConfigBuilder::with_custom_parameters(params.convert())
                .use_dedicated_compact_public_key_parameters(cpk_params)
                .enable_ciphertext_re_randomization(re_rand_ks_params.convert())
                .build();

            let hl_client_key = ClientKey::generate(config);
            let hl_server_key = ServerKey::new(&hl_client_key);
            let hl_public_key = CompressedCompactPublicKey::new(&hl_client_key);

            store_versioned_auxiliary(
                &hl_client_key,
                &dir,
                &HL_SERVERKEY_RERAND_TEST.client_key_filename,
            );

            store_versioned_auxiliary(
                &hl_public_key,
                &dir,
                &HL_SERVERKEY_RERAND_TEST.rerand_cpk_filename.unwrap(),
            );

            store_versioned_test(
                &hl_server_key,
                &dir,
                &HL_SERVERKEY_RERAND_TEST.test_filename,
            );
        }

        // Test CompressedKVStore
        {
            let config =
                ConfigBuilder::with_custom_parameters(VALID_TEST_PARAMS_TUNIFORM.convert())
                    .enable_compression(VALID_TEST_PARAMS_TUNIFORM_COMPRESSION.convert())
                    .build();
            let hl_client_key = ClientKey::generate(config);
            let hl_server_key = ServerKey::new(&hl_client_key);
            set_server_key(hl_server_key.clone());

            let mut clear_store = HashMap::new();
            let mut store = KVStore::new();
            for key in 0..HL_COMPRESSED_KV_STORE_TEST.num_elements as u32 {
                let value = u64::MAX - u64::from(key);

                let encrypted = FheUint64::encrypt(value, &hl_client_key);

                let _ = clear_store.insert(key, value);
                let _ = store.insert_with_clear_key(key, encrypted);
            }

            let compressed_kv_store = store.compress().unwrap();

            store_versioned_auxiliary(
                &hl_client_key,
                &dir,
                &HL_COMPRESSED_KV_STORE_TEST.client_key_file_name,
            );

            store_versioned_auxiliary(
                &hl_server_key,
                &dir,
                &HL_COMPRESSED_KV_STORE_TEST.server_key_file_name,
            );

            store_versioned_test(
                &compressed_kv_store,
                &dir,
                &HL_COMPRESSED_KV_STORE_TEST.kv_store_file_name,
            );
        }

        {
            let config = tfhe::ConfigBuilder::with_custom_parameters(
                INSECURE_SMALL_TEST_PARAMS_KS32.convert(),
            )
            .enable_noise_squashing(
                INSECURE_SMALL_TEST_NOISE_SQUASHING_PARAMS_MS_NOISE_REDUCTION.convert(),
            )
            .build();
            let client_key = ClientKey::generate(config);
            let compressed_server_key = CompressedServerKey::new(&client_key);
            let server_key = compressed_server_key.decompress();

            store_versioned_auxiliary(
                &client_key,
                &dir,
                &HL_SERVERKEY_KS32_NOISE_SQUASHING_TEST.client_key_filename,
            );

            store_versioned_test(
                &compressed_server_key,
                &dir,
                &HL_COMPRESSED_SERVERKEY_KS32_NOISE_SQUASHING_TEST.test_filename,
            );

            store_versioned_test(
                &server_key,
                &dir,
                &HL_SERVERKEY_KS32_NOISE_SQUASHING_TEST.test_filename,
            );
        }

        vec![
            TestMetadata::HlClientKey(HL_CLIENTKEY_WITH_NOISE_SQUASHING_TEST),
            TestMetadata::HlServerKey(HL_SERVERKEY_TEST),
            TestMetadata::HlSquashedNoiseUnsignedCiphertext(
                HL_SQUASHED_NOISE_UNSIGNED_CIPHERTEXT_TEST,
            ),
            TestMetadata::HlServerKey(HL_SERVERKEY_RERAND_TEST),
            TestMetadata::HlCompressedKVStoreTest(HL_COMPRESSED_KV_STORE_TEST),
            TestMetadata::HlServerKey(HL_COMPRESSED_SERVERKEY_KS32_NOISE_SQUASHING_TEST),
            TestMetadata::HlServerKey(HL_SERVERKEY_KS32_NOISE_SQUASHING_TEST),
        ]
    }
}
