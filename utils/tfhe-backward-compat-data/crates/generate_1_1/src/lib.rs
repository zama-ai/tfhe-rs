mod utils;
use tfhe::boolean::engine::BooleanEngine;
use tfhe::core_crypto::commons::generators::DeterministicSeeder;
use tfhe::core_crypto::prelude::DefaultRandomGenerator;
use tfhe::prelude::{FheEncrypt, SquashNoise};
use tfhe::shortint::engine::ShortintEngine;
use tfhe::{CompressedServerKey, FheBool, FheInt64, FheUint64, Seed, set_server_key};
use utils::*;

use std::borrow::Cow;
use std::fs::create_dir_all;
use std::path::Path;

use tfhe_backward_compat_data::generate::*;
use tfhe_backward_compat_data::*;

const HL_CLIENTKEY_WITH_NOISE_SQUASHING_TEST: HlClientKeyTest = HlClientKeyTest {
    test_filename: Cow::Borrowed("client_key_with_noise_squashing"),
    parameters: INSECURE_SMALL_TEST_PARAMS_MS_NOISE_REDUCTION,
};

const HL_SERVERKEY_MS_NOISE_REDUCTION_TEST: HlServerKeyTest = HlServerKeyTest {
    test_filename: Cow::Borrowed("server_key_with_noise_squashing"),
    client_key_filename: HL_CLIENTKEY_WITH_NOISE_SQUASHING_TEST.test_filename,
    rerand_cpk_filename: None,
    compressed: false,
};

const HL_SERVERKEY_MS_NOISE_REDUCTION_COMPRESSED_TEST: HlServerKeyTest = HlServerKeyTest {
    test_filename: Cow::Borrowed("server_key_with_noise_squashing_compressed"),
    client_key_filename: HL_CLIENTKEY_WITH_NOISE_SQUASHING_TEST.test_filename,
    rerand_cpk_filename: None,
    compressed: true,
};

const HL_SQUASHED_NOISE_UNSIGNED_CIPHERTEXT_TEST: HlSquashedNoiseUnsignedCiphertextTest =
    HlSquashedNoiseUnsignedCiphertextTest {
        test_filename: Cow::Borrowed("squashed_noise_unsigned_ciphertext"),
        key_filename: HL_CLIENTKEY_WITH_NOISE_SQUASHING_TEST.test_filename,
        clear_value: 42,
    };

const HL_SQUASHED_NOISE_SIGNED_CIPHERTEXT_TEST: HlSquashedNoiseSignedCiphertextTest =
    HlSquashedNoiseSignedCiphertextTest {
        test_filename: Cow::Borrowed("squashed_noise_signed_ciphertext"),
        key_filename: HL_CLIENTKEY_WITH_NOISE_SQUASHING_TEST.test_filename,
        clear_value: -37,
    };

const HL_SQUASHED_NOISE_BOOL_FALSE_CIPHERTEXT_TEST: HlSquashedNoiseBoolCiphertextTest =
    HlSquashedNoiseBoolCiphertextTest {
        test_filename: Cow::Borrowed("squashed_noise_bool_false_ciphertext"),
        key_filename: HL_CLIENTKEY_WITH_NOISE_SQUASHING_TEST.test_filename,
        clear_value: false,
    };

const HL_SQUASHED_NOISE_BOOL_TRUE_CIPHERTEXT_TEST: HlSquashedNoiseBoolCiphertextTest =
    HlSquashedNoiseBoolCiphertextTest {
        test_filename: Cow::Borrowed("squashed_noise_bool_true_ciphertext"),
        key_filename: HL_CLIENTKEY_WITH_NOISE_SQUASHING_TEST.test_filename,
        clear_value: true,
    };

pub struct V1_1;

impl TfhersVersion for V1_1 {
    const VERSION_NUMBER: &'static str = "1.1";

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

        let config = tfhe::ConfigBuilder::with_custom_parameters(
            HL_CLIENTKEY_WITH_NOISE_SQUASHING_TEST.parameters.convert(),
        )
        .enable_noise_squashing(
            INSECURE_SMALL_TEST_NOISE_SQUASHING_PARAMS_MS_NOISE_REDUCTION.convert(),
        )
        .build();

        let (hl_client_key, hl_server_key) = tfhe::generate_keys(config);

        set_server_key(hl_server_key.clone());

        let ct_unsigned = FheUint64::encrypt(
            HL_SQUASHED_NOISE_UNSIGNED_CIPHERTEXT_TEST.clear_value,
            &hl_client_key,
        );
        let ct_signed = FheInt64::encrypt(
            HL_SQUASHED_NOISE_SIGNED_CIPHERTEXT_TEST.clear_value,
            &hl_client_key,
        );
        let ct_false = FheBool::encrypt(
            HL_SQUASHED_NOISE_BOOL_FALSE_CIPHERTEXT_TEST.clear_value,
            &hl_client_key,
        );
        let ct_true = FheBool::encrypt(
            HL_SQUASHED_NOISE_BOOL_TRUE_CIPHERTEXT_TEST.clear_value,
            &hl_client_key,
        );

        let ct_unsigned = ct_unsigned.squash_noise().unwrap();
        let ct_signed = ct_signed.squash_noise().unwrap();
        let ct_false = ct_false.squash_noise().unwrap();
        let ct_true = ct_true.squash_noise().unwrap();

        store_versioned_test(
            &hl_client_key,
            &dir,
            &HL_CLIENTKEY_WITH_NOISE_SQUASHING_TEST.test_filename,
        );
        store_versioned_test(
            &hl_server_key,
            &dir,
            &HL_SERVERKEY_MS_NOISE_REDUCTION_TEST.test_filename,
        );

        store_versioned_test(
            &ct_unsigned,
            &dir,
            &HL_SQUASHED_NOISE_UNSIGNED_CIPHERTEXT_TEST.test_filename,
        );
        store_versioned_test(
            &ct_signed,
            &dir,
            &HL_SQUASHED_NOISE_SIGNED_CIPHERTEXT_TEST.test_filename,
        );
        store_versioned_test(
            &ct_false,
            &dir,
            &HL_SQUASHED_NOISE_BOOL_FALSE_CIPHERTEXT_TEST.test_filename,
        );
        store_versioned_test(
            &ct_true,
            &dir,
            &HL_SQUASHED_NOISE_BOOL_TRUE_CIPHERTEXT_TEST.test_filename,
        );

        let compressed_hl_server_key = CompressedServerKey::new(&hl_client_key);

        store_versioned_test(
            &compressed_hl_server_key,
            &dir,
            &HL_SERVERKEY_MS_NOISE_REDUCTION_COMPRESSED_TEST.test_filename,
        );

        vec![
            TestMetadata::HlClientKey(HL_CLIENTKEY_WITH_NOISE_SQUASHING_TEST),
            TestMetadata::HlServerKey(HL_SERVERKEY_MS_NOISE_REDUCTION_TEST),
            TestMetadata::HlServerKey(HL_SERVERKEY_MS_NOISE_REDUCTION_COMPRESSED_TEST),
            TestMetadata::HlSquashedNoiseUnsignedCiphertext(
                HL_SQUASHED_NOISE_UNSIGNED_CIPHERTEXT_TEST,
            ),
            TestMetadata::HlSquashedNoiseSignedCiphertext(HL_SQUASHED_NOISE_SIGNED_CIPHERTEXT_TEST),
            TestMetadata::HlSquashedNoiseBoolCiphertext(
                HL_SQUASHED_NOISE_BOOL_FALSE_CIPHERTEXT_TEST,
            ),
            TestMetadata::HlSquashedNoiseBoolCiphertext(
                HL_SQUASHED_NOISE_BOOL_TRUE_CIPHERTEXT_TEST,
            ),
        ]
    }
}
