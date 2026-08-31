mod utils;
use utils::*;

use std::borrow::Cow;
use std::fs::create_dir_all;
use std::path::Path;

use tfhe::boolean::engine::BooleanEngine;
use tfhe::core_crypto::commons::generators::DeterministicSeeder;
use tfhe::core_crypto::prelude::DefaultRandomGenerator;
use tfhe::prelude::*;
use tfhe::shortint::engine::ShortintEngine;
use tfhe::transciphering::{
    AesPlainKey, KreyviumPlainKey, KreyviumPlainState, OneTimePadPlainSecretMask,
};
use tfhe::{
    AesFheKey, ClientKey, CompressedServerKey, HlStreamCipher, KreyviumFheKey,
    OneTimePadFheSecretMask, Seed, ServerKey,
};
use tfhe_backward_compat_data::generate::*;
use tfhe_backward_compat_data::*;

const TRANSCIPHERING_CLIENT_KEY_FILENAME: &str = "transciphering_client_key";
const TRANSCIPHERING_TAG: &[u8] = &[0xC0, 0xFF, 0xEE, 0x00];
const KREYVIUM_PLAIN_KEY: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
const KREYVIUM_IV: [u8; 16] = [16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1];
const AES_PLAIN_KEY: [u8; 16] = [
    0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C,
];
const ONE_TIME_PAD: [u8; 8] = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];

const HL_KREYVIUM_FHE_KEY_TEST: HlKreyviumFheKeyTest = HlKreyviumFheKeyTest {
    test_filename: Cow::Borrowed("kreyvium_fhe_key"),
    key_filename: Cow::Borrowed(TRANSCIPHERING_CLIENT_KEY_FILENAME),
    plain_key: Cow::Borrowed(&KREYVIUM_PLAIN_KEY),
};

const HL_AES_FHE_KEY_TEST: HlAesFheKeyTest = HlAesFheKeyTest {
    test_filename: Cow::Borrowed("aes_fhe_key"),
    key_filename: Cow::Borrowed(TRANSCIPHERING_CLIENT_KEY_FILENAME),
    plain_key: Cow::Borrowed(&AES_PLAIN_KEY),
};

const HL_ONE_TIME_PAD_FHE_SECRET_MASK_TEST: HlOneTimePadFheSecretMaskTest =
    HlOneTimePadFheSecretMaskTest {
        test_filename: Cow::Borrowed("one_time_pad_fhe_secret_mask"),
        key_filename: Cow::Borrowed(TRANSCIPHERING_CLIENT_KEY_FILENAME),
        pad: Cow::Borrowed(&ONE_TIME_PAD),
        n_bits: 64,
    };

const HL_COMPRESSED_SERVER_KEY_TEST: HlServerKeyTest = HlServerKeyTest {
    test_filename: Cow::Borrowed("compressed_server_key_transciphering"),
    client_key_filename: Cow::Borrowed(TRANSCIPHERING_CLIENT_KEY_FILENAME),
    rerand_cpk_filename: None,
    compressed: true,
};

const HL_SERVER_KEY_TEST: HlServerKeyTest = HlServerKeyTest {
    test_filename: Cow::Borrowed("server_key_transciphering"),
    client_key_filename: Cow::Borrowed(TRANSCIPHERING_CLIENT_KEY_FILENAME),
    rerand_cpk_filename: None,
    compressed: false,
};

const HL_STREAM_CIPHERTEXT_TEST: HlStreamCiphertextTest = HlStreamCiphertextTest {
    test_filename: Cow::Borrowed("stream_ciphertext"),
    plain_key: Cow::Borrowed(&KREYVIUM_PLAIN_KEY),
    iv: Cow::Borrowed(&KREYVIUM_IV),
    clear_value: 0xDEAD_BEEF_CAFE_BABE,
    n_bits: 64,
};

pub struct V1_8;

impl TfhersVersion for V1_8 {
    const VERSION_NUMBER: &'static str = "1.8";

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
            let mut client_key =
                ClientKey::generate(INSECURE_TEST_TRANSCIPHERING_META_PARAMS.convert());
            client_key.tag_mut().set_data(TRANSCIPHERING_TAG);

            store_versioned_auxiliary(&client_key, &dir, &HL_KREYVIUM_FHE_KEY_TEST.key_filename);

            let compressed_server_key = CompressedServerKey::new(&client_key);
            store_versioned_test(
                &compressed_server_key,
                &dir,
                &HL_COMPRESSED_SERVER_KEY_TEST.test_filename(),
            );

            let server_key = ServerKey::new(&client_key);
            store_versioned_test(&server_key, &dir, &HL_SERVER_KEY_TEST.test_filename());

            let kreyvium_key = KreyviumFheKey::try_encrypt(
                KreyviumPlainKey::from(KREYVIUM_PLAIN_KEY),
                &client_key,
            )
            .unwrap();
            store_versioned_test(
                &kreyvium_key,
                &dir,
                &HL_KREYVIUM_FHE_KEY_TEST.test_filename(),
            );

            let aes_key =
                AesFheKey::try_encrypt(AesPlainKey::from(AES_PLAIN_KEY), &client_key).unwrap();
            store_versioned_test(&aes_key, &dir, &HL_AES_FHE_KEY_TEST.test_filename());

            let mask = OneTimePadFheSecretMask::try_encrypt(
                OneTimePadPlainSecretMask::new(
                    ONE_TIME_PAD.to_vec(),
                    HL_ONE_TIME_PAD_FHE_SECRET_MASK_TEST.n_bits as usize,
                ),
                &client_key,
            )
            .unwrap();
            store_versioned_test(
                &mask,
                &dir,
                &HL_ONE_TIME_PAD_FHE_SECRET_MASK_TEST.test_filename(),
            );
        }

        {
            let mut cipher =
                KreyviumPlainState::new(KreyviumPlainKey::from(KREYVIUM_PLAIN_KEY), KREYVIUM_IV);
            let stream_ciphertext = cipher
                .try_encrypt(HL_STREAM_CIPHERTEXT_TEST.clear_value)
                .unwrap();
            store_versioned_test(
                &stream_ciphertext,
                &dir,
                &HL_STREAM_CIPHERTEXT_TEST.test_filename(),
            );
        }

        vec![
            TestMetadata::HlKreyviumFheKey(HL_KREYVIUM_FHE_KEY_TEST),
            TestMetadata::HlAesFheKey(HL_AES_FHE_KEY_TEST),
            TestMetadata::HlOneTimePadFheSecretMask(HL_ONE_TIME_PAD_FHE_SECRET_MASK_TEST),
            TestMetadata::HlStreamCiphertext(HL_STREAM_CIPHERTEXT_TEST),
            TestMetadata::HlServerKey(HL_COMPRESSED_SERVER_KEY_TEST),
            TestMetadata::HlServerKey(HL_SERVER_KEY_TEST),
        ]
    }
}
