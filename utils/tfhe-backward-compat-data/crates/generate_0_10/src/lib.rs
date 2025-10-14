mod utils;
use tfhe::boolean::engine::BooleanEngine;
use tfhe::core_crypto::commons::generators::DeterministicSeeder;
use tfhe::core_crypto::prelude::ActivatedRandomGenerator;
use tfhe::shortint::engine::ShortintEngine;
use tfhe::{CompressedServerKey, Seed};
use utils::*;

use std::borrow::Cow;
use std::fs::create_dir_all;
use std::path::Path;

use tfhe_backward_compat_data::generate::*;
use tfhe_backward_compat_data::*;

const HL_CLIENTKEY_TEST: HlClientKeyTest = HlClientKeyTest {
    test_filename: Cow::Borrowed("client_key"),
    parameters: VALID_TEST_PARAMS_TUNIFORM,
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

pub struct V0_10;

impl TfhersVersion for V0_10 {
    const VERSION_NUMBER: &'static str = "0.10";

    fn seed_prng(seed: u128) {
        let mut seeder = DeterministicSeeder::<ActivatedRandomGenerator>::new(Seed(seed));
        let shortint_engine = ShortintEngine::new_from_seeder(&mut seeder);
        ShortintEngine::with_thread_local_mut(|local_engine| {
            let _ = std::mem::replace(local_engine, shortint_engine);
        });

        let boolean_engine = BooleanEngine::new_from_seeder(&mut seeder);
        BooleanEngine::replace_thread_local(boolean_engine);
    }
    fn gen_shortint_data<P: AsRef<Path>>(_base_data_dir: P) -> Vec<crate::TestMetadata> {
        Vec::new()
    }

    fn gen_hl_data<P: AsRef<Path>>(base_data_dir: P) -> Vec<crate::TestMetadata> {
        let dir = Self::data_dir(base_data_dir).join(HL_MODULE_NAME);
        create_dir_all(&dir).unwrap();

        let config =
            tfhe::ConfigBuilder::with_custom_parameters(HL_CLIENTKEY_TEST.parameters.convert())
                .enable_compression(VALID_TEST_PARAMS_TUNIFORM_COMPRESSION.convert())
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

        vec![
            TestMetadata::HlClientKey(HL_CLIENTKEY_TEST),
            TestMetadata::HlServerKey(HL_COMPRESSED_SERVERKEY_TEST),
            TestMetadata::HlServerKey(HL_SERVERKEY_WITH_COMPRESSION_TEST),
        ]
    }
}
