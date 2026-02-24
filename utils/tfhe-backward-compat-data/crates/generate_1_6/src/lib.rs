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
use tfhe::{Seed, Tag};
use tfhe_backward_compat_data::generate::*;
use tfhe_backward_compat_data::*;

const HL_COMPRESSED_XOF_KEY_SET_TEST: HlCompressedXofKeySetTest = HlCompressedXofKeySetTest {
    compressed_xof_key_set_file_name: Cow::Borrowed("compressed_xof_key_set"),
    client_key_file_name: Cow::Borrowed("xof_client_key"),
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
                INSECURE_TEST_META_PARAMS.convert().into(),
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

        vec![TestMetadata::HlCompressedXofKeySet(
            HL_COMPRESSED_XOF_KEY_SET_TEST,
        )]
    }
}
