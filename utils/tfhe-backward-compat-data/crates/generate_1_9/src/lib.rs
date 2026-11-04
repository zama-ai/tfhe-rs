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
use tfhe::transciphering::{OneTimePadPlainSecretMask, OneTimePadPlainState};
use tfhe::{
    ClientKey, OneTimePadFheSecretMask, Seed, ServerKey, StreamCiphertextList, set_server_key,
};
use tfhe_backward_compat_data::generate::*;
use tfhe_backward_compat_data::*;

const TRANSCIPHERING_TAG: &[u8] = &[0xC0, 0xFF, 0xEE, 0x00];
const ONE_TIME_PAD: [u8; 8] = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];

const HL_COMPRESSED_SQUASHED_NOISE_ONE_TIME_PAD_FHE_SECRET_MASK_TEST:
    HlCompressedSquashedNoiseOneTimePadFheSecretMaskTest =
    HlCompressedSquashedNoiseOneTimePadFheSecretMaskTest {
        test_filename: Cow::Borrowed("compressed_squashed_noise_one_time_pad_fhe_secret_mask"),
        key_filename: Cow::Borrowed("client_key_with_noise_squashing"),
        pad: Cow::Borrowed(&ONE_TIME_PAD),
        n_bits: 64,
    };

const HL_STREAM_CIPHERTEXT_LIST_TEST: HlStreamCiphertextListTest = HlStreamCiphertextListTest {
    test_filename: Cow::Borrowed("stream_ciphertext_list"),
    key_filename: Cow::Borrowed("client_key_with_noise_squashing"),
    pad: Cow::Borrowed(&ONE_TIME_PAD),
    clear_values: Cow::Borrowed(&[42, 1, -12]),
    data_kinds: Cow::Borrowed(&[DataKind::Unsigned, DataKind::Bool, DataKind::Signed]),
};

pub struct V1_9;

impl TfhersVersion for V1_9 {
    const VERSION_NUMBER: &'static str = "1.9";

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
            let mut client_key = ClientKey::generate(INSECURE_TEST_META_PARAMS.convert());
            client_key.tag_mut().set_data(TRANSCIPHERING_TAG);
            set_server_key(ServerKey::new(&client_key));

            store_versioned_auxiliary(
                &client_key,
                &dir,
                &HL_COMPRESSED_SQUASHED_NOISE_ONE_TIME_PAD_FHE_SECRET_MASK_TEST.key_filename,
            );

            let mask = OneTimePadFheSecretMask::try_encrypt(
                OneTimePadPlainSecretMask::new(
                    ONE_TIME_PAD.to_vec(),
                    HL_COMPRESSED_SQUASHED_NOISE_ONE_TIME_PAD_FHE_SECRET_MASK_TEST.n_bits as usize,
                ),
                &client_key,
            )
            .unwrap();
            let compressed_mask = mask.squash_noise().unwrap().compress().unwrap();
            store_versioned_test(
                &compressed_mask,
                &dir,
                &HL_COMPRESSED_SQUASHED_NOISE_ONE_TIME_PAD_FHE_SECRET_MASK_TEST.test_filename(),
            );

            let list = StreamCiphertextList::builder()
                .push(HL_STREAM_CIPHERTEXT_LIST_TEST.clear_values[0] as u8)
                .push(HL_STREAM_CIPHERTEXT_LIST_TEST.clear_values[1] != 0)
                .push(HL_STREAM_CIPHERTEXT_LIST_TEST.clear_values[2] as i8)
                .build(&mut OneTimePadPlainState::new(
                    OneTimePadPlainSecretMask::new(ONE_TIME_PAD.to_vec(), ONE_TIME_PAD.len() * 8),
                ))
                .unwrap();
            store_versioned_test(&list, &dir, &HL_STREAM_CIPHERTEXT_LIST_TEST.test_filename());
        }

        vec![
            TestMetadata::HlCompressedSquashedNoiseOneTimePadFheSecretMask(
                HL_COMPRESSED_SQUASHED_NOISE_ONE_TIME_PAD_FHE_SECRET_MASK_TEST,
            ),
            TestMetadata::HlStreamCiphertextList(HL_STREAM_CIPHERTEXT_LIST_TEST),
        ]
    }
}
