mod utils;
use tfhe::boolean::engine::BooleanEngine;
use tfhe::boolean::prelude::LweDimension;
use tfhe::core_crypto::commons::generators::DeterministicSeeder;
use tfhe::core_crypto::commons::math::random::RandomGenerator;
use tfhe::core_crypto::prelude::{CiphertextModulus, DefaultRandomGenerator, TUniform};
use tfhe::prelude::{FheEncrypt, SquashNoise};
use tfhe::shortint::engine::ShortintEngine;
use tfhe::shortint::parameters::LweCiphertextCount;
use tfhe::zk::{CompactPkeCrs, ZkComputeLoad, ZkMSBZeroPaddingBitCount};
use tfhe::{
    ClientKey, CompactPublicKey, CompressedServerKey, CompressedSquashedNoiseCiphertextList,
    FheBool, FheInt32, FheUint8, FheUint32, ProvenCompactCiphertextList, Seed, ServerKey,
    set_server_key,
};
use utils::*;

use std::borrow::Cow;
use std::fs::create_dir_all;
use std::path::Path;

use tfhe_backward_compat_data::generate::*;
use tfhe_backward_compat_data::*;

const ZK_PKE_CRS_TEST: ZkPkePublicParamsTest = ZkPkePublicParamsTest {
    test_filename: Cow::Borrowed("zk_pke_crs"),
    lwe_dimension: VALID_TEST_PARAMS_TUNIFORM.polynomial_size()
        * VALID_TEST_PARAMS_TUNIFORM.glwe_dimension(), // Lwe dimension of the "big" key is glwe dimension * polynomial size
    max_num_cleartext: 16,
    noise_bound: match VALID_TEST_PARAMS_TUNIFORM.lwe_noise_distribution() {
        TestDistribution::Gaussian { .. } => unreachable!(),
        TestDistribution::TUniform { bound_log2 } => bound_log2 as usize,
    },
    ciphertext_modulus: VALID_TEST_PARAMS_TUNIFORM.ciphertext_modulus(),
    plaintext_modulus: VALID_TEST_PARAMS_TUNIFORM.message_modulus()
        * VALID_TEST_PARAMS_TUNIFORM.carry_modulus()
        * 2, // *2 for padding bit
    padding_bit_count: 1,
};

const HL_PROVEN_COMPACTLIST_TEST_ZKV2_FASTHASH: HlHeterogeneousCiphertextListTest =
    HlHeterogeneousCiphertextListTest {
        test_filename: Cow::Borrowed("hl_proven_heterogeneous_list_zkv2_fasthash"),
        key_filename: Cow::Borrowed("client_key"),
        clear_values: Cow::Borrowed(&[17u8 as u64, -12i8 as u64, false as u64, true as u64]),
        data_kinds: Cow::Borrowed(&[
            DataKind::Unsigned,
            DataKind::Signed,
            DataKind::Bool,
            DataKind::Bool,
        ]),
        compressed: false,
        proof_info: Some(PkeZkProofAuxiliaryInfo {
            public_key_filename: Cow::Borrowed("public_key"),
            params_filename: ZK_PKE_CRS_TEST.test_filename,
            metadata: Cow::Borrowed("2vdrawkcab"),
        }),
    };

const HL_CLIENTKEY_MS_MEAN_COMPENSATION: HlClientKeyTest = HlClientKeyTest {
    test_filename: Cow::Borrowed("client_key_ms_mean_compensation"),
    parameters: INSECURE_SMALL_TEST_PARAMS_MS_MEAN_COMPENSATION,
};

const HL_SERVERKEY_MS_MEAN_COMPENSATION: HlServerKeyTest = HlServerKeyTest {
    test_filename: Cow::Borrowed("server_key_ms_mean_compensation"),
    client_key_filename: Cow::Borrowed("client_key_ms_mean_compensation.cbor"),
    rerand_cpk_filename: None,
    compressed: false,
};

const HL_COMPRESSED_SQUASHED_NOISE_CIPHERTEXT_LIST: HlCompressedSquashedNoiseCiphertextListTest =
    HlCompressedSquashedNoiseCiphertextListTest {
        test_filename: Cow::Borrowed("hl_compressed_squashed_noise_ciphertext_list"),
        key_filename: Cow::Borrowed("client_key_with_noise_squashing"),
        clear_values: Cow::Borrowed(&[
            54679568u32 as u64,
            -12396372i32 as u64,
            12396372i32 as u64,
            false as u64,
            true as u64,
        ]),
        data_kinds: Cow::Borrowed(&[
            DataKind::Unsigned,
            DataKind::Signed,
            DataKind::Signed,
            DataKind::Bool,
            DataKind::Bool,
        ]),
    };

const CLIENT_KEY_KS32_FILENAME: &str = "client_key_ks32";

const CLIENT_KEY_KS32_TEST: HlClientKeyTest = HlClientKeyTest {
    test_filename: Cow::Borrowed(CLIENT_KEY_KS32_FILENAME),
    parameters: VALID_TEST_PARAMS_KS32_TUNIFORM,
};

const SERVER_KEY_KS32_TEST: HlServerKeyTest = HlServerKeyTest {
    test_filename: Cow::Borrowed("server_key_ks32"),
    client_key_filename: Cow::Borrowed(CLIENT_KEY_KS32_FILENAME),
    rerand_cpk_filename: None,
    compressed: false,
};

const COMPRESSED_SERVER_KEY_KS32_TEST: HlServerKeyTest = HlServerKeyTest {
    test_filename: Cow::Borrowed("compressed_server_key_ks32"),
    client_key_filename: Cow::Borrowed(CLIENT_KEY_KS32_FILENAME),
    rerand_cpk_filename: None,
    compressed: true,
};

const CT_KS32_TEST: HlCiphertextTest = HlCiphertextTest {
    test_filename: Cow::Borrowed("ct_ks32"),
    key_filename: Cow::Borrowed(CLIENT_KEY_KS32_FILENAME),
    compressed: false,
    clear_value: 25,
};

pub struct V1_3;

impl TfhersVersion for V1_3 {
    const VERSION_NUMBER: &'static str = "1.3";

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

        let mut zk_rng: RandomGenerator<DefaultRandomGenerator> =
            RandomGenerator::new(Seed(PRNG_SEED));

        // Generate a compact public key needed to create a compact list
        let config =
            tfhe::ConfigBuilder::with_custom_parameters(VALID_TEST_PARAMS_TUNIFORM.convert())
                .build();
        let hl_client_key = ClientKey::generate(config);
        let hl_server_key = ServerKey::new(&hl_client_key);
        set_server_key(hl_server_key.clone());
        let compact_pub_key = CompactPublicKey::new(&hl_client_key);

        let crs = CompactPkeCrs::new(
            LweDimension(ZK_PKE_CRS_TEST.lwe_dimension),
            LweCiphertextCount(ZK_PKE_CRS_TEST.max_num_cleartext),
            TUniform::<u64>::new(ZK_PKE_CRS_TEST.noise_bound as u32),
            CiphertextModulus::new(ZK_PKE_CRS_TEST.ciphertext_modulus),
            ZK_PKE_CRS_TEST.plaintext_modulus as u64,
            ZkMSBZeroPaddingBitCount(ZK_PKE_CRS_TEST.padding_bit_count as u64),
            &mut zk_rng,
        )
        .unwrap();

        // Store the crs
        store_versioned_auxiliary(&crs, &dir, &ZK_PKE_CRS_TEST.test_filename);

        // Store the associated client key to be able to decrypt the ciphertexts in the list
        store_versioned_auxiliary(
            &hl_client_key,
            &dir,
            &HL_PROVEN_COMPACTLIST_TEST_ZKV2_FASTHASH.key_filename,
        );

        store_versioned_auxiliary(
            &compact_pub_key,
            &dir,
            &HL_PROVEN_COMPACTLIST_TEST_ZKV2_FASTHASH
                .proof_info
                .unwrap()
                .public_key_filename,
        );

        let mut proven_builder = ProvenCompactCiphertextList::builder(&compact_pub_key);
        proven_builder
            .push(HL_PROVEN_COMPACTLIST_TEST_ZKV2_FASTHASH.clear_values[0] as u8)
            .push(HL_PROVEN_COMPACTLIST_TEST_ZKV2_FASTHASH.clear_values[1] as i8)
            .push(HL_PROVEN_COMPACTLIST_TEST_ZKV2_FASTHASH.clear_values[2] != 0)
            .push(HL_PROVEN_COMPACTLIST_TEST_ZKV2_FASTHASH.clear_values[3] != 0);

        let proven_list_packed = proven_builder
            .build_with_proof_packed(
                &crs,
                HL_PROVEN_COMPACTLIST_TEST_ZKV2_FASTHASH
                    .proof_info
                    .unwrap()
                    .metadata
                    .as_bytes(),
                ZkComputeLoad::Verify,
            )
            .unwrap();

        store_versioned_test(
            &proven_list_packed,
            &dir,
            &HL_PROVEN_COMPACTLIST_TEST_ZKV2_FASTHASH.test_filename,
        );

        let config = tfhe::ConfigBuilder::with_custom_parameters(
            HL_CLIENTKEY_MS_MEAN_COMPENSATION.parameters.convert(),
        )
        .build();

        let (hl_client_key, hl_server_key) = tfhe::generate_keys(config);

        store_versioned_test(
            &hl_client_key,
            &dir,
            &HL_CLIENTKEY_MS_MEAN_COMPENSATION.test_filename,
        );
        store_versioned_test(
            &hl_server_key,
            &dir,
            &HL_SERVERKEY_MS_MEAN_COMPENSATION.test_filename,
        );

        // Generate data for the squashed noise compressed ciphertext list
        {
            let config = tfhe::ConfigBuilder::with_custom_parameters(
                INSECURE_SMALL_TEST_PARAMS_MS_NOISE_REDUCTION.convert(),
            )
            .enable_noise_squashing(
                INSECURE_SMALL_TEST_NOISE_SQUASHING_PARAMS_MS_NOISE_REDUCTION.convert(),
            )
            .enable_noise_squashing_compression(TEST_PARAMS_NOISE_SQUASHING_COMPRESSION.convert())
            .build();
            let hl_client_key = ClientKey::generate(config);
            let hl_server_key = ServerKey::new(&hl_client_key);
            set_server_key(hl_server_key.clone());

            let input_a = FheUint32::encrypt(
                HL_COMPRESSED_SQUASHED_NOISE_CIPHERTEXT_LIST.clear_values[0] as u32,
                &hl_client_key,
            );
            let input_b = FheInt32::encrypt(
                HL_COMPRESSED_SQUASHED_NOISE_CIPHERTEXT_LIST.clear_values[1] as i32,
                &hl_client_key,
            );
            let input_c = FheInt32::encrypt(
                HL_COMPRESSED_SQUASHED_NOISE_CIPHERTEXT_LIST.clear_values[2] as i32,
                &hl_client_key,
            );
            let input_d = FheBool::encrypt(
                HL_COMPRESSED_SQUASHED_NOISE_CIPHERTEXT_LIST.clear_values[3] != 0,
                &hl_client_key,
            );
            let input_e = FheBool::encrypt(
                HL_COMPRESSED_SQUASHED_NOISE_CIPHERTEXT_LIST.clear_values[4] != 0,
                &hl_client_key,
            );

            let ns_a = input_a.squash_noise().unwrap();
            let ns_b = input_b.squash_noise().unwrap();
            let ns_c = input_c.squash_noise().unwrap();
            let ns_d = input_d.squash_noise().unwrap();
            let ns_e = input_e.squash_noise().unwrap();

            let compressed_list = CompressedSquashedNoiseCiphertextList::builder()
                .push(ns_a)
                .push(ns_b)
                .push(ns_c)
                .push(ns_d)
                .push(ns_e)
                .build()
                .unwrap();

            store_versioned_auxiliary(
                &hl_client_key,
                &dir,
                &HL_COMPRESSED_SQUASHED_NOISE_CIPHERTEXT_LIST.key_filename,
            );

            store_versioned_test(
                &compressed_list,
                &dir,
                &HL_COMPRESSED_SQUASHED_NOISE_CIPHERTEXT_LIST.test_filename,
            );
        };

        // Generate data for the KS32 AP
        {
            let config = tfhe::ConfigBuilder::default()
                .use_custom_parameters(CLIENT_KEY_KS32_TEST.parameters.convert())
                .build();

            let hl_client_key = ClientKey::generate(config);
            let compressed_server_key = CompressedServerKey::new(&hl_client_key);
            let hl_server_key = compressed_server_key.decompress();

            let ct = FheUint8::encrypt(CT_KS32_TEST.clear_value, &hl_client_key);

            store_versioned_test(&hl_client_key, &dir, &CLIENT_KEY_KS32_TEST.test_filename);
            store_versioned_test(&hl_server_key, &dir, &SERVER_KEY_KS32_TEST.test_filename);
            store_versioned_test(
                &compressed_server_key,
                &dir,
                &COMPRESSED_SERVER_KEY_KS32_TEST.test_filename,
            );
            store_versioned_test(&ct, &dir, &CT_KS32_TEST.test_filename);
        }

        vec![
            TestMetadata::HlHeterogeneousCiphertextList(HL_PROVEN_COMPACTLIST_TEST_ZKV2_FASTHASH),
            TestMetadata::HlClientKey(HL_CLIENTKEY_MS_MEAN_COMPENSATION),
            TestMetadata::HlServerKey(HL_SERVERKEY_MS_MEAN_COMPENSATION),
            TestMetadata::HlCompressedSquashedNoiseCiphertextList(
                HL_COMPRESSED_SQUASHED_NOISE_CIPHERTEXT_LIST,
            ),
            TestMetadata::HlClientKey(CLIENT_KEY_KS32_TEST),
            TestMetadata::HlServerKey(SERVER_KEY_KS32_TEST),
            TestMetadata::HlServerKey(COMPRESSED_SERVER_KEY_KS32_TEST),
            TestMetadata::HlCiphertext(CT_KS32_TEST),
        ]
    }
}
