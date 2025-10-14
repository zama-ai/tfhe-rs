mod utils;
use tfhe::Seed;
use tfhe::boolean::engine::BooleanEngine;
use tfhe::core_crypto::commons::generators::DeterministicSeeder;
use tfhe::core_crypto::commons::math::random::RandomGenerator;
use tfhe::core_crypto::prelude::{DefaultRandomGenerator, TUniform};
use tfhe::shortint::CiphertextModulus;
use tfhe::shortint::engine::ShortintEngine;
use tfhe::shortint::parameters::{LweCiphertextCount, LweDimension};
use tfhe::zk::{CompactPkeCrs, ZkMSBZeroPaddingBitCount};
use utils::*;

use std::borrow::Cow;
use std::fs::create_dir_all;
use std::path::Path;

use tfhe_backward_compat_data::generate::*;
use tfhe_backward_compat_data::*;

const HL_CLIENTKEY_MS_NOISE_REDUCTION_TEST: HlClientKeyTest = HlClientKeyTest {
    test_filename: Cow::Borrowed("client_key_ms_noise_reduction"),
    parameters: INSECURE_SMALL_TEST_PARAMS_MS_NOISE_REDUCTION,
};

const HL_SERVERKEY_MS_NOISE_REDUCTION_TEST: HlServerKeyTest = HlServerKeyTest {
    test_filename: Cow::Borrowed("server_key_ms_noise_reduction"),
    client_key_filename: Cow::Borrowed("client_key_ms_noise_reduction.cbor"),
    rerand_cpk_filename: None,
    compressed: false,
};

const ZK_PKEV2_CRS_TEST: ZkPkePublicParamsTest = ZkPkePublicParamsTest {
    test_filename: Cow::Borrowed("zk_pkev2_crs"),
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

pub struct V1_0;

impl TfhersVersion for V1_0 {
    const VERSION_NUMBER: &'static str = "1.0";

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
            HL_CLIENTKEY_MS_NOISE_REDUCTION_TEST.parameters.convert(),
        )
        .build();

        let (hl_client_key, hl_server_key) = tfhe::generate_keys(config);

        store_versioned_test(
            &hl_client_key,
            &dir,
            &HL_CLIENTKEY_MS_NOISE_REDUCTION_TEST.test_filename,
        );
        store_versioned_test(
            &hl_server_key,
            &dir,
            &HL_SERVERKEY_MS_NOISE_REDUCTION_TEST.test_filename,
        );

        let mut zk_rng: RandomGenerator<DefaultRandomGenerator> =
            RandomGenerator::new(Seed(PRNG_SEED));

        let zkv2_crs = CompactPkeCrs::new(
            LweDimension(ZK_PKEV2_CRS_TEST.lwe_dimension),
            LweCiphertextCount(ZK_PKEV2_CRS_TEST.max_num_cleartext),
            TUniform::<u64>::new(ZK_PKEV2_CRS_TEST.noise_bound as u32),
            CiphertextModulus::new(ZK_PKEV2_CRS_TEST.ciphertext_modulus),
            ZK_PKEV2_CRS_TEST.plaintext_modulus as u64,
            ZkMSBZeroPaddingBitCount(ZK_PKEV2_CRS_TEST.padding_bit_count as u64),
            &mut zk_rng,
        )
        .unwrap();

        store_versioned_test(&zkv2_crs, &dir, &ZK_PKEV2_CRS_TEST.test_filename);

        vec![
            TestMetadata::HlClientKey(HL_CLIENTKEY_MS_NOISE_REDUCTION_TEST),
            TestMetadata::HlServerKey(HL_SERVERKEY_MS_NOISE_REDUCTION_TEST),
            TestMetadata::ZkPkePublicParams(ZK_PKEV2_CRS_TEST),
        ]
    }
}
