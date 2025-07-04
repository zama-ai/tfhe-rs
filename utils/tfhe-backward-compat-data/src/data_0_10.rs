use crate::generate::{
    store_versioned_test_tfhe_0_10, TfhersVersion, VALID_TEST_PARAMS_TUNIFORM,
    VALID_TEST_PARAMS_TUNIFORM_COMPRESSION,
};
use crate::{
    HlClientKeyTest, HlServerKeyTest, TestCompressionParameterSet, TestDistribution, TestMetadata,
    TestParameterSet, HL_MODULE_NAME,
};
use std::borrow::Cow;
use std::fs::create_dir_all;
use tfhe_0_10::boolean::engine::BooleanEngine;
use tfhe_0_10::core_crypto::commons::generators::DeterministicSeeder;
use tfhe_0_10::core_crypto::commons::math::random::ActivatedRandomGenerator;
use tfhe_0_10::core_crypto::prelude::{CiphertextModulusLog, LweCiphertextCount};
use tfhe_0_10::shortint::engine::ShortintEngine;
use tfhe_0_10::shortint::parameters::{
    CarryModulus, CiphertextModulus, ClassicPBSParameters, CompressionParameters,
    DecompositionBaseLog, DecompositionLevelCount, DynamicDistribution, EncryptionKeyChoice,
    GlweDimension, LweDimension, MaxNoiseLevel, MessageModulus, PBSParameters, PolynomialSize,
    StandardDev,
};
use tfhe_0_10::{CompressedServerKey, Seed};

macro_rules! store_versioned_test {
    ($msg:expr, $dir:expr, $test_filename:expr $(,)? ) => {
        store_versioned_test_tfhe_0_10($msg, $dir, $test_filename)
    };
}

impl From<TestDistribution> for DynamicDistribution<u64> {
    fn from(value: TestDistribution) -> Self {
        match value {
            TestDistribution::Gaussian { stddev } => {
                DynamicDistribution::new_gaussian_from_std_dev(StandardDev(stddev))
            }
            TestDistribution::TUniform { bound_log2 } => {
                DynamicDistribution::new_t_uniform(bound_log2)
            }
        }
    }
}

impl From<TestParameterSet> for ClassicPBSParameters {
    fn from(value: TestParameterSet) -> Self {
        ClassicPBSParameters {
            lwe_dimension: LweDimension(value.lwe_dimension),
            glwe_dimension: GlweDimension(value.glwe_dimension),
            polynomial_size: PolynomialSize(value.polynomial_size),
            lwe_noise_distribution: value.lwe_noise_distribution.into(),
            glwe_noise_distribution: value.glwe_noise_distribution.into(),
            pbs_base_log: DecompositionBaseLog(value.pbs_base_log),
            pbs_level: DecompositionLevelCount(value.pbs_level),
            ks_base_log: DecompositionBaseLog(value.ks_base_log),
            ks_level: DecompositionLevelCount(value.ks_level),
            message_modulus: MessageModulus(value.message_modulus),
            carry_modulus: CarryModulus(value.carry_modulus),
            max_noise_level: MaxNoiseLevel::new(value.max_noise_level),
            log2_p_fail: value.log2_p_fail,
            ciphertext_modulus: CiphertextModulus::try_new(value.ciphertext_modulus).unwrap(),
            encryption_key_choice: {
                match &*value.encryption_key_choice {
                    "big" => EncryptionKeyChoice::Big,
                    "small" => EncryptionKeyChoice::Small,
                    _ => panic!("Invalid encryption key choice"),
                }
            },
        }
    }
}

impl From<TestParameterSet> for PBSParameters {
    fn from(value: TestParameterSet) -> Self {
        let tmp: ClassicPBSParameters = value.into();
        tmp.into()
    }
}

impl From<TestCompressionParameterSet> for CompressionParameters {
    fn from(value: TestCompressionParameterSet) -> Self {
        let TestCompressionParameterSet {
            br_level,
            br_base_log,
            packing_ks_level,
            packing_ks_base_log,
            packing_ks_polynomial_size,
            packing_ks_glwe_dimension,
            lwe_per_glwe,
            storage_log_modulus,
            packing_ks_key_noise_distribution,
        } = value;
        Self {
            br_level: DecompositionLevelCount(br_level),
            br_base_log: DecompositionBaseLog(br_base_log),
            packing_ks_level: DecompositionLevelCount(packing_ks_level),
            packing_ks_base_log: DecompositionBaseLog(packing_ks_base_log),
            packing_ks_polynomial_size: PolynomialSize(packing_ks_polynomial_size),
            packing_ks_glwe_dimension: GlweDimension(packing_ks_glwe_dimension),
            lwe_per_glwe: LweCiphertextCount(lwe_per_glwe),
            storage_log_modulus: CiphertextModulusLog(storage_log_modulus),
            packing_ks_key_noise_distribution: packing_ks_key_noise_distribution.into(),
        }
    }
}

const HL_CLIENTKEY_TEST: HlClientKeyTest = HlClientKeyTest {
    test_filename: Cow::Borrowed("client_key"),
    parameters: VALID_TEST_PARAMS_TUNIFORM,
};

const HL_COMPRESSED_SERVERKEY_TEST: HlServerKeyTest = HlServerKeyTest {
    test_filename: Cow::Borrowed("compressed_server_key"),
    client_key_filename: Cow::Borrowed("client_key.cbor"),
    compressed: true,
};

const HL_SERVERKEY_WITH_COMPRESSION_TEST: HlServerKeyTest = HlServerKeyTest {
    test_filename: Cow::Borrowed("server_key_with_compression"),
    client_key_filename: Cow::Borrowed("client_key.cbor"),
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

    fn gen_shortint_data() -> Vec<crate::TestMetadata> {
        Vec::new()
    }

    fn gen_hl_data() -> Vec<crate::TestMetadata> {
        let dir = Self::data_dir().join(HL_MODULE_NAME);
        create_dir_all(&dir).unwrap();

        let config = tfhe_0_10::ConfigBuilder::with_custom_parameters(HL_CLIENTKEY_TEST.parameters)
            .enable_compression(VALID_TEST_PARAMS_TUNIFORM_COMPRESSION.into())
            .build();
        let (hl_client_key, hl_server_key) = tfhe_0_10::generate_keys(config);
        let compressed_server_key = CompressedServerKey::new(&hl_client_key);

        store_versioned_test!(&hl_client_key, &dir, &HL_CLIENTKEY_TEST.test_filename);
        store_versioned_test!(
            &compressed_server_key,
            &dir,
            &HL_COMPRESSED_SERVERKEY_TEST.test_filename,
        );
        store_versioned_test!(
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
