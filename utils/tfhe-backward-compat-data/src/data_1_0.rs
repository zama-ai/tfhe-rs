use crate::generate::{
    store_versioned_test_tfhe_1_0, TfhersVersion, INSECURE_SMALL_TEST_PARAMS_MS_NOISE_REDUCTION,
    PRNG_SEED, VALID_TEST_PARAMS_TUNIFORM,
};
use crate::{
    HlClientKeyTest, HlServerKeyTest, TestDistribution, TestMetadata,
    TestModulusSwitchNoiseReductionParams, TestModulusSwitchType, TestParameterSet,
    ZkPkePublicParamsTest, HL_MODULE_NAME,
};
use std::borrow::Cow;
use std::fs::create_dir_all;
use tfhe_1_0::boolean::engine::BooleanEngine;
use tfhe_1_0::core_crypto::commons::generators::DeterministicSeeder;
use tfhe_1_0::core_crypto::commons::math::random::{DefaultRandomGenerator, RandomGenerator};
use tfhe_1_0::core_crypto::prelude::{
    LweCiphertextCount, NoiseEstimationMeasureBound, RSigmaFactor, TUniform, Variance,
};
use tfhe_1_0::shortint::engine::ShortintEngine;
use tfhe_1_0::shortint::parameters::{
    CarryModulus, CiphertextModulus, ClassicPBSParameters, DecompositionBaseLog,
    DecompositionLevelCount, DynamicDistribution, EncryptionKeyChoice, GlweDimension, LweDimension,
    MaxNoiseLevel, MessageModulus, ModulusSwitchNoiseReductionParams, PBSParameters,
    PolynomialSize, StandardDev,
};
use tfhe_1_0::zk::{CompactPkeCrs, ZkMSBZeroPaddingBitCount};
use tfhe_1_0::Seed;

macro_rules! store_versioned_test {
    ($msg:expr, $dir:expr, $test_filename:expr $(,)? ) => {
        store_versioned_test_tfhe_1_0($msg, $dir, $test_filename)
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

impl From<TestModulusSwitchNoiseReductionParams> for ModulusSwitchNoiseReductionParams {
    fn from(value: TestModulusSwitchNoiseReductionParams) -> Self {
        let TestModulusSwitchNoiseReductionParams {
            modulus_switch_zeros_count,
            ms_bound,
            ms_r_sigma_factor,
            ms_input_variance,
        } = value;

        ModulusSwitchNoiseReductionParams {
            modulus_switch_zeros_count: LweCiphertextCount(modulus_switch_zeros_count),
            ms_bound: NoiseEstimationMeasureBound(ms_bound),
            ms_r_sigma_factor: RSigmaFactor(ms_r_sigma_factor),
            ms_input_variance: Variance(ms_input_variance),
        }
    }
}

impl From<TestParameterSet> for ClassicPBSParameters {
    fn from(value: TestParameterSet) -> Self {
        let modulus_switch_noise_reduction_params =
            match value.modulus_switch_noise_reduction_params {
                TestModulusSwitchType::Standard => None,
                TestModulusSwitchType::DriftTechniqueNoiseReduction(
                    test_modulus_switch_noise_reduction_params,
                ) => Some(test_modulus_switch_noise_reduction_params.into()),
                TestModulusSwitchType::CenteredMeanNoiseReduction => panic!("Not supported"),
            };

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
            message_modulus: MessageModulus(value.message_modulus as u64),
            carry_modulus: CarryModulus(value.carry_modulus as u64),
            max_noise_level: MaxNoiseLevel::new(value.max_noise_level as u64),
            log2_p_fail: value.log2_p_fail,
            ciphertext_modulus: CiphertextModulus::try_new(value.ciphertext_modulus).unwrap(),
            encryption_key_choice: {
                match &*value.encryption_key_choice {
                    "big" => EncryptionKeyChoice::Big,
                    "small" => EncryptionKeyChoice::Small,
                    _ => panic!("Invalid encryption key choice"),
                }
            },
            modulus_switch_noise_reduction_params,
        }
    }
}

impl From<TestParameterSet> for PBSParameters {
    fn from(value: TestParameterSet) -> Self {
        let tmp: ClassicPBSParameters = value.into();
        tmp.into()
    }
}

const HL_CLIENTKEY_MS_NOISE_REDUCTION_TEST: HlClientKeyTest = HlClientKeyTest {
    test_filename: Cow::Borrowed("client_key_ms_noise_reduction"),
    parameters: INSECURE_SMALL_TEST_PARAMS_MS_NOISE_REDUCTION,
};

const HL_SERVERKEY_MS_NOISE_REDUCTION_TEST: HlServerKeyTest = HlServerKeyTest {
    test_filename: Cow::Borrowed("server_key_ms_noise_reduction"),
    client_key_filename: Cow::Borrowed("client_key_ms_noise_reduction.cbor"),
    compressed: false,
};

const ZK_PKEV2_CRS_TEST: ZkPkePublicParamsTest = ZkPkePublicParamsTest {
    test_filename: Cow::Borrowed("zk_pkev2_crs"),
    lwe_dimension: VALID_TEST_PARAMS_TUNIFORM.polynomial_size
        * VALID_TEST_PARAMS_TUNIFORM.glwe_dimension, // Lwe dimension of the "big" key is glwe dimension * polynomial size
    max_num_cleartext: 16,
    noise_bound: match VALID_TEST_PARAMS_TUNIFORM.lwe_noise_distribution {
        TestDistribution::Gaussian { .. } => unreachable!(),
        TestDistribution::TUniform { bound_log2 } => bound_log2 as usize,
    },
    ciphertext_modulus: VALID_TEST_PARAMS_TUNIFORM.ciphertext_modulus,
    plaintext_modulus: VALID_TEST_PARAMS_TUNIFORM.message_modulus
        * VALID_TEST_PARAMS_TUNIFORM.carry_modulus
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

    fn gen_shortint_data() -> Vec<TestMetadata> {
        Vec::new()
    }

    fn gen_hl_data() -> Vec<TestMetadata> {
        let dir = Self::data_dir().join(HL_MODULE_NAME);
        create_dir_all(&dir).unwrap();

        let config = tfhe_1_0::ConfigBuilder::with_custom_parameters(
            HL_CLIENTKEY_MS_NOISE_REDUCTION_TEST.parameters,
        )
        .build();

        let (hl_client_key, hl_server_key) = tfhe_1_0::generate_keys(config);

        store_versioned_test!(
            &hl_client_key,
            &dir,
            &HL_CLIENTKEY_MS_NOISE_REDUCTION_TEST.test_filename
        );
        store_versioned_test!(
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

        store_versioned_test!(&zkv2_crs, &dir, &ZK_PKEV2_CRS_TEST.test_filename,);

        vec![
            TestMetadata::HlClientKey(HL_CLIENTKEY_MS_NOISE_REDUCTION_TEST),
            TestMetadata::HlServerKey(HL_SERVERKEY_MS_NOISE_REDUCTION_TEST),
            TestMetadata::ZkPkePublicParams(ZK_PKEV2_CRS_TEST),
        ]
    }
}
