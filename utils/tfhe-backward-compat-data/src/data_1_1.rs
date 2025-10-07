use crate::generate::{
    store_versioned_test_tfhe_1_1, TfhersVersion,
    INSECURE_SMALL_TEST_NOISE_SQUASHING_PARAMS_MS_NOISE_REDUCTION,
    INSECURE_SMALL_TEST_PARAMS_MS_NOISE_REDUCTION,
};
use crate::{
    HlClientKeyTest, HlServerKeyTest, HlSquashedNoiseBoolCiphertextTest,
    HlSquashedNoiseSignedCiphertextTest, HlSquashedNoiseUnsignedCiphertextTest,
    TestClassicParameterSet, TestDistribution, TestMetadata, TestModulusSwitchNoiseReductionParams,
    TestModulusSwitchType, TestMultiBitParameterSet, TestNoiseSquashingParams, TestParameterSet,
    HL_MODULE_NAME,
};
use std::borrow::Cow;
use std::fs::create_dir_all;
use tfhe_1_1::boolean::engine::BooleanEngine;
use tfhe_1_1::core_crypto::commons::generators::DeterministicSeeder;
use tfhe_1_1::core_crypto::commons::math::random::DefaultRandomGenerator;
use tfhe_1_1::core_crypto::prelude::{
    LweCiphertextCount, NoiseEstimationMeasureBound, RSigmaFactor, UnsignedInteger, Variance,
};
use tfhe_1_1::prelude::*;
use tfhe_1_1::shortint::engine::ShortintEngine;
use tfhe_1_1::shortint::parameters::{
    CarryModulus, CiphertextModulus, ClassicPBSParameters, CoreCiphertextModulus,
    DecompositionBaseLog, DecompositionLevelCount, DynamicDistribution, EncryptionKeyChoice,
    GlweDimension, LweBskGroupingFactor, LweDimension, MaxNoiseLevel, MessageModulus,
    ModulusSwitchNoiseReductionParams, MultiBitPBSParameters, NoiseSquashingParameters,
    PBSParameters, PolynomialSize, StandardDev,
};
use tfhe_1_1::{set_server_key, CompressedServerKey, FheBool, FheInt64, FheUint64, Seed};

macro_rules! store_versioned_test {
    ($msg:expr, $dir:expr, $test_filename:expr $(,)? ) => {
        store_versioned_test_tfhe_1_1($msg, $dir, $test_filename)
    };
}

impl<Scalar: UnsignedInteger> From<TestDistribution> for DynamicDistribution<Scalar> {
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

impl From<TestModulusSwitchType> for Option<ModulusSwitchNoiseReductionParams> {
    fn from(value: TestModulusSwitchType) -> Self {
        let modulus_switch_noise_reduction_params = match value {
            TestModulusSwitchType::Standard => return None,
            TestModulusSwitchType::DriftTechniqueNoiseReduction(
                test_modulus_switch_noise_reduction_params,
            ) => test_modulus_switch_noise_reduction_params,
            TestModulusSwitchType::CenteredMeanNoiseReduction => panic!("Not supported"),
        };

        let TestModulusSwitchNoiseReductionParams {
            modulus_switch_zeros_count,
            ms_bound,
            ms_r_sigma_factor,
            ms_input_variance,
        } = modulus_switch_noise_reduction_params;

        Some(ModulusSwitchNoiseReductionParams {
            modulus_switch_zeros_count: LweCiphertextCount(modulus_switch_zeros_count),
            ms_bound: NoiseEstimationMeasureBound(ms_bound),
            ms_r_sigma_factor: RSigmaFactor(ms_r_sigma_factor),
            ms_input_variance: Variance(ms_input_variance),
        })
    }
}

impl From<TestClassicParameterSet> for ClassicPBSParameters {
    fn from(value: TestClassicParameterSet) -> Self {
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
            modulus_switch_noise_reduction_params: value
                .modulus_switch_noise_reduction_params
                .into(),
        }
    }
}

impl From<TestMultiBitParameterSet> for MultiBitPBSParameters {
    fn from(value: TestMultiBitParameterSet) -> Self {
        let TestMultiBitParameterSet {
            lwe_dimension,
            glwe_dimension,
            polynomial_size,
            lwe_noise_distribution,
            glwe_noise_distribution,
            pbs_base_log,
            pbs_level,
            ks_base_log,
            ks_level,
            message_modulus,
            ciphertext_modulus,
            carry_modulus,
            max_noise_level,
            log2_p_fail,
            encryption_key_choice,
            grouping_factor,
        } = value;

        MultiBitPBSParameters {
            lwe_dimension: LweDimension(lwe_dimension),
            glwe_dimension: GlweDimension(glwe_dimension),
            polynomial_size: PolynomialSize(polynomial_size),
            lwe_noise_distribution: lwe_noise_distribution.into(),
            glwe_noise_distribution: glwe_noise_distribution.into(),
            pbs_base_log: DecompositionBaseLog(pbs_base_log),
            pbs_level: DecompositionLevelCount(pbs_level),
            ks_base_log: DecompositionBaseLog(ks_base_log),
            ks_level: DecompositionLevelCount(ks_level),
            message_modulus: MessageModulus(message_modulus as u64),
            carry_modulus: CarryModulus(carry_modulus as u64),
            max_noise_level: MaxNoiseLevel::new(max_noise_level as u64),
            log2_p_fail,
            ciphertext_modulus: CiphertextModulus::try_new(ciphertext_modulus).unwrap(),
            encryption_key_choice: {
                match &*encryption_key_choice {
                    "big" => EncryptionKeyChoice::Big,
                    "small" => EncryptionKeyChoice::Small,
                    _ => panic!("Invalid encryption key choice"),
                }
            },
            grouping_factor: LweBskGroupingFactor(grouping_factor),
            deterministic_execution: false,
        }
    }
}

impl From<TestParameterSet> for PBSParameters {
    fn from(value: TestParameterSet) -> Self {
        match value {
            TestParameterSet::TestClassicParameterSet(test_classic_parameter_set) => {
                PBSParameters::PBS(test_classic_parameter_set.into())
            }
            TestParameterSet::TestMultiBitParameterSet(test_parameter_set_multi_bit) => {
                PBSParameters::MultiBitPBS(test_parameter_set_multi_bit.into())
            }
            TestParameterSet::TestKS32ParameterSet(_) => {
                panic!("unsupported ks32 parameters for version")
            }
        }
    }
}

impl From<TestNoiseSquashingParams> for NoiseSquashingParameters {
    fn from(value: TestNoiseSquashingParams) -> Self {
        let TestNoiseSquashingParams {
            glwe_dimension,
            polynomial_size,
            glwe_noise_distribution,
            decomp_base_log,
            decomp_level_count,
            modulus_switch_noise_reduction_params,
            message_modulus,
            carry_modulus,
            ciphertext_modulus,
        } = value;

        Self {
            glwe_dimension: GlweDimension(glwe_dimension),
            polynomial_size: PolynomialSize(polynomial_size),
            glwe_noise_distribution: glwe_noise_distribution.into(),
            decomp_base_log: DecompositionBaseLog(decomp_base_log),
            decomp_level_count: DecompositionLevelCount(decomp_level_count),
            modulus_switch_noise_reduction_params: modulus_switch_noise_reduction_params.into(),
            message_modulus: MessageModulus(message_modulus.try_into().unwrap()),
            carry_modulus: CarryModulus(carry_modulus.try_into().unwrap()),
            ciphertext_modulus: if ciphertext_modulus == 0 {
                CoreCiphertextModulus::new_native()
            } else {
                CoreCiphertextModulus::try_new(ciphertext_modulus).unwrap()
            },
        }
    }
}

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

    fn gen_shortint_data() -> Vec<TestMetadata> {
        Vec::new()
    }

    fn gen_hl_data() -> Vec<TestMetadata> {
        let dir = Self::data_dir().join(HL_MODULE_NAME);
        create_dir_all(&dir).unwrap();

        let config = tfhe_1_1::ConfigBuilder::with_custom_parameters(
            HL_CLIENTKEY_WITH_NOISE_SQUASHING_TEST.parameters,
        )
        .enable_noise_squashing(
            INSECURE_SMALL_TEST_NOISE_SQUASHING_PARAMS_MS_NOISE_REDUCTION.into(),
        )
        .build();

        let (hl_client_key, hl_server_key) = tfhe_1_1::generate_keys(config);

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

        store_versioned_test!(
            &hl_client_key,
            &dir,
            &HL_CLIENTKEY_WITH_NOISE_SQUASHING_TEST.test_filename
        );
        store_versioned_test!(
            &hl_server_key,
            &dir,
            &HL_SERVERKEY_MS_NOISE_REDUCTION_TEST.test_filename,
        );

        store_versioned_test!(
            &ct_unsigned,
            &dir,
            &HL_SQUASHED_NOISE_UNSIGNED_CIPHERTEXT_TEST.test_filename,
        );
        store_versioned_test!(
            &ct_signed,
            &dir,
            &HL_SQUASHED_NOISE_SIGNED_CIPHERTEXT_TEST.test_filename,
        );
        store_versioned_test!(
            &ct_false,
            &dir,
            &HL_SQUASHED_NOISE_BOOL_FALSE_CIPHERTEXT_TEST.test_filename,
        );
        store_versioned_test!(
            &ct_true,
            &dir,
            &HL_SQUASHED_NOISE_BOOL_TRUE_CIPHERTEXT_TEST.test_filename,
        );

        let compressed_hl_server_key = CompressedServerKey::new(&hl_client_key);

        store_versioned_test!(
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
