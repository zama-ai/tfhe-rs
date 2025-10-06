use crate::generate::{
    store_versioned_auxiliary_tfhe_1_4, store_versioned_test_tfhe_1_4, TfhersVersion,
    INSECURE_DEDICATED_CPK_TEST_PARAMS, INSECURE_SMALL_TEST_NOISE_SQUASHING_PARAMS_MULTI_BIT,
    INSECURE_SMALL_TEST_PARAMS_MS_MEAN_COMPENSATION, INSECURE_SMALL_TEST_PARAMS_MULTI_BIT,
    KS_TO_BIG_TEST_PARAMS, KS_TO_SMALL_TEST_PARAMS, VALID_TEST_PARAMS_TUNIFORM,
    VALID_TEST_PARAMS_TUNIFORM_COMPRESSION,
};
use crate::{
    HlClientKeyTest, HlCompressedKVStoreTest, HlServerKeyTest,
    HlSquashedNoiseUnsignedCiphertextTest, TestClassicParameterSet,
    TestCompactPublicKeyEncryptionParameters, TestCompressionParameterSet, TestDistribution,
    TestKeySwitchingParams, TestMetadata, TestModulusSwitchNoiseReductionParams,
    TestModulusSwitchType, TestMultiBitParameterSet, TestNoiseSquashingParamsMultiBit,
    TestParameterSet, HL_MODULE_NAME,
};
use std::borrow::Cow;
use std::collections::HashMap;
use std::fs::create_dir_all;

use tfhe_1_4::boolean::engine::BooleanEngine;
use tfhe_1_4::core_crypto::commons::generators::DeterministicSeeder;

use tfhe_1_4::core_crypto::prelude::DefaultRandomGenerator;
use tfhe_1_4::prelude::*;
use tfhe_1_4::shortint::engine::ShortintEngine;
use tfhe_1_4::shortint::parameters::noise_squashing::NoiseSquashingMultiBitParameters;
use tfhe_1_4::shortint::parameters::{
    CarryModulus, CiphertextModulus, CiphertextModulusLog, CompactCiphertextListExpansionKind,
    CompactPublicKeyEncryptionParameters, CompressionParameters, CoreCiphertextModulus,
    DecompositionBaseLog, DecompositionLevelCount, DynamicDistribution, EncryptionKeyChoice,
    GlweDimension, LweBskGroupingFactor, LweCiphertextCount, LweDimension, MaxNoiseLevel,
    MessageModulus, ModulusSwitchNoiseReductionParams, ModulusSwitchType,
    NoiseEstimationMeasureBound, NoiseSquashingParameters, PolynomialSize, RSigmaFactor,
    ShortintKeySwitchingParameters, StandardDev, SupportedCompactPkeZkScheme, Variance,
};
use tfhe_1_4::shortint::{AtomicPatternParameters, ClassicPBSParameters, MultiBitPBSParameters};
use tfhe_1_4::{
    set_server_key, ClientKey, CompressedCompactPublicKey, ConfigBuilder, FheUint32, FheUint64,
    KVStore, Seed, ServerKey,
};

macro_rules! store_versioned_test {
    ($msg:expr, $dir:expr, $test_filename:expr $(,)? ) => {
        store_versioned_test_tfhe_1_4($msg, $dir, $test_filename)
    };
}

macro_rules! store_versioned_auxiliary {
    ($msg:expr, $dir:expr, $test_filename:expr $(,)? ) => {
        store_versioned_auxiliary_tfhe_1_4($msg, $dir, $test_filename)
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

impl From<TestDistribution> for DynamicDistribution<u128> {
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

impl From<TestModulusSwitchType> for ModulusSwitchType {
    fn from(value: TestModulusSwitchType) -> Self {
        match value {
            TestModulusSwitchType::Standard => ModulusSwitchType::Standard,
            TestModulusSwitchType::DriftTechniqueNoiseReduction(
                test_modulus_switch_noise_reduction_params,
            ) => ModulusSwitchType::DriftTechniqueNoiseReduction(
                test_modulus_switch_noise_reduction_params.into(),
            ),
            TestModulusSwitchType::CenteredMeanNoiseReduction => {
                ModulusSwitchType::CenteredMeanNoiseReduction
            }
        }
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

impl From<TestParameterSet> for AtomicPatternParameters {
    fn from(value: TestParameterSet) -> Self {
        match value {
            TestParameterSet::TestClassicParameterSet(test_classic_parameter_set) => {
                let classic = ClassicPBSParameters::from(test_classic_parameter_set);

                classic.into()
            }
            TestParameterSet::TestMultiBitParameterSet(test_parameter_set_multi_bit) => {
                let classic = MultiBitPBSParameters::from(test_parameter_set_multi_bit);

                classic.into()
            }
        }
    }
}

impl From<TestNoiseSquashingParamsMultiBit> for NoiseSquashingParameters {
    fn from(value: TestNoiseSquashingParamsMultiBit) -> Self {
        let TestNoiseSquashingParamsMultiBit {
            glwe_dimension,
            polynomial_size,
            glwe_noise_distribution,
            decomp_base_log,
            decomp_level_count,
            grouping_factor,
            message_modulus,
            carry_modulus,
            ciphertext_modulus,
        } = value;

        Self::MultiBit(NoiseSquashingMultiBitParameters {
            glwe_dimension: GlweDimension(glwe_dimension),
            polynomial_size: PolynomialSize(polynomial_size),
            glwe_noise_distribution: glwe_noise_distribution.into(),
            decomp_base_log: DecompositionBaseLog(decomp_base_log),
            decomp_level_count: DecompositionLevelCount(decomp_level_count),
            grouping_factor: LweBskGroupingFactor(grouping_factor),
            message_modulus: MessageModulus(message_modulus as u64),
            carry_modulus: CarryModulus(carry_modulus as u64),
            ciphertext_modulus: CoreCiphertextModulus::try_new(ciphertext_modulus).unwrap(),
            deterministic_execution: false,
        })
    }
}

impl From<TestKeySwitchingParams> for ShortintKeySwitchingParameters {
    fn from(value: TestKeySwitchingParams) -> Self {
        Self {
            ks_level: DecompositionLevelCount(value.ks_level),
            ks_base_log: DecompositionBaseLog(value.ks_base_log),
            destination_key: match &*value.destination_key {
                "big" => EncryptionKeyChoice::Big,
                "small" => EncryptionKeyChoice::Small,
                _ => panic!("Invalid encryption key choice"),
            },
        }
    }
}

impl From<TestCompactPublicKeyEncryptionParameters> for CompactPublicKeyEncryptionParameters {
    fn from(value: TestCompactPublicKeyEncryptionParameters) -> Self {
        Self {
            encryption_lwe_dimension: LweDimension(value.encryption_lwe_dimension),
            encryption_noise_distribution: value.encryption_noise_distribution.into(),
            message_modulus: MessageModulus(value.message_modulus as u64),
            carry_modulus: CarryModulus(value.carry_modulus as u64),
            ciphertext_modulus: CoreCiphertextModulus::try_new(value.ciphertext_modulus).unwrap(),
            expansion_kind: match &*value.expansion_kind {
                "requires_casting" => CompactCiphertextListExpansionKind::RequiresCasting,
                _ => panic!("Invalid expansion kind"),
            },
            zk_scheme: match &*value.zk_scheme {
                "zkv1" => SupportedCompactPkeZkScheme::V1,
                "zkv2" => SupportedCompactPkeZkScheme::V2,
                _ => panic!("Invalid zk scheme"),
            },
        }
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

const TEST_FILENAME: Cow<'static, str> = Cow::Borrowed("client_key_with_noise_squashing");

const HL_CLIENTKEY_WITH_NOISE_SQUASHING_TEST: HlClientKeyTest = HlClientKeyTest {
    test_filename: TEST_FILENAME,
    parameters: INSECURE_SMALL_TEST_PARAMS_MULTI_BIT,
};

const HL_SERVERKEY_TEST: HlServerKeyTest = HlServerKeyTest {
    test_filename: Cow::Borrowed("server_key_with_noise_squashing"),
    client_key_filename: TEST_FILENAME,
    rerand_cpk_filename: None,
    compressed: false,
};

const HL_SQUASHED_NOISE_UNSIGNED_CIPHERTEXT_TEST: HlSquashedNoiseUnsignedCiphertextTest =
    HlSquashedNoiseUnsignedCiphertextTest {
        test_filename: Cow::Borrowed("squashed_noise_unsigned_ciphertext"),
        key_filename: TEST_FILENAME,
        clear_value: 42,
    };

const HL_SERVERKEY_RERAND_TEST: HlServerKeyTest = HlServerKeyTest {
    test_filename: Cow::Borrowed("server_key_for_rerand"),
    client_key_filename: Cow::Borrowed("client_key_for_rerand"),
    rerand_cpk_filename: Some(Cow::Borrowed("cpk_for_rerand")),
    compressed: false,
};

const HL_COMPRESSED_KV_STORE_TEST: HlCompressedKVStoreTest = HlCompressedKVStoreTest {
    kv_store_file_name: Cow::Borrowed("compressed_kv_store"),
    client_key_file_name: Cow::Borrowed("client_key_for_kv_store"),
    server_key_file_name: Cow::Borrowed("server_key_for_kv_store"),
    num_elements: 512,
};

pub struct V1_4;

impl TfhersVersion for V1_4 {
    const VERSION_NUMBER: &'static str = "1.4";

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

        // Test noise squahsing multibit
        {
            let config = ConfigBuilder::with_custom_parameters(
                HL_CLIENTKEY_WITH_NOISE_SQUASHING_TEST.parameters,
            )
            .enable_noise_squashing(INSECURE_SMALL_TEST_NOISE_SQUASHING_PARAMS_MULTI_BIT.into())
            .build();
            let hl_client_key = ClientKey::generate(config);
            let hl_server_key = ServerKey::new(&hl_client_key);
            set_server_key(hl_server_key.clone());

            let input = FheUint32::encrypt(
                HL_SQUASHED_NOISE_UNSIGNED_CIPHERTEXT_TEST.clear_value as u32,
                &hl_client_key,
            );

            let ns = input.squash_noise().unwrap();

            store_versioned_test!(
                &hl_client_key,
                &dir,
                &HL_CLIENTKEY_WITH_NOISE_SQUASHING_TEST.test_filename
            );
            store_versioned_test!(&hl_server_key, &dir, &HL_SERVERKEY_TEST.test_filename,);

            store_versioned_test!(
                &ns,
                &dir,
                &HL_SQUASHED_NOISE_UNSIGNED_CIPHERTEXT_TEST.test_filename,
            );
        }

        // Test re-randomization
        {
            let params = INSECURE_SMALL_TEST_PARAMS_MS_MEAN_COMPENSATION;
            let cpk_params = (
                INSECURE_DEDICATED_CPK_TEST_PARAMS.into(),
                KS_TO_SMALL_TEST_PARAMS.into(),
            );
            let re_rand_ks_params = KS_TO_BIG_TEST_PARAMS;

            let config = ConfigBuilder::with_custom_parameters(params)
                .use_dedicated_compact_public_key_parameters(cpk_params)
                .enable_ciphertext_re_randomization(re_rand_ks_params.into())
                .build();

            let hl_client_key = ClientKey::generate(config);
            let hl_server_key = ServerKey::new(&hl_client_key);
            let hl_public_key = CompressedCompactPublicKey::new(&hl_client_key);

            store_versioned_auxiliary!(
                &hl_client_key,
                &dir,
                &HL_SERVERKEY_RERAND_TEST.client_key_filename
            );

            store_versioned_auxiliary!(
                &hl_public_key,
                &dir,
                &HL_SERVERKEY_RERAND_TEST.rerand_cpk_filename.unwrap()
            );

            store_versioned_test!(
                &hl_server_key,
                &dir,
                &HL_SERVERKEY_RERAND_TEST.test_filename,
            );
        }

        // Test CompressedKVStore
        {
            let config = ConfigBuilder::with_custom_parameters(VALID_TEST_PARAMS_TUNIFORM)
                .enable_compression(VALID_TEST_PARAMS_TUNIFORM_COMPRESSION.into())
                .build();
            let hl_client_key = ClientKey::generate(config);
            let hl_server_key = ServerKey::new(&hl_client_key);
            set_server_key(hl_server_key.clone());

            let mut clear_store = HashMap::new();
            let mut store = KVStore::new();
            for key in 0..HL_COMPRESSED_KV_STORE_TEST.num_elements as u32 {
                let value = u64::MAX - u64::from(key);

                let encrypted = FheUint64::encrypt(value, &hl_client_key);

                let _ = clear_store.insert(key, value);
                let _ = store.insert_with_clear_key(key, encrypted);
            }

            let compressed_kv_store = store.compress().unwrap();

            store_versioned_auxiliary!(
                &hl_client_key,
                &dir,
                &HL_COMPRESSED_KV_STORE_TEST.client_key_file_name
            );

            store_versioned_auxiliary!(
                &hl_server_key,
                &dir,
                &HL_COMPRESSED_KV_STORE_TEST.server_key_file_name
            );

            store_versioned_test!(
                &compressed_kv_store,
                &dir,
                &HL_COMPRESSED_KV_STORE_TEST.kv_store_file_name,
            );
        }

        vec![
            TestMetadata::HlClientKey(HL_CLIENTKEY_WITH_NOISE_SQUASHING_TEST),
            TestMetadata::HlServerKey(HL_SERVERKEY_TEST),
            TestMetadata::HlSquashedNoiseUnsignedCiphertext(
                HL_SQUASHED_NOISE_UNSIGNED_CIPHERTEXT_TEST,
            ),
            TestMetadata::HlServerKey(HL_SERVERKEY_RERAND_TEST),
            TestMetadata::HlCompressedKVStoreTest(HL_COMPRESSED_KV_STORE_TEST),
        ]
    }
}
