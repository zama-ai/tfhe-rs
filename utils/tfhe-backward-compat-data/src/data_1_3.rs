use crate::generate::{
    store_versioned_auxiliary_tfhe_1_3, store_versioned_test_tfhe_1_3, TfhersVersion,
    INSECURE_SMALL_TEST_PARAMS_MS_MEAN_COMPENSATION, PRNG_SEED, VALID_TEST_PARAMS_TUNIFORM,
};
use crate::{
    DataKind, HlClientKeyTest, HlCompressedSquashedNoiseCiphertextListTest,
    HlHeterogeneousCiphertextListTest, HlServerKeyTest, PkeZkProofAuxiliaryInfo,
    TestClassicParameterSet, TestDistribution, TestMetadata, TestModulusSwitchNoiseReductionParams,
    TestModulusSwitchType, TestMultiBitParameterSet, TestNoiseSquashingCompressionParameters,
    TestNoiseSquashingParams, TestParameterSet, ZkPkePublicParamsTest, HL_MODULE_NAME,
};
use std::borrow::Cow;
use std::fs::create_dir_all;

use crate::generate::{
    INSECURE_SMALL_TEST_NOISE_SQUASHING_PARAMS_MS_NOISE_REDUCTION,
    INSECURE_SMALL_TEST_PARAMS_MS_NOISE_REDUCTION, TEST_PRAMS_NOISE_SQUASHING_COMPRESSION,
};

use tfhe_1_3::boolean::engine::BooleanEngine;
use tfhe_1_3::core_crypto::commons::generators::DeterministicSeeder;
use tfhe_1_3::core_crypto::commons::math::random::RandomGenerator;
use tfhe_1_3::core_crypto::prelude::{DefaultRandomGenerator, TUniform};
use tfhe_1_3::prelude::*;
use tfhe_1_3::shortint::engine::ShortintEngine;
use tfhe_1_3::shortint::parameters::{
    CarryModulus, CiphertextModulus, ClassicPBSParameters, CoreCiphertextModulus,
    DecompositionBaseLog, DecompositionLevelCount, DynamicDistribution, EncryptionKeyChoice,
    GlweDimension, LweBskGroupingFactor, LweCiphertextCount, LweDimension, MaxNoiseLevel,
    MessageModulus, ModulusSwitchNoiseReductionParams, MultiBitPBSParameters,
    NoiseEstimationMeasureBound, NoiseSquashingCompressionParameters, NoiseSquashingParameters,
    PolynomialSize, RSigmaFactor, StandardDev, Variance,
};
use tfhe_1_3::shortint::prelude::ModulusSwitchType;
use tfhe_1_3::shortint::AtomicPatternParameters;
use tfhe_1_3::zk::{CompactPkeCrs, ZkComputeLoad, ZkMSBZeroPaddingBitCount};
use tfhe_1_3::{
    set_server_key, ClientKey, CompactPublicKey, CompressedSquashedNoiseCiphertextList, FheBool,
    FheInt32, FheUint32, ProvenCompactCiphertextList, Seed, ServerKey,
};

macro_rules! store_versioned_test {
    ($msg:expr, $dir:expr, $test_filename:expr $(,)? ) => {
        store_versioned_test_tfhe_1_3($msg, $dir, $test_filename)
    };
}

macro_rules! store_versioned_auxiliary {
    ($msg:expr, $dir:expr, $test_filename:expr $(,)? ) => {
        store_versioned_auxiliary_tfhe_1_3($msg, $dir, $test_filename)
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
                let multibit = MultiBitPBSParameters::from(test_parameter_set_multi_bit);

                multibit.into()
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
            modulus_switch_noise_reduction_params: match modulus_switch_noise_reduction_params {
                Some(p) => ModulusSwitchType::DriftTechniqueNoiseReduction(p.into()),
                None => ModulusSwitchType::Standard,
            },
            message_modulus: MessageModulus(message_modulus as u64),
            carry_modulus: CarryModulus(carry_modulus as u64),
            ciphertext_modulus: CoreCiphertextModulus::try_new(ciphertext_modulus).unwrap(),
        }
    }
}

impl From<TestNoiseSquashingCompressionParameters> for NoiseSquashingCompressionParameters {
    fn from(value: TestNoiseSquashingCompressionParameters) -> Self {
        let TestNoiseSquashingCompressionParameters {
            packing_ks_level,
            packing_ks_base_log,
            packing_ks_polynomial_size,
            packing_ks_glwe_dimension,
            lwe_per_glwe,
            packing_ks_key_noise_distribution,
            message_modulus,
            carry_modulus,
            ciphertext_modulus,
        } = value;

        Self {
            packing_ks_level: DecompositionLevelCount(packing_ks_level),
            packing_ks_base_log: DecompositionBaseLog(packing_ks_base_log),
            packing_ks_polynomial_size: PolynomialSize(packing_ks_polynomial_size),
            packing_ks_glwe_dimension: GlweDimension(packing_ks_glwe_dimension),
            lwe_per_glwe: LweCiphertextCount(lwe_per_glwe),
            packing_ks_key_noise_distribution: packing_ks_key_noise_distribution.into(),
            message_modulus: MessageModulus(message_modulus as u64),
            carry_modulus: CarryModulus(carry_modulus as u64),
            ciphertext_modulus: CoreCiphertextModulus::try_new(ciphertext_modulus).unwrap(),
        }
    }
}

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

    fn gen_shortint_data() -> Vec<TestMetadata> {
        Vec::new()
    }

    fn gen_hl_data() -> Vec<TestMetadata> {
        let dir = Self::data_dir().join(HL_MODULE_NAME);
        create_dir_all(&dir).unwrap();

        let mut zk_rng: RandomGenerator<DefaultRandomGenerator> =
            RandomGenerator::new(Seed(PRNG_SEED));

        // Generate a compact public key needed to create a compact list
        let config =
            tfhe_1_3::ConfigBuilder::with_custom_parameters(VALID_TEST_PARAMS_TUNIFORM).build();
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
        store_versioned_auxiliary!(&crs, &dir, &ZK_PKE_CRS_TEST.test_filename);

        // Store the associated client key to be able to decrypt the ciphertexts in the list
        store_versioned_auxiliary!(
            &hl_client_key,
            &dir,
            &HL_PROVEN_COMPACTLIST_TEST_ZKV2_FASTHASH.key_filename
        );

        store_versioned_auxiliary!(
            &compact_pub_key,
            &dir,
            &HL_PROVEN_COMPACTLIST_TEST_ZKV2_FASTHASH
                .proof_info
                .unwrap()
                .public_key_filename
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

        store_versioned_test!(
            &proven_list_packed,
            &dir,
            &HL_PROVEN_COMPACTLIST_TEST_ZKV2_FASTHASH.test_filename,
        );

        let config = tfhe_1_3::ConfigBuilder::with_custom_parameters(
            HL_CLIENTKEY_MS_MEAN_COMPENSATION.parameters,
        )
        .build();

        let (hl_client_key, hl_server_key) = tfhe_1_3::generate_keys(config);

        store_versioned_test!(
            &hl_client_key,
            &dir,
            &HL_CLIENTKEY_MS_MEAN_COMPENSATION.test_filename
        );
        store_versioned_test!(
            &hl_server_key,
            &dir,
            &HL_SERVERKEY_MS_MEAN_COMPENSATION.test_filename,
        );

        // Generate data for the squashed noise compressed ciphertext list
        {
            let config = tfhe_1_3::ConfigBuilder::with_custom_parameters(
                INSECURE_SMALL_TEST_PARAMS_MS_NOISE_REDUCTION,
            )
            .enable_noise_squashing(
                INSECURE_SMALL_TEST_NOISE_SQUASHING_PARAMS_MS_NOISE_REDUCTION.into(),
            )
            .enable_noise_squashing_compression(TEST_PRAMS_NOISE_SQUASHING_COMPRESSION.into())
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

            store_versioned_auxiliary!(
                &hl_client_key,
                &dir,
                &HL_COMPRESSED_SQUASHED_NOISE_CIPHERTEXT_LIST.key_filename
            );

            store_versioned_test!(
                &compressed_list,
                &dir,
                &HL_COMPRESSED_SQUASHED_NOISE_CIPHERTEXT_LIST.test_filename,
            );
        };

        vec![
            TestMetadata::HlHeterogeneousCiphertextList(HL_PROVEN_COMPACTLIST_TEST_ZKV2_FASTHASH),
            TestMetadata::HlClientKey(HL_CLIENTKEY_MS_MEAN_COMPENSATION),
            TestMetadata::HlServerKey(HL_SERVERKEY_MS_MEAN_COMPENSATION),
            TestMetadata::HlCompressedSquashedNoiseCiphertextList(
                HL_COMPRESSED_SQUASHED_NOISE_CIPHERTEXT_LIST,
            ),
        ]
    }
}
