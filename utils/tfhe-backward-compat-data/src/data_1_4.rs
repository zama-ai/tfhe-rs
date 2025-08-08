use crate::generate::{
    store_versioned_test_tfhe_1_4, TfhersVersion,
    INSECURE_SMALL_TEST_NOISE_SQUASHING_PARAMS_MULTI_BIT, INSECURE_SMALL_TEST_PARAMS_MULTI_BIT,
};
use crate::{
    HlClientKeyTest, HlServerKeyTest, HlSquashedNoiseUnsignedCiphertextTest, TestDistribution,
    TestMetadata, TestMultiBitParameterSet, TestNoiseSquashingParamsMultiBit, TestParameterSet,
    HL_MODULE_NAME,
};
use std::borrow::Cow;
use std::fs::create_dir_all;

use tfhe_1_4::boolean::engine::BooleanEngine;
use tfhe_1_4::core_crypto::commons::generators::DeterministicSeeder;

use tfhe_1_4::core_crypto::prelude::DefaultRandomGenerator;
use tfhe_1_4::prelude::*;
use tfhe_1_4::shortint::engine::ShortintEngine;
use tfhe_1_4::shortint::parameters::noise_squashing::NoiseSquashingMultiBitParameters;
use tfhe_1_4::shortint::parameters::{
    CarryModulus, CiphertextModulus, CoreCiphertextModulus, DecompositionBaseLog,
    DecompositionLevelCount, DynamicDistribution, EncryptionKeyChoice, GlweDimension,
    LweBskGroupingFactor, LweDimension, MaxNoiseLevel, MessageModulus, NoiseSquashingParameters,
    PolynomialSize, StandardDev,
};
use tfhe_1_4::shortint::{AtomicPatternParameters, MultiBitPBSParameters};
use tfhe_1_4::{set_server_key, ClientKey, FheUint32, Seed, ServerKey};

macro_rules! store_versioned_test {
    ($msg:expr, $dir:expr, $test_filename:expr $(,)? ) => {
        store_versioned_test_tfhe_1_4($msg, $dir, $test_filename)
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
            TestParameterSet::TestClassicParameterSet(_) => {
                unreachable!()
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

const TEST_FILENAME: Cow<'static, str> = Cow::Borrowed("client_key_with_noise_squashing");

const HL_CLIENTKEY_WITH_NOISE_SQUASHING_TEST: HlClientKeyTest = HlClientKeyTest {
    test_filename: TEST_FILENAME,
    parameters: INSECURE_SMALL_TEST_PARAMS_MULTI_BIT,
};

const HL_SERVERKEY_TEST: HlServerKeyTest = HlServerKeyTest {
    test_filename: Cow::Borrowed("server_key_with_noise_squashing"),
    client_key_filename: TEST_FILENAME,
    compressed: false,
};

const HL_SQUASHED_NOISE_UNSIGNED_CIPHERTEXT_TEST: HlSquashedNoiseUnsignedCiphertextTest =
    HlSquashedNoiseUnsignedCiphertextTest {
        test_filename: Cow::Borrowed("squashed_noise_unsigned_ciphertext"),
        key_filename: Cow::Borrowed("client_key_with_noise_squashing"),
        clear_value: 42,
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

        let config = tfhe_1_4::ConfigBuilder::with_custom_parameters(
            HL_CLIENTKEY_WITH_NOISE_SQUASHING_TEST.parameters,
        )
        .build();

        let (hl_client_key, hl_server_key) = tfhe_1_4::generate_keys(config);

        store_versioned_test!(
            &hl_client_key,
            &dir,
            &HL_CLIENTKEY_WITH_NOISE_SQUASHING_TEST.test_filename
        );
        store_versioned_test!(&hl_server_key, &dir, &HL_SERVERKEY_TEST.test_filename,);

        // Generate data for the squashed noise compressed ciphertext list
        {
            let config = tfhe_1_4::ConfigBuilder::with_custom_parameters(
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
                &ns,
                &dir,
                &HL_SQUASHED_NOISE_UNSIGNED_CIPHERTEXT_TEST.test_filename,
            );
        };

        vec![
            TestMetadata::HlClientKey(HL_CLIENTKEY_WITH_NOISE_SQUASHING_TEST),
            TestMetadata::HlServerKey(HL_SERVERKEY_TEST),
            TestMetadata::HlSquashedNoiseUnsignedCiphertext(
                HL_SQUASHED_NOISE_UNSIGNED_CIPHERTEXT_TEST,
            ),
        ]
    }
}
