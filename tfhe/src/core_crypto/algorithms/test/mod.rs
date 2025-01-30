pub mod params;
use super::misc::check_encrypted_content_respects_mod;
use crate::core_crypto::algorithms::misc::divide_round;
use crate::core_crypto::keycache::KeyCacheAccess;
use crate::core_crypto::prelude::*;
#[cfg(feature = "gpu")]
use crate::shortint::parameters::ModulusSwitchNoiseReductionParams;
pub(crate) use params::*;
use std::fmt::Debug;

mod ggsw_encryption;
mod glwe_encryption;
mod glwe_linear_algebra;
mod glwe_sample_extraction;
mod lwe_bootstrap_key_generation;
mod lwe_compact_public_key_generation;
mod lwe_encryption;
mod lwe_keyswitch;
mod lwe_keyswitch_key_generation;
mod lwe_linear_algebra;
mod lwe_multi_bit_bootstrap_key_generation;
pub(crate) mod lwe_multi_bit_programmable_bootstrapping;
mod lwe_packing_keyswitch;
mod lwe_packing_keyswitch_key_generation;
mod lwe_private_functional_packing_keyswitch;
pub(crate) mod lwe_programmable_bootstrapping;
mod modulus_switch_compression;
mod modulus_switch_noise_reduction;
pub(crate) mod noise_distribution;

pub struct TestResources {
    pub seeder: Box<dyn Seeder>,
    pub encryption_random_generator: EncryptionRandomGenerator<DefaultRandomGenerator>,
    pub secret_random_generator: SecretRandomGenerator<DefaultRandomGenerator>,
}

impl TestResources {
    pub fn new() -> Self {
        let mut seeder = new_seeder();
        let encryption_random_generator =
            EncryptionRandomGenerator::new(seeder.seed(), seeder.as_mut());
        let secret_random_generator = SecretRandomGenerator::new(seeder.seed());
        Self {
            seeder,
            encryption_random_generator,
            secret_random_generator,
        }
    }
}

impl Default for TestResources {
    fn default() -> Self {
        Self::new()
    }
}

// DISCLAIMER: all parameters here are not guaranteed to be secure or yield correct computations
pub const TEST_PARAMS_4_BITS_NATIVE_U64: ClassicTestParams<u64> = ClassicTestParams {
    lwe_dimension: LweDimension(742),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.000007069849454709433,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.00000000000000029403601535432533,
    )),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(5),
    ks_base_log: DecompositionBaseLog(3),
    pfks_level: DecompositionLevelCount(1),
    pfks_base_log: DecompositionBaseLog(23),
    pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.00000000000000029403601535432533,
    )),
    cbs_level: DecompositionLevelCount(0),
    cbs_base_log: DecompositionBaseLog(0),
    message_modulus_log: MessageModulusLog(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
};

pub const TEST_PARAMS_3_BITS_63_U64: ClassicTestParams<u64> = ClassicTestParams {
    lwe_dimension: LweDimension(742),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.000007069849454709433,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.00000000000000029403601535432533,
    )),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(5),
    ks_base_log: DecompositionBaseLog(3),
    pfks_level: DecompositionLevelCount(1),
    pfks_base_log: DecompositionBaseLog(23),
    pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.00000000000000029403601535432533,
    )),
    cbs_level: DecompositionLevelCount(0),
    cbs_base_log: DecompositionBaseLog(0),
    message_modulus_log: MessageModulusLog(3),
    ciphertext_modulus: CiphertextModulus::new(1 << 63),
};

pub const TEST_PARAMS_3_BITS_SOLINAS_U64: ClassicTestParams<u64> = ClassicTestParams {
    lwe_dimension: LweDimension(742),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.000007069849454709433,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.00000000000000029403601535432533,
    )),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(5),
    ks_base_log: DecompositionBaseLog(3),
    pfks_level: DecompositionLevelCount(1),
    pfks_base_log: DecompositionBaseLog(23),
    pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.00000000000000029403601535432533,
    )),
    cbs_level: DecompositionLevelCount(0),
    cbs_base_log: DecompositionBaseLog(0),
    message_modulus_log: MessageModulusLog(3),
    ciphertext_modulus: CiphertextModulus::new((1 << 64) - (1 << 32) + 1),
};

pub const DUMMY_NATIVE_U32: ClassicTestParams<u32> = ClassicTestParams {
    lwe_dimension: LweDimension(742),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.000007069849454709433,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.00000000000000029403601535432533,
    )),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(5),
    ks_base_log: DecompositionBaseLog(3),
    pfks_level: DecompositionLevelCount(1),
    pfks_base_log: DecompositionBaseLog(23),
    pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.00000000000000029403601535432533,
    )),
    cbs_level: DecompositionLevelCount(0),
    cbs_base_log: DecompositionBaseLog(0),
    message_modulus_log: MessageModulusLog(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
};

pub const DUMMY_31_U32: ClassicTestParams<u32> = ClassicTestParams {
    lwe_dimension: LweDimension(742),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.000007069849454709433,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.00000000000000029403601535432533,
    )),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(5),
    ks_base_log: DecompositionBaseLog(3),
    pfks_level: DecompositionLevelCount(1),
    pfks_base_log: DecompositionBaseLog(23),
    pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.00000000000000029403601535432533,
    )),
    cbs_level: DecompositionLevelCount(0),
    cbs_base_log: DecompositionBaseLog(0),
    message_modulus_log: MessageModulusLog(3),
    ciphertext_modulus: CiphertextModulus::new(1 << 31),
};

pub const MULTI_BIT_2_2_2_PARAMS: MultiBitTestParams<u64> = MultiBitTestParams {
    input_lwe_dimension: LweDimension(818),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.000002226459789930014,
    )),
    decomp_base_log: DecompositionBaseLog(22),
    decomp_level_count: DecompositionLevelCount(1),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.0000000000000003152931493498455,
    )),
    message_modulus_log: MessageModulusLog(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    grouping_factor: LweBskGroupingFactor(2),
    thread_count: ThreadCount(5),
};

pub const MULTI_BIT_3_3_2_PARAMS: MultiBitTestParams<u64> = MultiBitTestParams {
    input_lwe_dimension: LweDimension(922),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.0000003272369292345697,
    )),
    decomp_base_log: DecompositionBaseLog(14),
    decomp_level_count: DecompositionLevelCount(2),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.0000000000000000002168404344971009,
    )),
    message_modulus_log: MessageModulusLog(6),
    ciphertext_modulus: CiphertextModulus::new_native(),
    grouping_factor: LweBskGroupingFactor(2),
    thread_count: ThreadCount(5),
};

pub const MULTI_BIT_2_2_2_CUSTOM_MOD_PARAMS: MultiBitTestParams<u64> = MultiBitTestParams {
    input_lwe_dimension: LweDimension(818),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.000002226459789930014,
    )),
    decomp_base_log: DecompositionBaseLog(22),
    decomp_level_count: DecompositionLevelCount(1),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.0000000000000003152931493498455,
    )),
    message_modulus_log: MessageModulusLog(3),
    ciphertext_modulus: CiphertextModulus::new(1 << 63),
    grouping_factor: LweBskGroupingFactor(2),
    thread_count: ThreadCount(5),
};

pub const MULTI_BIT_2_2_3_PARAMS: MultiBitTestParams<u64> = MultiBitTestParams {
    input_lwe_dimension: LweDimension(888),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.0000006125031601933181,
    )),
    decomp_base_log: DecompositionBaseLog(21),
    decomp_level_count: DecompositionLevelCount(1),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.0000000000000003152931493498455,
    )),
    message_modulus_log: MessageModulusLog(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    grouping_factor: LweBskGroupingFactor(3),
    thread_count: ThreadCount(12),
};

pub const MULTI_BIT_3_3_3_PARAMS: MultiBitTestParams<u64> = MultiBitTestParams {
    input_lwe_dimension: LweDimension(972),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.00000013016688349592805,
    )),
    decomp_base_log: DecompositionBaseLog(14),
    decomp_level_count: DecompositionLevelCount(2),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.0000000000000000002168404344971009,
    )),
    message_modulus_log: MessageModulusLog(6),
    ciphertext_modulus: CiphertextModulus::new_native(),
    grouping_factor: LweBskGroupingFactor(3),
    thread_count: ThreadCount(5),
};

pub const MULTI_BIT_2_2_3_CUSTOM_MOD_PARAMS: MultiBitTestParams<u64> = MultiBitTestParams {
    input_lwe_dimension: LweDimension(888),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.0000006125031601933181,
    )),
    decomp_base_log: DecompositionBaseLog(21),
    decomp_level_count: DecompositionLevelCount(1),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.0000000000000003152931493498455,
    )),
    message_modulus_log: MessageModulusLog(3),
    ciphertext_modulus: CiphertextModulus::new(1 << 63),
    grouping_factor: LweBskGroupingFactor(3),
    thread_count: ThreadCount(12),
};

// DISCLAIMER: example parameters tailored for FFT implementation tests. There are not guaranteed
// to be secure or yield correct computations.
// Define the parameters for a 4 bits message able to hold the doubled 2 bits message.
pub const FFT_U32_PARAMS: FftTestParams<u32> = FftTestParams {
    lwe_dimension: LweDimension(742),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.00000000004998277131225527,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.00000000000000000000000000000008645717832544903,
    )),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ciphertext_modulus: CiphertextModulus::new_native(),
};

pub const FFT_U64_PARAMS: FftTestParams<u64> = FftTestParams {
    lwe_dimension: LweDimension(742),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.00000000004998277131225527,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.00000000000000000000000000000008645717832544903,
    )),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ciphertext_modulus: CiphertextModulus::new_native(),
};

pub const FFT_U128_PARAMS: FftTestParams<u128> = FftTestParams {
    lwe_dimension: LweDimension(742),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.00000000004998277131225527,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.00000000000000000000000000000008645717832544903,
    )),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ciphertext_modulus: CiphertextModulus::new_native(),
};

pub const FFT128_U128_PARAMS: FftTestParams<u128> = FftTestParams {
    lwe_dimension: LweDimension(742),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(0.12345)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.00000000000000000000000000000008645717832544903,
    )),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ciphertext_modulus: CiphertextModulus::<u128>::new_native(),
};

pub const FFT_WOPBS_PARAMS: FftWopPbsTestParams<u64> = FftWopPbsTestParams {
    lwe_dimension: LweDimension(481),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(1024),
    // Value was 0.000_000_000_000_000_221_486_881_160_055_68_513645324585951
    // But rust indicates it gets truncated anyways to
    // 0.000_000_000_000_000_221_486_881_160_055_68
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.000_000_000_000_000_221_486_881_160_055_68,
    )),
    // Value was 0.000_061_200_133_780_220_371_345
    // But rust indicates it gets truncated anyways to
    // 0.000_061_200_133_780_220_36
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.000_061_200_133_780_220_36,
    )),
    pbs_base_log: DecompositionBaseLog(4),
    pbs_level: DecompositionLevelCount(9),
    pfks_level: DecompositionLevelCount(9),
    pfks_base_log: DecompositionBaseLog(4),
    cbs_level: DecompositionLevelCount(4),
    cbs_base_log: DecompositionBaseLog(6),
    ciphertext_modulus: CiphertextModulus::new_native(),
};

pub const FFT_WOPBS_N512_PARAMS: FftWopPbsTestParams<u64> = FftWopPbsTestParams {
    lwe_dimension: LweDimension(4),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(512),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.000_000_000_000_000_221_486_881_160_055_68,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.000_061_200_133_780_220_36,
    )),
    pbs_base_log: DecompositionBaseLog(9),
    pbs_level: DecompositionLevelCount(4),
    pfks_level: DecompositionLevelCount(2),
    pfks_base_log: DecompositionBaseLog(15),
    cbs_level: DecompositionLevelCount(4),
    cbs_base_log: DecompositionBaseLog(6),
    ciphertext_modulus: CiphertextModulus::new_native(),
};

pub const FFT_WOPBS_N1024_PARAMS: FftWopPbsTestParams<u64> = FftWopPbsTestParams {
    lwe_dimension: LweDimension(4),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.000_000_000_000_000_221_486_881_160_055_68,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.000_061_200_133_780_220_36,
    )),
    pbs_base_log: DecompositionBaseLog(9),
    pbs_level: DecompositionLevelCount(4),
    pfks_level: DecompositionLevelCount(2),
    pfks_base_log: DecompositionBaseLog(15),
    cbs_level: DecompositionLevelCount(4),
    cbs_base_log: DecompositionBaseLog(6),
    ciphertext_modulus: CiphertextModulus::new_native(),
};

pub const FFT_WOPBS_N2048_PARAMS: FftWopPbsTestParams<u64> = FftWopPbsTestParams {
    lwe_dimension: LweDimension(4),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.000_000_000_000_000_221_486_881_160_055_68,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.000_061_200_133_780_220_36,
    )),
    pbs_base_log: DecompositionBaseLog(9),
    pbs_level: DecompositionLevelCount(4),
    pfks_level: DecompositionLevelCount(2),
    pfks_base_log: DecompositionBaseLog(15),
    cbs_level: DecompositionLevelCount(4),
    cbs_base_log: DecompositionBaseLog(6),
    ciphertext_modulus: CiphertextModulus::new_native(),
};

#[cfg(feature = "gpu")]
pub const NOISESQUASHING128_U128_GPU_PARAMS: NoiseSquashingTestParams<u128> =
    NoiseSquashingTestParams {
        lwe_dimension: LweDimension(879),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(2048),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(46),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(30),
        pbs_base_log: DecompositionBaseLog(24),
        pbs_level: DecompositionLevelCount(3),
        modulus_switch_noise_reduction_params: Some(ModulusSwitchNoiseReductionParams {
            modulus_switch_zeros_count: LweCiphertextCount(1449),
            ms_bound: NoiseEstimationMeasureBound(288230376151711744f64),
            ms_r_sigma_factor: RSigmaFactor(13.179852282053789f64),
            ms_input_variance: Variance(2.63039184094559E-7f64),
        }),
        ciphertext_modulus: CiphertextModulus::new_native(),
    };

pub fn get_encoding_with_padding<Scalar: UnsignedInteger>(
    ciphertext_modulus: CiphertextModulus<Scalar>,
) -> Scalar {
    if ciphertext_modulus.is_native_modulus() {
        Scalar::ONE << (Scalar::BITS - 1)
    } else {
        Scalar::cast_from(ciphertext_modulus.get_custom_modulus() / 2)
    }
}

pub fn round_decode<Scalar: UnsignedInteger>(decrypted: Scalar, delta: Scalar) -> Scalar {
    divide_round(decrypted, delta)
}

pub(crate) fn gen_keys_or_get_from_cache_if_enabled<
    P: Debug + KeyCacheAccess<Keys = K> + serde::Serialize + serde::de::DeserializeOwned,
    K: serde::de::DeserializeOwned + serde::Serialize + Clone,
>(
    params: P,
    keygen_func: &mut dyn FnMut(P) -> K,
) -> K {
    #[cfg(feature = "internal-keycache")]
    {
        crate::core_crypto::keycache::KEY_CACHE.get_key_with_closure(params, keygen_func)
    }
    #[cfg(not(feature = "internal-keycache"))]
    {
        keygen_func(params)
    }
}

// Macro to generate tests for all parameter sets
macro_rules! create_parameterized_test{
    ($name:ident { $($param:ident),*  $(,)? }) => {
        ::paste::paste! {
            $(
            #[test]
            fn [<test_ $name _ $param:lower>]() {
                $name($param)
            }
            )*
        }
    };
    ($name:ident)=> {
        create_parameterized_test!($name
        {
            TEST_PARAMS_4_BITS_NATIVE_U64,
            TEST_PARAMS_3_BITS_63_U64
        });
    };
}

// Macro to generate tests for all parameter sets
macro_rules! create_parameterized_test_with_non_native_parameters {
    ($name:ident) => {
        create_parameterized_test!($name {
            TEST_PARAMS_4_BITS_NATIVE_U64,
            TEST_PARAMS_3_BITS_63_U64,
            TEST_PARAMS_3_BITS_SOLINAS_U64
        });
    };
}

pub(crate) use {create_parameterized_test, create_parameterized_test_with_non_native_parameters};
