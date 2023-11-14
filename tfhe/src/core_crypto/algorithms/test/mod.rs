pub mod params;
pub(crate) use params::*;

pub use super::misc::check_encrypted_content_respects_mod;
use crate::core_crypto::algorithms::misc::divide_round;
use crate::core_crypto::keycache::KeyCacheAccess;
use crate::core_crypto::prelude::*;
use paste::paste;
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
mod noise_distribution;

pub struct TestResources {
    pub seeder: Box<dyn Seeder>,
    pub encryption_random_generator: EncryptionRandomGenerator<ActivatedRandomGenerator>,
    pub secret_random_generator: SecretRandomGenerator<ActivatedRandomGenerator>,
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
    lwe_modular_std_dev: StandardDev(0.000007069849454709433),
    glwe_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(5),
    ks_base_log: DecompositionBaseLog(3),
    pfks_level: DecompositionLevelCount(1),
    pfks_base_log: DecompositionBaseLog(23),
    pfks_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
    cbs_level: DecompositionLevelCount(0),
    cbs_base_log: DecompositionBaseLog(0),
    message_modulus_log: CiphertextModulusLog(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
};

pub const TEST_PARAMS_3_BITS_63_U64: ClassicTestParams<u64> = ClassicTestParams {
    lwe_dimension: LweDimension(742),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_modular_std_dev: StandardDev(0.000007069849454709433),
    glwe_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(5),
    ks_base_log: DecompositionBaseLog(3),
    pfks_level: DecompositionLevelCount(1),
    pfks_base_log: DecompositionBaseLog(23),
    pfks_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
    cbs_level: DecompositionLevelCount(0),
    cbs_base_log: DecompositionBaseLog(0),
    message_modulus_log: CiphertextModulusLog(3),
    ciphertext_modulus: CiphertextModulus::new(1 << 63),
};

pub const TEST_PARAMS_3_BITS_SOLINAS_U64: ClassicTestParams<u64> = ClassicTestParams {
    lwe_dimension: LweDimension(742),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_modular_std_dev: StandardDev(0.000007069849454709433),
    glwe_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(5),
    ks_base_log: DecompositionBaseLog(3),
    pfks_level: DecompositionLevelCount(1),
    pfks_base_log: DecompositionBaseLog(23),
    pfks_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
    cbs_level: DecompositionLevelCount(0),
    cbs_base_log: DecompositionBaseLog(0),
    message_modulus_log: CiphertextModulusLog(3),
    ciphertext_modulus: CiphertextModulus::new((1 << 64) - (1 << 32) + 1),
};

pub const DUMMY_NATIVE_U32: ClassicTestParams<u32> = ClassicTestParams {
    lwe_dimension: LweDimension(742),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_modular_std_dev: StandardDev(0.000007069849454709433),
    glwe_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(5),
    ks_base_log: DecompositionBaseLog(3),
    pfks_level: DecompositionLevelCount(1),
    pfks_base_log: DecompositionBaseLog(23),
    pfks_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
    cbs_level: DecompositionLevelCount(0),
    cbs_base_log: DecompositionBaseLog(0),
    message_modulus_log: CiphertextModulusLog(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
};

pub const DUMMY_31_U32: ClassicTestParams<u32> = ClassicTestParams {
    lwe_dimension: LweDimension(742),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_modular_std_dev: StandardDev(0.000007069849454709433),
    glwe_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(5),
    ks_base_log: DecompositionBaseLog(3),
    pfks_level: DecompositionLevelCount(1),
    pfks_base_log: DecompositionBaseLog(23),
    pfks_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
    cbs_level: DecompositionLevelCount(0),
    cbs_base_log: DecompositionBaseLog(0),
    message_modulus_log: CiphertextModulusLog(3),
    ciphertext_modulus: CiphertextModulus::new(1 << 31),
};

pub const MULTI_BIT_2_2_2_PARAMS: MultiBitTestParams<u64> = MultiBitTestParams {
    input_lwe_dimension: LweDimension(818),
    lwe_modular_std_dev: StandardDev(0.000002226459789930014),
    decomp_base_log: DecompositionBaseLog(22),
    decomp_level_count: DecompositionLevelCount(1),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    glwe_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    message_modulus_log: CiphertextModulusLog(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    grouping_factor: LweBskGroupingFactor(2),
    thread_count: ThreadCount(5),
};

pub const MULTI_BIT_2_2_2_CUSTOM_MOD_PARAMS: MultiBitTestParams<u64> = MultiBitTestParams {
    input_lwe_dimension: LweDimension(818),
    lwe_modular_std_dev: StandardDev(0.000002226459789930014),
    decomp_base_log: DecompositionBaseLog(22),
    decomp_level_count: DecompositionLevelCount(1),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    glwe_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    message_modulus_log: CiphertextModulusLog(3),
    ciphertext_modulus: CiphertextModulus::new(1 << 63),
    grouping_factor: LweBskGroupingFactor(2),
    thread_count: ThreadCount(5),
};

pub const MULTI_BIT_2_2_3_PARAMS: MultiBitTestParams<u64> = MultiBitTestParams {
    input_lwe_dimension: LweDimension(888),
    lwe_modular_std_dev: StandardDev(0.0000006125031601933181),
    decomp_base_log: DecompositionBaseLog(21),
    decomp_level_count: DecompositionLevelCount(1),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    glwe_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    message_modulus_log: CiphertextModulusLog(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    grouping_factor: LweBskGroupingFactor(3),
    thread_count: ThreadCount(12),
};

pub const MULTI_BIT_2_2_3_CUSTOM_MOD_PARAMS: MultiBitTestParams<u64> = MultiBitTestParams {
    input_lwe_dimension: LweDimension(888),
    lwe_modular_std_dev: StandardDev(0.0000006125031601933181),
    decomp_base_log: DecompositionBaseLog(21),
    decomp_level_count: DecompositionLevelCount(1),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    glwe_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    message_modulus_log: CiphertextModulusLog(3),
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
    lwe_modular_std_dev: StandardDev(0.00000000004998277131225527),
    glwe_modular_std_dev: StandardDev(0.00000000000000000000000000000008645717832544903),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ciphertext_modulus: CiphertextModulus::new_native(),
};

pub const FFT_U64_PARAMS: FftTestParams<u64> = FftTestParams {
    lwe_dimension: LweDimension(742),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_modular_std_dev: StandardDev(0.00000000004998277131225527),
    glwe_modular_std_dev: StandardDev(0.00000000000000000000000000000008645717832544903),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ciphertext_modulus: CiphertextModulus::new_native(),
};

pub const FFT_U128_PARAMS: FftTestParams<u128> = FftTestParams {
    lwe_dimension: LweDimension(742),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_modular_std_dev: StandardDev(0.00000000004998277131225527),
    glwe_modular_std_dev: StandardDev(0.00000000000000000000000000000008645717832544903),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ciphertext_modulus: CiphertextModulus::new_native(),
};

pub const FFT128_U128_PARAMS: FftTestParams<u128> = FftTestParams {
    lwe_dimension: LweDimension(742),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_modular_std_dev: StandardDev(0.12345),
    glwe_modular_std_dev: StandardDev(0.00000000000000000000000000000008645717832544903),
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
    lwe_modular_std_dev: StandardDev(0.000_000_000_000_000_221_486_881_160_055_68),
    // Value was 0.000_061_200_133_780_220_371_345
    // But rust indicates it gets truncated anyways to
    // 0.000_061_200_133_780_220_36
    glwe_modular_std_dev: StandardDev(0.000_061_200_133_780_220_36),
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
    lwe_modular_std_dev: StandardDev(0.000_000_000_000_000_221_486_881_160_055_68),
    glwe_modular_std_dev: StandardDev(0.000_061_200_133_780_220_36),
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
    lwe_modular_std_dev: StandardDev(0.000_000_000_000_000_221_486_881_160_055_68),
    glwe_modular_std_dev: StandardDev(0.000_061_200_133_780_220_36),
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
    lwe_modular_std_dev: StandardDev(0.000_000_000_000_000_221_486_881_160_055_68),
    glwe_modular_std_dev: StandardDev(0.000_061_200_133_780_220_36),
    pbs_base_log: DecompositionBaseLog(9),
    pbs_level: DecompositionLevelCount(4),
    pfks_level: DecompositionLevelCount(2),
    pfks_base_log: DecompositionBaseLog(15),
    cbs_level: DecompositionLevelCount(4),
    cbs_base_log: DecompositionBaseLog(6),
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

// Here we will define a helper function to generate an accumulator for a PBS
fn generate_accumulator<F, Scalar: UnsignedTorus + CastFrom<usize>>(
    polynomial_size: PolynomialSize,
    glwe_size: GlweSize,
    message_modulus: usize,
    ciphertext_modulus: CiphertextModulus<Scalar>,
    delta: Scalar,
    f: F,
) -> GlweCiphertextOwned<Scalar>
where
    F: Fn(Scalar) -> Scalar,
{
    // N/(p/2) = size of each block, to correct noise from the input we introduce the
    // notion of box, which manages redundancy to yield a denoised value
    // for several noisy values around a true input value.
    let box_size = polynomial_size.0 / message_modulus;

    // Create the accumulator
    let mut accumulator_scalar = vec![Scalar::ZERO; polynomial_size.0];

    // Fill each box with the encoded denoised value
    for i in 0..message_modulus {
        let index = i * box_size;
        accumulator_scalar[index..index + box_size]
            .iter_mut()
            .for_each(|a| *a = f(Scalar::cast_from(i)) * delta);
    }

    let half_box_size = box_size / 2;

    if ciphertext_modulus.is_compatible_with_native_modulus() {
        // Negate the first half_box_size coefficients to manage negacyclicity and rotate
        for a_i in accumulator_scalar[0..half_box_size].iter_mut() {
            *a_i = (*a_i).wrapping_neg();
        }
    } else {
        let modulus: Scalar = ciphertext_modulus.get_custom_modulus().cast_into();
        for a_i in accumulator_scalar[0..half_box_size].iter_mut() {
            *a_i = (*a_i).wrapping_neg_custom_mod(modulus);
        }
    }

    // Rotate the accumulator
    accumulator_scalar.rotate_left(half_box_size);

    let accumulator_plaintext = PlaintextList::from_container(accumulator_scalar);

    allocate_and_trivially_encrypt_new_glwe_ciphertext(
        glwe_size,
        &accumulator_plaintext,
        ciphertext_modulus,
    )
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
macro_rules! create_parametrized_test{
    ($name:ident { $($param:ident),*  $(,)? }) => {
        paste! {
            $(
            #[test]
            fn [<test_ $name _ $param:lower>]() {
                $name($param)
            }
            )*
        }
    };
     ($name:ident)=> {
        create_parametrized_test!($name
        {
            TEST_PARAMS_4_BITS_NATIVE_U64,
            TEST_PARAMS_3_BITS_63_U64
        });
    };
}

// Macro to generate tests for all parameter sets
macro_rules! create_parametrized_test_with_non_native_parameters {
    ($name:ident) => {
        create_parametrized_test!($name {
            TEST_PARAMS_4_BITS_NATIVE_U64,
            TEST_PARAMS_3_BITS_63_U64,
            TEST_PARAMS_3_BITS_SOLINAS_U64
        });
    };
}

use {create_parametrized_test, create_parametrized_test_with_non_native_parameters};
