use crate::core_crypto::prelude::*;
use paste::paste;

mod ggsw_encryption;
mod glwe_encryption;
mod lwe_bootstrap_key_generation;
mod lwe_compact_public_key_generation;
mod lwe_encryption;
mod lwe_keyswitch;
mod lwe_keyswitch_key_generation;
mod lwe_linear_algebra;
mod lwe_multi_bit_bootstrap_key_generation;
mod lwe_multi_bit_programmable_bootstrapping;
mod lwe_packing_keyswitch;
mod lwe_packing_keyswitch_key_generation;
mod lwe_private_functional_packing_keyswitch;
mod lwe_programmable_bootstrapping;
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

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct TestParams<Scalar: UnsignedTorus> {
    pub lwe_dimension: LweDimension,
    pub glwe_dimension: GlweDimension,
    pub polynomial_size: PolynomialSize,
    pub lwe_modular_std_dev: StandardDev,
    pub glwe_modular_std_dev: StandardDev,
    pub pbs_base_log: DecompositionBaseLog,
    pub pbs_level: DecompositionLevelCount,
    pub ks_base_log: DecompositionBaseLog,
    pub ks_level: DecompositionLevelCount,
    pub pfks_level: DecompositionLevelCount,
    pub pfks_base_log: DecompositionBaseLog,
    pub pfks_modular_std_dev: StandardDev,
    pub cbs_level: DecompositionLevelCount,
    pub cbs_base_log: DecompositionBaseLog,
    pub message_modulus_log: CiphertextModulusLog,
    pub ciphertext_modulus: CiphertextModulus<Scalar>,
}

// DISCLAIMER: all parameters here are not guaranteed to be secure or yield correct computations
pub const TEST_PARAMS_4_BITS_NATIVE_U64: TestParams<u64> = TestParams {
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

pub const TEST_PARAMS_3_BITS_63_U64: TestParams<u64> = TestParams {
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
    ciphertext_modulus: unsafe { CiphertextModulus::new_unchecked(1 << 63) },
};

pub const DUMMY_NATIVE_U32: TestParams<u32> = TestParams {
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

pub const DUMMY_31_U32: TestParams<u32> = TestParams {
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
    ciphertext_modulus: unsafe { CiphertextModulus::new_unchecked(1 << 31) },
};

// Our representation of non native power of 2 moduli puts the information in the MSBs and leaves
// the LSBs empty, this is what this function is checking
pub fn check_content_respects_mod<Scalar: UnsignedInteger, Input: AsRef<[Scalar]>>(
    input: &Input,
    modulus: CiphertextModulus<Scalar>,
) -> bool {
    if !modulus.is_native_modulus() {
        // If our modulus is 2^60, the scaling is 2^4 = 00...00010000, minus 1 = 00...00001111
        // we want the bits under the mask to be 0
        let power_2_diff_mask = modulus.get_power_of_two_scaling_to_native_torus() - Scalar::ONE;
        return input
            .as_ref()
            .iter()
            .all(|&x| (x & power_2_diff_mask) == Scalar::ZERO);
    }

    true
}

// See above
pub fn check_scalar_respects_mod<Scalar: UnsignedInteger>(
    input: Scalar,
    modulus: CiphertextModulus<Scalar>,
) -> bool {
    if !modulus.is_native_modulus() {
        let power_2_diff_mask = modulus.get_power_of_two_scaling_to_native_torus() - Scalar::ONE;
        return (input & power_2_diff_mask) == Scalar::ZERO;
    }

    true
}

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
    // Get half interval on the discretized torus
    let rounding_margin = delta.wrapping_div(Scalar::TWO);

    // Add the half interval mapping
    // [delta * (m - 1/2); delta * (m + 1/2)[ to [delta * m; delta * (m + 1)[
    // Dividing by delta gives m which is what we want
    (decrypted.wrapping_add(rounding_margin)).wrapping_div(delta)
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

    // Negate the first half_box_size coefficients to manage negacyclicity and rotate
    for a_i in accumulator_scalar[0..half_box_size].iter_mut() {
        *a_i = (*a_i).wrapping_neg();
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

// Macro to generate tests for all parameter sets
macro_rules! create_parametrized_test{
    ($name:ident { $($param:ident),* }) => {
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

use create_parametrized_test;
