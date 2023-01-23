use crate::core_crypto::prelude::*;
use paste::paste;

mod lwe_encryption;
mod lwe_keyswitch;
mod lwe_linear_algebra;

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
    lwe_modular_std_dev: StandardDev(1.0e-100),
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
    ciphertext_modulus: CiphertextModulus::new_unchecked(1 << 63),
};

pub const TEST_PARAMS_3_BITS_SOLINAS_U64: TestParams<u64> = TestParams {
    lwe_dimension: LweDimension(742),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_modular_std_dev: StandardDev(1.0e-100),
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
    ciphertext_modulus: CiphertextModulus::new_unchecked((1 << 64) - (1 << 32) + 1),
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
    ciphertext_modulus: CiphertextModulus::new_unchecked(1 << 31),
};

pub fn cast_into_u128<Scalar: CastInto<u128>>(val: Scalar) -> u128 {
    val.cast_into()
}

pub fn check_content_respects_mod<Scalar: UnsignedInteger, Input: AsRef<[Scalar]>>(
    input: &Input,
    modulus: CiphertextModulus<Scalar>,
) -> bool {
    if !modulus.is_native_modulus() {
        return input
            .as_ref()
            .iter()
            .all(|&x| cast_into_u128(x) < modulus.get());
    }

    true
}

pub fn check_scalar_respects_mod<Scalar: UnsignedInteger>(
    input: Scalar,
    modulus: CiphertextModulus<Scalar>,
) -> bool {
    if !modulus.is_native_modulus() {
        return cast_into_u128(input) < modulus.get();
    }

    true
}

pub fn get_encoding_with_padding<Scalar: UnsignedInteger>(
    ciphertext_modulus: CiphertextModulus<Scalar>,
) -> u128 {
    if ciphertext_modulus.is_native_modulus() {
        1 << (Scalar::BITS - 1)
    } else {
        ciphertext_modulus.get() / 2
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
            TEST_PARAMS_3_BITS_63_U64,
            TEST_PARAMS_3_BITS_SOLINAS_U64
        });
    };
}

pub(self) use create_parametrized_test;
