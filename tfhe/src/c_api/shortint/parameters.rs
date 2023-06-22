use crate::c_api::utils::*;
pub use crate::core_crypto::commons::dispersion::StandardDev;
pub use crate::core_crypto::commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
};
pub use crate::shortint::parameters::parameters_compact_pk::*;
pub use crate::shortint::parameters::*;
use std::os::raw::c_int;

use crate::shortint;

#[repr(C)]
#[derive(Copy, Clone)]
pub enum ShortintEncryptionKeyChoice {
    ShortintEncryptionKeyChoiceBig,
    ShortintEncryptionKeyChoiceSmall,
}

impl From<ShortintEncryptionKeyChoice> for crate::shortint::parameters::EncryptionKeyChoice {
    fn from(value: ShortintEncryptionKeyChoice) -> Self {
        match value {
            ShortintEncryptionKeyChoice::ShortintEncryptionKeyChoiceBig => {
                shortint::parameters::EncryptionKeyChoice::Big
            }
            ShortintEncryptionKeyChoice::ShortintEncryptionKeyChoiceSmall => {
                shortint::parameters::EncryptionKeyChoice::Small
            }
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ShortintPBSParameters {
    pub lwe_dimension: usize,
    pub glwe_dimension: usize,
    pub polynomial_size: usize,
    pub lwe_modular_std_dev: f64,
    pub glwe_modular_std_dev: f64,
    pub pbs_base_log: usize,
    pub pbs_level: usize,
    pub ks_base_log: usize,
    pub ks_level: usize,
    pub message_modulus: usize,
    pub carry_modulus: usize,
    pub modulus_power_of_2_exponent: usize,
    pub encryption_key_choice: ShortintEncryptionKeyChoice,
}

impl From<ShortintPBSParameters> for crate::shortint::ClassicPBSParameters {
    fn from(c_params: ShortintPBSParameters) -> Self {
        Self {
            lwe_dimension: LweDimension(c_params.lwe_dimension),
            glwe_dimension: GlweDimension(c_params.glwe_dimension),
            polynomial_size: PolynomialSize(c_params.polynomial_size),
            lwe_modular_std_dev: StandardDev(c_params.lwe_modular_std_dev),
            glwe_modular_std_dev: StandardDev(c_params.glwe_modular_std_dev),
            pbs_base_log: DecompositionBaseLog(c_params.pbs_base_log),
            pbs_level: DecompositionLevelCount(c_params.pbs_level),
            ks_base_log: DecompositionBaseLog(c_params.ks_base_log),
            ks_level: DecompositionLevelCount(c_params.ks_level),
            message_modulus: crate::shortint::parameters::MessageModulus(c_params.message_modulus),
            carry_modulus: crate::shortint::parameters::CarryModulus(c_params.carry_modulus),
            ciphertext_modulus: crate::shortint::parameters::CiphertextModulus::try_new_power_of_2(
                c_params.modulus_power_of_2_exponent,
            )
            .unwrap(),
            encryption_key_choice: c_params.encryption_key_choice.into(),
        }
    }
}

impl From<crate::shortint::ClassicPBSParameters> for ShortintPBSParameters {
    fn from(rust_params: crate::shortint::ClassicPBSParameters) -> Self {
        Self::convert(rust_params)
    }
}

impl ShortintEncryptionKeyChoice {
    // From::from cannot be marked as const, so we have to have
    // our own function
    const fn convert(rust_choice: crate::shortint::EncryptionKeyChoice) -> Self {
        match rust_choice {
            crate::shortint::EncryptionKeyChoice::Big => Self::ShortintEncryptionKeyChoiceBig,
            crate::shortint::EncryptionKeyChoice::Small => Self::ShortintEncryptionKeyChoiceSmall,
        }
    }
}

const fn convert_modulus(rust_modulus: crate::shortint::CiphertextModulus) -> usize {
    if rust_modulus.is_native_modulus() {
        64 // shortints are on 64 bits
    } else {
        assert!(rust_modulus.is_power_of_two());
        let modulus = rust_modulus.get_custom_modulus();
        let exponent = modulus.ilog2() as usize;
        assert!(exponent <= 64);
        exponent
    }
}

impl ShortintPBSParameters {
    const fn convert(rust_params: crate::shortint::ClassicPBSParameters) -> Self {
        Self {
            lwe_dimension: rust_params.lwe_dimension.0,
            glwe_dimension: rust_params.glwe_dimension.0,
            polynomial_size: rust_params.polynomial_size.0,
            lwe_modular_std_dev: rust_params.lwe_modular_std_dev.0,
            glwe_modular_std_dev: rust_params.glwe_modular_std_dev.0,
            pbs_base_log: rust_params.pbs_base_log.0,
            pbs_level: rust_params.pbs_level.0,
            ks_base_log: rust_params.ks_base_log.0,
            ks_level: rust_params.ks_level.0,
            message_modulus: rust_params.message_modulus.0,
            carry_modulus: rust_params.carry_modulus.0,
            modulus_power_of_2_exponent: convert_modulus(rust_params.ciphertext_modulus),
            encryption_key_choice: ShortintEncryptionKeyChoice::convert(
                rust_params.encryption_key_choice,
            ),
        }
    }
}

macro_rules! expose_as_shortint_pbs_parameters(
    (
        $(
            $param_name:ident
        ),*
        $(,)?
    ) => {
        ::paste::paste!{
            $(
                #[no_mangle]
                pub static [<SHORTINT_ $param_name>]: ShortintPBSParameters =
                    ShortintPBSParameters::convert($param_name);

            )*
        }

        // Test that converting a param from its rust struct
        // to the c struct and then to the rust struct again
        // yields the same values as the original struct
        //
        // This is what will essentially happen in the real code
        #[test]
        fn test_shortint_pbs_parameters_roundtrip_c_rust() {
            $(
                // 1 scope for each parameters
                {
                    let rust_params = crate::shortint::parameters::$param_name;
                    let c_params = ShortintPBSParameters::from(rust_params);
                    let rust_params_from_c = crate::shortint::parameters::ClassicPBSParameters::from(c_params);
                    assert_eq!(rust_params, rust_params_from_c);
                }
            )*
        }
    }
);

expose_as_shortint_pbs_parameters!(
    PARAM_MESSAGE_1_CARRY_0_KS_PBS,
    PARAM_MESSAGE_1_CARRY_1_KS_PBS,
    PARAM_MESSAGE_2_CARRY_0_KS_PBS,
    PARAM_MESSAGE_1_CARRY_2_KS_PBS,
    PARAM_MESSAGE_2_CARRY_1_KS_PBS,
    PARAM_MESSAGE_3_CARRY_0_KS_PBS,
    PARAM_MESSAGE_1_CARRY_3_KS_PBS,
    PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    PARAM_MESSAGE_3_CARRY_1_KS_PBS,
    PARAM_MESSAGE_4_CARRY_0_KS_PBS,
    PARAM_MESSAGE_1_CARRY_4_KS_PBS,
    PARAM_MESSAGE_2_CARRY_3_KS_PBS,
    PARAM_MESSAGE_3_CARRY_2_KS_PBS,
    PARAM_MESSAGE_4_CARRY_1_KS_PBS,
    PARAM_MESSAGE_5_CARRY_0_KS_PBS,
    PARAM_MESSAGE_1_CARRY_5_KS_PBS,
    PARAM_MESSAGE_2_CARRY_4_KS_PBS,
    PARAM_MESSAGE_3_CARRY_3_KS_PBS,
    PARAM_MESSAGE_4_CARRY_2_KS_PBS,
    PARAM_MESSAGE_5_CARRY_1_KS_PBS,
    PARAM_MESSAGE_6_CARRY_0_KS_PBS,
    PARAM_MESSAGE_1_CARRY_6_KS_PBS,
    PARAM_MESSAGE_2_CARRY_5_KS_PBS,
    PARAM_MESSAGE_3_CARRY_4_KS_PBS,
    PARAM_MESSAGE_4_CARRY_3_KS_PBS,
    PARAM_MESSAGE_5_CARRY_2_KS_PBS,
    PARAM_MESSAGE_6_CARRY_1_KS_PBS,
    PARAM_MESSAGE_7_CARRY_0_KS_PBS,
    PARAM_MESSAGE_1_CARRY_7_KS_PBS,
    PARAM_MESSAGE_2_CARRY_6_KS_PBS,
    PARAM_MESSAGE_3_CARRY_5_KS_PBS,
    PARAM_MESSAGE_4_CARRY_4_KS_PBS,
    PARAM_MESSAGE_5_CARRY_3_KS_PBS,
    PARAM_MESSAGE_6_CARRY_2_KS_PBS,
    PARAM_MESSAGE_7_CARRY_1_KS_PBS,
    PARAM_MESSAGE_8_CARRY_0_KS_PBS,
    // Small params
    PARAM_MESSAGE_1_CARRY_1_PBS_KS,
    PARAM_MESSAGE_2_CARRY_2_PBS_KS,
    PARAM_MESSAGE_3_CARRY_3_PBS_KS,
    PARAM_MESSAGE_4_CARRY_4_PBS_KS,
    // CPK
    PARAM_MESSAGE_1_CARRY_2_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_1_CARRY_3_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_1_CARRY_4_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_1_CARRY_5_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_1_CARRY_6_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_1_CARRY_7_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_2_CARRY_1_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_2_CARRY_3_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_2_CARRY_4_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_2_CARRY_5_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_2_CARRY_6_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_3_CARRY_1_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_3_CARRY_2_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_3_CARRY_3_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_3_CARRY_4_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_3_CARRY_5_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_4_CARRY_1_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_4_CARRY_2_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_4_CARRY_3_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_4_CARRY_4_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_5_CARRY_1_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_5_CARRY_2_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_5_CARRY_3_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_6_CARRY_1_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_6_CARRY_2_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_7_CARRY_1_COMPACT_PK_KS_PBS,
    // CPK SMALL
    PARAM_MESSAGE_1_CARRY_1_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_1_CARRY_2_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_1_CARRY_3_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_1_CARRY_4_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_1_CARRY_5_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_1_CARRY_6_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_1_CARRY_7_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_2_CARRY_1_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_2_CARRY_3_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_2_CARRY_4_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_2_CARRY_5_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_2_CARRY_6_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_3_CARRY_1_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_3_CARRY_2_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_3_CARRY_3_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_3_CARRY_4_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_3_CARRY_5_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_4_CARRY_1_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_4_CARRY_2_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_4_CARRY_3_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_4_CARRY_4_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_5_CARRY_1_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_5_CARRY_2_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_5_CARRY_3_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_6_CARRY_1_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_6_CARRY_2_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_7_CARRY_1_COMPACT_PK_PBS_KS,
    // Aliases to remove eventually
    PARAM_MESSAGE_1_CARRY_0,
    PARAM_MESSAGE_1_CARRY_1,
    PARAM_MESSAGE_2_CARRY_0,
    PARAM_MESSAGE_1_CARRY_2,
    PARAM_MESSAGE_2_CARRY_1,
    PARAM_MESSAGE_3_CARRY_0,
    PARAM_MESSAGE_1_CARRY_3,
    PARAM_MESSAGE_2_CARRY_2,
    PARAM_MESSAGE_3_CARRY_1,
    PARAM_MESSAGE_4_CARRY_0,
    PARAM_MESSAGE_1_CARRY_4,
    PARAM_MESSAGE_2_CARRY_3,
    PARAM_MESSAGE_3_CARRY_2,
    PARAM_MESSAGE_4_CARRY_1,
    PARAM_MESSAGE_5_CARRY_0,
    PARAM_MESSAGE_1_CARRY_5,
    PARAM_MESSAGE_2_CARRY_4,
    PARAM_MESSAGE_3_CARRY_3,
    PARAM_MESSAGE_4_CARRY_2,
    PARAM_MESSAGE_5_CARRY_1,
    PARAM_MESSAGE_6_CARRY_0,
    PARAM_MESSAGE_1_CARRY_6,
    PARAM_MESSAGE_2_CARRY_5,
    PARAM_MESSAGE_3_CARRY_4,
    PARAM_MESSAGE_4_CARRY_3,
    PARAM_MESSAGE_5_CARRY_2,
    PARAM_MESSAGE_6_CARRY_1,
    PARAM_MESSAGE_7_CARRY_0,
    PARAM_MESSAGE_1_CARRY_7,
    PARAM_MESSAGE_2_CARRY_6,
    PARAM_MESSAGE_3_CARRY_5,
    PARAM_MESSAGE_4_CARRY_4,
    PARAM_MESSAGE_5_CARRY_3,
    PARAM_MESSAGE_6_CARRY_2,
    PARAM_MESSAGE_7_CARRY_1,
    PARAM_MESSAGE_8_CARRY_0,
    // Small params
    PARAM_SMALL_MESSAGE_1_CARRY_1,
    PARAM_SMALL_MESSAGE_2_CARRY_2,
    PARAM_SMALL_MESSAGE_3_CARRY_3,
    PARAM_SMALL_MESSAGE_4_CARRY_4,
);

#[no_mangle]
pub unsafe extern "C" fn shortint_get_parameters(
    message_bits: u32,
    carry_bits: u32,
    result: *mut ShortintPBSParameters,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();
        let params: Option<_> = match (message_bits, carry_bits) {
            (1, 0) => Some(crate::shortint::parameters::PARAM_MESSAGE_1_CARRY_0_KS_PBS),
            (1, 1) => Some(crate::shortint::parameters::PARAM_MESSAGE_1_CARRY_1_KS_PBS),
            (2, 0) => Some(crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_0_KS_PBS),
            (1, 2) => Some(crate::shortint::parameters::PARAM_MESSAGE_1_CARRY_2_KS_PBS),
            (2, 1) => Some(crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_1_KS_PBS),
            (3, 0) => Some(crate::shortint::parameters::PARAM_MESSAGE_3_CARRY_0_KS_PBS),
            (1, 3) => Some(crate::shortint::parameters::PARAM_MESSAGE_1_CARRY_3_KS_PBS),
            (2, 2) => Some(crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS),
            (3, 1) => Some(crate::shortint::parameters::PARAM_MESSAGE_3_CARRY_1_KS_PBS),
            (4, 0) => Some(crate::shortint::parameters::PARAM_MESSAGE_4_CARRY_0_KS_PBS),
            (1, 4) => Some(crate::shortint::parameters::PARAM_MESSAGE_1_CARRY_4_KS_PBS),
            (2, 3) => Some(crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_3_KS_PBS),
            (3, 2) => Some(crate::shortint::parameters::PARAM_MESSAGE_3_CARRY_2_KS_PBS),
            (4, 1) => Some(crate::shortint::parameters::PARAM_MESSAGE_4_CARRY_1_KS_PBS),
            (5, 0) => Some(crate::shortint::parameters::PARAM_MESSAGE_5_CARRY_0_KS_PBS),
            (1, 5) => Some(crate::shortint::parameters::PARAM_MESSAGE_1_CARRY_5_KS_PBS),
            (2, 4) => Some(crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_4_KS_PBS),
            (3, 3) => Some(crate::shortint::parameters::PARAM_MESSAGE_3_CARRY_3_KS_PBS),
            (4, 2) => Some(crate::shortint::parameters::PARAM_MESSAGE_4_CARRY_2_KS_PBS),
            (5, 1) => Some(crate::shortint::parameters::PARAM_MESSAGE_5_CARRY_1_KS_PBS),
            (6, 0) => Some(crate::shortint::parameters::PARAM_MESSAGE_6_CARRY_0_KS_PBS),
            (1, 6) => Some(crate::shortint::parameters::PARAM_MESSAGE_1_CARRY_6_KS_PBS),
            (2, 5) => Some(crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_5_KS_PBS),
            (3, 4) => Some(crate::shortint::parameters::PARAM_MESSAGE_3_CARRY_4_KS_PBS),
            (4, 3) => Some(crate::shortint::parameters::PARAM_MESSAGE_4_CARRY_3_KS_PBS),
            (5, 2) => Some(crate::shortint::parameters::PARAM_MESSAGE_5_CARRY_2_KS_PBS),
            (6, 1) => Some(crate::shortint::parameters::PARAM_MESSAGE_6_CARRY_1_KS_PBS),
            (7, 0) => Some(crate::shortint::parameters::PARAM_MESSAGE_7_CARRY_0_KS_PBS),
            (1, 7) => Some(crate::shortint::parameters::PARAM_MESSAGE_1_CARRY_7_KS_PBS),
            (2, 6) => Some(crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_6_KS_PBS),
            (3, 5) => Some(crate::shortint::parameters::PARAM_MESSAGE_3_CARRY_5_KS_PBS),
            (4, 4) => Some(crate::shortint::parameters::PARAM_MESSAGE_4_CARRY_4_KS_PBS),
            (5, 3) => Some(crate::shortint::parameters::PARAM_MESSAGE_5_CARRY_3_KS_PBS),
            (6, 2) => Some(crate::shortint::parameters::PARAM_MESSAGE_6_CARRY_2_KS_PBS),
            (7, 1) => Some(crate::shortint::parameters::PARAM_MESSAGE_7_CARRY_1_KS_PBS),
            (8, 0) => Some(crate::shortint::parameters::PARAM_MESSAGE_8_CARRY_0_KS_PBS),
            _ => None,
        };

        if let Some(params) = params {
            *result = params.into();
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_get_parameters_small(
    message_bits: u32,
    carry_bits: u32,
    result: *mut ShortintPBSParameters,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();
        let params: Option<_> = match (message_bits, carry_bits) {
            (1, 1) => Some(crate::shortint::parameters::PARAM_MESSAGE_1_CARRY_1_PBS_KS),
            (2, 2) => Some(crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_PBS_KS),
            (3, 3) => Some(crate::shortint::parameters::PARAM_MESSAGE_3_CARRY_3_PBS_KS),
            (4, 4) => Some(crate::shortint::parameters::PARAM_MESSAGE_4_CARRY_4_PBS_KS),
            _ => None,
        };

        if let Some(params) = params {
            *result = params.into();
        }
    })
}
