use crate::c_api::utils::*;
pub use crate::core_crypto::commons::dispersion::StandardDev;
pub use crate::core_crypto::commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
};
pub use crate::shortint::parameters::compact_public_key_only::p_fail_2_minus_64::ks_pbs::PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
pub use crate::shortint::parameters::key_switching::p_fail_2_minus_64::ks_pbs::PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
pub use crate::shortint::parameters::*;
use std::os::raw::c_int;

#[repr(C)]
#[derive(Copy, Clone)]
pub enum ShortintEncryptionKeyChoice {
    ShortintEncryptionKeyChoiceBig,
    ShortintEncryptionKeyChoiceSmall,
}

impl From<ShortintEncryptionKeyChoice> for crate::shortint::parameters::EncryptionKeyChoice {
    fn from(value: ShortintEncryptionKeyChoice) -> Self {
        match value {
            ShortintEncryptionKeyChoice::ShortintEncryptionKeyChoiceBig => Self::Big,
            ShortintEncryptionKeyChoice::ShortintEncryptionKeyChoiceSmall => Self::Small,
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ShortintPBSParameters {
    pub lwe_dimension: usize,
    pub glwe_dimension: usize,
    pub polynomial_size: usize,
    pub lwe_noise_distribution: crate::c_api::core_crypto::DynamicDistribution,
    pub glwe_noise_distribution: crate::c_api::core_crypto::DynamicDistribution,
    pub pbs_base_log: usize,
    pub pbs_level: usize,
    pub ks_base_log: usize,
    pub ks_level: usize,
    pub message_modulus: usize,
    pub carry_modulus: usize,
    pub max_noise_level: usize,
    pub log2_p_fail: f64,
    pub modulus_power_of_2_exponent: usize,
    pub encryption_key_choice: ShortintEncryptionKeyChoice,
}

impl TryFrom<ShortintPBSParameters> for crate::shortint::ClassicPBSParameters {
    type Error = &'static str;

    fn try_from(c_params: ShortintPBSParameters) -> Result<Self, Self::Error> {
        Ok(Self {
            lwe_dimension: LweDimension(c_params.lwe_dimension),
            glwe_dimension: GlweDimension(c_params.glwe_dimension),
            polynomial_size: PolynomialSize(c_params.polynomial_size),
            lwe_noise_distribution: c_params.lwe_noise_distribution.try_into()?,
            glwe_noise_distribution: c_params.glwe_noise_distribution.try_into()?,
            pbs_base_log: DecompositionBaseLog(c_params.pbs_base_log),
            pbs_level: DecompositionLevelCount(c_params.pbs_level),
            ks_base_log: DecompositionBaseLog(c_params.ks_base_log),
            ks_level: DecompositionLevelCount(c_params.ks_level),
            message_modulus: crate::shortint::parameters::MessageModulus(c_params.message_modulus),
            carry_modulus: crate::shortint::parameters::CarryModulus(c_params.carry_modulus),
            ciphertext_modulus: crate::shortint::parameters::CiphertextModulus::try_new_power_of_2(
                c_params.modulus_power_of_2_exponent,
            )?,
            max_noise_level: crate::shortint::parameters::MaxNoiseLevel::new(
                c_params.max_noise_level,
            ),
            log2_p_fail: c_params.log2_p_fail,
            encryption_key_choice: c_params.encryption_key_choice.into(),
        })
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
            lwe_noise_distribution: rust_params.lwe_noise_distribution.convert_to_c(),
            glwe_noise_distribution: rust_params.glwe_noise_distribution.convert_to_c(),
            pbs_base_log: rust_params.pbs_base_log.0,
            pbs_level: rust_params.pbs_level.0,
            ks_base_log: rust_params.ks_base_log.0,
            ks_level: rust_params.ks_level.0,
            message_modulus: rust_params.message_modulus.0,
            carry_modulus: rust_params.carry_modulus.0,
            max_noise_level: rust_params.max_noise_level.get(),
            log2_p_fail: rust_params.log2_p_fail,
            modulus_power_of_2_exponent: convert_modulus(rust_params.ciphertext_modulus),
            encryption_key_choice: ShortintEncryptionKeyChoice::convert(
                rust_params.encryption_key_choice,
            ),
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ShortintCompactCiphertextListCastingParameters {
    pub ks_base_log: usize,
    pub ks_level: usize,
    pub destination_key: ShortintEncryptionKeyChoice,
}

impl From<ShortintCompactCiphertextListCastingParameters>
    for crate::shortint::parameters::key_switching::ShortintKeySwitchingParameters
{
    fn from(value: ShortintCompactCiphertextListCastingParameters) -> Self {
        Self {
            ks_base_log: DecompositionBaseLog(value.ks_base_log),
            ks_level: DecompositionLevelCount(value.ks_level),
            destination_key: value.destination_key.into(),
        }
    }
}

impl From<crate::shortint::parameters::key_switching::ShortintKeySwitchingParameters>
    for ShortintCompactCiphertextListCastingParameters
{
    fn from(
        rust_params: crate::shortint::parameters::key_switching::ShortintKeySwitchingParameters,
    ) -> Self {
        Self::convert(rust_params)
    }
}

impl ShortintCompactCiphertextListCastingParameters {
    const fn convert(
        rust_params: crate::shortint::parameters::key_switching::ShortintKeySwitchingParameters,
    ) -> Self {
        Self {
            ks_base_log: rust_params.ks_base_log.0,
            ks_level: rust_params.ks_level.0,
            destination_key: ShortintEncryptionKeyChoice::convert(rust_params.destination_key),
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ShortintCompactPublicKeyEncryptionParameters {
    pub encryption_lwe_dimension: usize,
    pub encryption_noise_distribution: crate::c_api::core_crypto::DynamicDistribution,
    pub message_modulus: usize,
    pub carry_modulus: usize,
    pub modulus_power_of_2_exponent: usize,
    // Normally the CompactPublicKeyEncryptionParameters has an additional field expansion_kind,
    // but it's only used to manage different kind of parameters internally, for the C API
    // these parameters will always require casting, as they always require casting we add a field
    // for the casting parameters here.
    pub casting_parameters: ShortintCompactCiphertextListCastingParameters,
}

impl TryFrom<ShortintCompactPublicKeyEncryptionParameters>
    for crate::shortint::parameters::CompactPublicKeyEncryptionParameters
{
    type Error = &'static str;

    fn try_from(
        c_params: ShortintCompactPublicKeyEncryptionParameters,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            encryption_lwe_dimension: LweDimension(c_params.encryption_lwe_dimension),
            encryption_noise_distribution: c_params.encryption_noise_distribution.try_into()?,
            message_modulus: MessageModulus(c_params.message_modulus),
            carry_modulus: CarryModulus(c_params.carry_modulus),
            ciphertext_modulus: crate::shortint::parameters::CiphertextModulus::try_new_power_of_2(
                c_params.modulus_power_of_2_exponent,
            )?,
            expansion_kind:
                crate::shortint::parameters::CompactCiphertextListExpansionKind::RequiresCasting,
        })
    }
}

impl TryFrom<ShortintCompactPublicKeyEncryptionParameters>
    for (
        crate::shortint::parameters::CompactPublicKeyEncryptionParameters,
        crate::shortint::parameters::key_switching::ShortintKeySwitchingParameters,
    )
{
    type Error = &'static str;

    fn try_from(value: ShortintCompactPublicKeyEncryptionParameters) -> Result<Self, Self::Error> {
        Ok((value.try_into()?, value.casting_parameters.into()))
    }
}

impl ShortintCompactPublicKeyEncryptionParameters {
    const fn convert(
        rust_params: (
            crate::shortint::parameters::CompactPublicKeyEncryptionParameters,
            crate::shortint::parameters::key_switching::ShortintKeySwitchingParameters,
        ),
    ) -> Self {
        let compact_pke_params = rust_params.0;
        let casting_parameters = rust_params.1;
        Self {
            encryption_lwe_dimension: compact_pke_params.encryption_lwe_dimension.0,
            encryption_noise_distribution: compact_pke_params
                .encryption_noise_distribution
                .convert_to_c(),
            message_modulus: compact_pke_params.message_modulus.0,
            carry_modulus: compact_pke_params.carry_modulus.0,
            modulus_power_of_2_exponent: convert_modulus(compact_pke_params.ciphertext_modulus),
            casting_parameters: ShortintCompactCiphertextListCastingParameters::convert(
                casting_parameters,
            ),
        }
    }
}

// TODO: use macros once we have more parameters using the same pattern as
// expose_predefined_parameters
#[no_mangle]
pub static SHORTINT_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64:
    ShortintCompactPublicKeyEncryptionParameters =
    ShortintCompactPublicKeyEncryptionParameters::convert((
        PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
    ));

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
                    let rust_params_from_c = crate::shortint::parameters::ClassicPBSParameters::try_from(c_params).unwrap();
                    assert_eq!(rust_params, rust_params_from_c);
                }
            )*
        }
    }
);

expose_as_shortint_pbs_parameters!(
    PARAM_MESSAGE_1_CARRY_0_KS_PBS_GAUSSIAN_2M64,
    PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    PARAM_MESSAGE_2_CARRY_0_KS_PBS_GAUSSIAN_2M64,
    PARAM_MESSAGE_1_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    PARAM_MESSAGE_2_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    PARAM_MESSAGE_3_CARRY_0_KS_PBS_GAUSSIAN_2M64,
    PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64,
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    PARAM_MESSAGE_3_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    PARAM_MESSAGE_4_CARRY_0_KS_PBS_GAUSSIAN_2M64,
    PARAM_MESSAGE_1_CARRY_4_KS_PBS_GAUSSIAN_2M64,
    PARAM_MESSAGE_2_CARRY_3_KS_PBS_GAUSSIAN_2M64,
    PARAM_MESSAGE_3_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    PARAM_MESSAGE_4_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    PARAM_MESSAGE_5_CARRY_0_KS_PBS_GAUSSIAN_2M64,
    PARAM_MESSAGE_1_CARRY_5_KS_PBS_GAUSSIAN_2M64,
    PARAM_MESSAGE_2_CARRY_4_KS_PBS_GAUSSIAN_2M64,
    PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
    PARAM_MESSAGE_4_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    PARAM_MESSAGE_5_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    PARAM_MESSAGE_6_CARRY_0_KS_PBS_GAUSSIAN_2M64,
    PARAM_MESSAGE_1_CARRY_6_KS_PBS_GAUSSIAN_2M64,
    PARAM_MESSAGE_2_CARRY_5_KS_PBS_GAUSSIAN_2M64,
    PARAM_MESSAGE_3_CARRY_4_KS_PBS_GAUSSIAN_2M64,
    PARAM_MESSAGE_4_CARRY_3_KS_PBS_GAUSSIAN_2M64,
    PARAM_MESSAGE_5_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    PARAM_MESSAGE_6_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    PARAM_MESSAGE_7_CARRY_0_KS_PBS_GAUSSIAN_2M64,
    PARAM_MESSAGE_1_CARRY_7_KS_PBS_GAUSSIAN_2M64,
    PARAM_MESSAGE_2_CARRY_6_KS_PBS_GAUSSIAN_2M64,
    PARAM_MESSAGE_3_CARRY_5_KS_PBS_GAUSSIAN_2M64,
    PARAM_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M64,
    PARAM_MESSAGE_5_CARRY_3_KS_PBS_GAUSSIAN_2M64,
    PARAM_MESSAGE_6_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    PARAM_MESSAGE_7_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    PARAM_MESSAGE_8_CARRY_0_KS_PBS_GAUSSIAN_2M64,
    // Small params
    PARAM_MESSAGE_1_CARRY_1_PBS_KS_GAUSSIAN_2M64,
    PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64,
    PARAM_MESSAGE_3_CARRY_3_PBS_KS_GAUSSIAN_2M64,
    PARAM_MESSAGE_4_CARRY_4_PBS_KS_GAUSSIAN_2M64,
    // CPK
    PARAM_MESSAGE_1_CARRY_1_COMPACT_PK_KS_PBS,
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
    PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_3_CARRY_3_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_4_CARRY_4_COMPACT_PK_PBS_KS,
    // TUniform
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
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
            (1, 0) => {
                Some(crate::shortint::parameters::PARAM_MESSAGE_1_CARRY_0_KS_PBS_GAUSSIAN_2M64)
            }
            (1, 1) => {
                Some(crate::shortint::parameters::PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64)
            }
            (2, 0) => {
                Some(crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_0_KS_PBS_GAUSSIAN_2M64)
            }
            (1, 2) => {
                Some(crate::shortint::parameters::PARAM_MESSAGE_1_CARRY_2_KS_PBS_GAUSSIAN_2M64)
            }
            (2, 1) => {
                Some(crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_1_KS_PBS_GAUSSIAN_2M64)
            }
            (3, 0) => {
                Some(crate::shortint::parameters::PARAM_MESSAGE_3_CARRY_0_KS_PBS_GAUSSIAN_2M64)
            }
            (1, 3) => {
                Some(crate::shortint::parameters::PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64)
            }
            (2, 2) => Some(crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS),
            (3, 1) => {
                Some(crate::shortint::parameters::PARAM_MESSAGE_3_CARRY_1_KS_PBS_GAUSSIAN_2M64)
            }
            (4, 0) => {
                Some(crate::shortint::parameters::PARAM_MESSAGE_4_CARRY_0_KS_PBS_GAUSSIAN_2M64)
            }
            (1, 4) => {
                Some(crate::shortint::parameters::PARAM_MESSAGE_1_CARRY_4_KS_PBS_GAUSSIAN_2M64)
            }
            (2, 3) => {
                Some(crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_3_KS_PBS_GAUSSIAN_2M64)
            }
            (3, 2) => {
                Some(crate::shortint::parameters::PARAM_MESSAGE_3_CARRY_2_KS_PBS_GAUSSIAN_2M64)
            }
            (4, 1) => {
                Some(crate::shortint::parameters::PARAM_MESSAGE_4_CARRY_1_KS_PBS_GAUSSIAN_2M64)
            }
            (5, 0) => {
                Some(crate::shortint::parameters::PARAM_MESSAGE_5_CARRY_0_KS_PBS_GAUSSIAN_2M64)
            }
            (1, 5) => {
                Some(crate::shortint::parameters::PARAM_MESSAGE_1_CARRY_5_KS_PBS_GAUSSIAN_2M64)
            }
            (2, 4) => {
                Some(crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_4_KS_PBS_GAUSSIAN_2M64)
            }
            (3, 3) => {
                Some(crate::shortint::parameters::PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64)
            }
            (4, 2) => {
                Some(crate::shortint::parameters::PARAM_MESSAGE_4_CARRY_2_KS_PBS_GAUSSIAN_2M64)
            }
            (5, 1) => {
                Some(crate::shortint::parameters::PARAM_MESSAGE_5_CARRY_1_KS_PBS_GAUSSIAN_2M64)
            }
            (6, 0) => {
                Some(crate::shortint::parameters::PARAM_MESSAGE_6_CARRY_0_KS_PBS_GAUSSIAN_2M64)
            }
            (1, 6) => {
                Some(crate::shortint::parameters::PARAM_MESSAGE_1_CARRY_6_KS_PBS_GAUSSIAN_2M64)
            }
            (2, 5) => {
                Some(crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_5_KS_PBS_GAUSSIAN_2M64)
            }
            (3, 4) => {
                Some(crate::shortint::parameters::PARAM_MESSAGE_3_CARRY_4_KS_PBS_GAUSSIAN_2M64)
            }
            (4, 3) => {
                Some(crate::shortint::parameters::PARAM_MESSAGE_4_CARRY_3_KS_PBS_GAUSSIAN_2M64)
            }
            (5, 2) => {
                Some(crate::shortint::parameters::PARAM_MESSAGE_5_CARRY_2_KS_PBS_GAUSSIAN_2M64)
            }
            (6, 1) => {
                Some(crate::shortint::parameters::PARAM_MESSAGE_6_CARRY_1_KS_PBS_GAUSSIAN_2M64)
            }
            (7, 0) => {
                Some(crate::shortint::parameters::PARAM_MESSAGE_7_CARRY_0_KS_PBS_GAUSSIAN_2M64)
            }
            (1, 7) => {
                Some(crate::shortint::parameters::PARAM_MESSAGE_1_CARRY_7_KS_PBS_GAUSSIAN_2M64)
            }
            (2, 6) => {
                Some(crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_6_KS_PBS_GAUSSIAN_2M64)
            }
            (3, 5) => {
                Some(crate::shortint::parameters::PARAM_MESSAGE_3_CARRY_5_KS_PBS_GAUSSIAN_2M64)
            }
            (4, 4) => {
                Some(crate::shortint::parameters::PARAM_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M64)
            }
            (5, 3) => {
                Some(crate::shortint::parameters::PARAM_MESSAGE_5_CARRY_3_KS_PBS_GAUSSIAN_2M64)
            }
            (6, 2) => {
                Some(crate::shortint::parameters::PARAM_MESSAGE_6_CARRY_2_KS_PBS_GAUSSIAN_2M64)
            }
            (7, 1) => {
                Some(crate::shortint::parameters::PARAM_MESSAGE_7_CARRY_1_KS_PBS_GAUSSIAN_2M64)
            }
            (8, 0) => {
                Some(crate::shortint::parameters::PARAM_MESSAGE_8_CARRY_0_KS_PBS_GAUSSIAN_2M64)
            }
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
            (1, 1) => {
                Some(crate::shortint::parameters::PARAM_MESSAGE_1_CARRY_1_PBS_KS_GAUSSIAN_2M64)
            }
            (2, 2) => {
                Some(crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64)
            }
            (3, 3) => {
                Some(crate::shortint::parameters::PARAM_MESSAGE_3_CARRY_3_PBS_KS_GAUSSIAN_2M64)
            }
            (4, 4) => {
                Some(crate::shortint::parameters::PARAM_MESSAGE_4_CARRY_4_PBS_KS_GAUSSIAN_2M64)
            }
            _ => None,
        };

        if let Some(params) = params {
            *result = params.into();
        }
    })
}

pub struct CompressionParameters(
    pub(crate) crate::shortint::parameters::list_compression::CompressionParameters,
);

#[no_mangle]
pub static SHORTINT_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64: CompressionParameters = CompressionParameters(
    crate::shortint::parameters::list_compression::COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
);
