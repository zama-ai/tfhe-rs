use crate::shortint::parameters::v0_11::classic::compact_pk::*;
use crate::shortint::parameters::v0_11::classic::gaussian::*;
use crate::shortint::parameters::v0_11::compact_public_key_only::p_fail_2_minus_64::ks_pbs::V0_11_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
use crate::shortint::parameters::v0_11::key_switching::p_fail_2_minus_64::ks_pbs::V0_11_PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
use crate::shortint::parameters::v0_11::list_compression::V0_11_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
use crate::shortint::parameters::v1_0::*;
use crate::shortint::parameters::v1_1::*;
use crate::shortint::parameters::v1_2::*;
use crate::shortint::parameters::v1_3::*;
use crate::shortint::parameters::v1_4::*;
use crate::shortint::parameters::v1_5::*;
pub use crate::shortint::parameters::*;
use crate::shortint::parameters::{
    ModulusSwitchNoiseReductionParams as RustModulusSwitchNoiseReductionParams,
    ModulusSwitchType as RustModulusSwitchType,
};

#[repr(C)]
#[derive(Copy, Clone)]
pub enum ShortintEncryptionKeyChoice {
    ShortintEncryptionKeyChoiceBig,
    ShortintEncryptionKeyChoiceSmall,
}

impl From<ShortintEncryptionKeyChoice> for EncryptionKeyChoice {
    fn from(value: ShortintEncryptionKeyChoice) -> Self {
        match value {
            ShortintEncryptionKeyChoice::ShortintEncryptionKeyChoiceBig => Self::Big,
            ShortintEncryptionKeyChoice::ShortintEncryptionKeyChoiceSmall => Self::Small,
        }
    }
}

#[repr(u64)]
#[derive(Clone, Copy)]
pub enum OptionTag {
    None = 0,
    Some = 1,
}

impl TryFrom<u64> for OptionTag {
    type Error = &'static str;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::None),
            1 => Ok(Self::Some),
            _ => Err("Invalid value for OptionTag"),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ModulusSwitchNoiseReductionParams {
    pub modulus_switch_zeros_count: u32,
    pub ms_bound: f64,
    pub ms_r_sigma_factor: f64,
    pub ms_input_variance: f64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ModulusSwitchType {
    pub tag: u64,
    pub modulus_switch_noise_reduction_params: ModulusSwitchNoiseReductionParams,
}

impl ModulusSwitchType {
    pub const fn new_plain() -> Self {
        Self {
            tag: 0,
            modulus_switch_noise_reduction_params: ModulusSwitchNoiseReductionParams {
                modulus_switch_zeros_count: 0,
                ms_bound: 0.,
                ms_r_sigma_factor: 0.,
                ms_input_variance: 0.,
            },
        }
    }

    pub const fn new_plain_add_zero(
        modulus_switch_noise_reduction_params: ModulusSwitchNoiseReductionParams,
    ) -> Self {
        Self {
            tag: 1,
            modulus_switch_noise_reduction_params,
        }
    }

    pub const fn new_centered_binary() -> Self {
        Self {
            tag: 2,
            modulus_switch_noise_reduction_params: ModulusSwitchNoiseReductionParams {
                modulus_switch_zeros_count: 0,
                ms_bound: 0.,
                ms_r_sigma_factor: 0.,
                ms_input_variance: 0.,
            },
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn modulus_switch_noise_reduction_params_option_none() -> ModulusSwitchType {
    ModulusSwitchType::new_plain()
}

#[no_mangle]
pub unsafe extern "C" fn modulus_switch_noise_reduction_params_option_some(
    modulus_switch_noise_reduction_params: ModulusSwitchNoiseReductionParams,
) -> ModulusSwitchType {
    ModulusSwitchType::new_plain_add_zero(modulus_switch_noise_reduction_params)
}

impl From<ModulusSwitchNoiseReductionParams> for RustModulusSwitchNoiseReductionParams {
    fn from(value: ModulusSwitchNoiseReductionParams) -> Self {
        let ModulusSwitchNoiseReductionParams {
            modulus_switch_zeros_count,
            ms_bound,
            ms_r_sigma_factor,
            ms_input_variance,
        } = value;
        Self {
            modulus_switch_zeros_count: LweCiphertextCount(modulus_switch_zeros_count as usize),
            ms_bound: NoiseEstimationMeasureBound(ms_bound),
            ms_r_sigma_factor: RSigmaFactor(ms_r_sigma_factor),
            ms_input_variance: Variance(ms_input_variance),
        }
    }
}

impl TryFrom<ModulusSwitchType> for RustModulusSwitchType {
    type Error = &'static str;

    fn try_from(value: ModulusSwitchType) -> Result<Self, Self::Error> {
        match value.tag {
            0 => Ok(Self::Standard),
            1 => Ok(Self::DriftTechniqueNoiseReduction(
                value.modulus_switch_noise_reduction_params.into(),
            )),
            2 => Ok(Self::CenteredMeanNoiseReduction),
            _ => Err("Invalid value for ModulusSwitchType tag"),
        }
    }
}

impl RustModulusSwitchType {
    const fn convert_to_c(&self) -> ModulusSwitchType {
        let modulus_switch_noise_reduction_params_default = ModulusSwitchNoiseReductionParams {
            modulus_switch_zeros_count: 0,
            ms_bound: 0.,
            ms_r_sigma_factor: 0.,
            ms_input_variance: 0.,
        };

        match self {
            Self::Standard => ModulusSwitchType {
                tag: 0,
                modulus_switch_noise_reduction_params:
                    modulus_switch_noise_reduction_params_default,
            },
            Self::DriftTechniqueNoiseReduction(modulus_switch_noise_reduction_params) => {
                ModulusSwitchType {
                    tag: 1,
                    modulus_switch_noise_reduction_params: modulus_switch_noise_reduction_params
                        .convert_to_c(),
                }
            }
            Self::CenteredMeanNoiseReduction => ModulusSwitchType {
                tag: 2,
                modulus_switch_noise_reduction_params:
                    modulus_switch_noise_reduction_params_default,
            },
        }
    }
}

impl RustModulusSwitchNoiseReductionParams {
    pub const fn convert_to_c(&self) -> ModulusSwitchNoiseReductionParams {
        ModulusSwitchNoiseReductionParams {
            modulus_switch_zeros_count: self.modulus_switch_zeros_count.0 as u32,
            ms_bound: self.ms_bound.0,
            ms_r_sigma_factor: self.ms_r_sigma_factor.0,
            ms_input_variance: self.ms_input_variance.0,
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
    pub message_modulus: u64,
    pub carry_modulus: u64,
    pub max_noise_level: u64,
    pub log2_p_fail: f64,
    pub modulus_power_of_2_exponent: usize,
    pub encryption_key_choice: ShortintEncryptionKeyChoice,
    pub modulus_switch_noise_reduction_params: ModulusSwitchType,
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
            message_modulus: MessageModulus(c_params.message_modulus),
            carry_modulus: CarryModulus(c_params.carry_modulus),
            ciphertext_modulus: CiphertextModulus::try_new_power_of_2(
                c_params.modulus_power_of_2_exponent,
            )?,
            max_noise_level: MaxNoiseLevel::new(c_params.max_noise_level),
            log2_p_fail: c_params.log2_p_fail,
            encryption_key_choice: c_params.encryption_key_choice.into(),
            modulus_switch_noise_reduction_params: c_params
                .modulus_switch_noise_reduction_params
                .try_into()?,
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
        let crate::shortint::ClassicPBSParameters {
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
            carry_modulus,
            max_noise_level,
            log2_p_fail,
            ciphertext_modulus,
            encryption_key_choice,
            modulus_switch_noise_reduction_params,
        } = rust_params;

        Self {
            lwe_dimension: lwe_dimension.0,
            glwe_dimension: glwe_dimension.0,
            polynomial_size: polynomial_size.0,
            lwe_noise_distribution: lwe_noise_distribution.convert_to_c(),
            glwe_noise_distribution: glwe_noise_distribution.convert_to_c(),
            pbs_base_log: pbs_base_log.0,
            pbs_level: pbs_level.0,
            ks_base_log: ks_base_log.0,
            ks_level: ks_level.0,
            message_modulus: message_modulus.0,
            carry_modulus: carry_modulus.0,
            max_noise_level: max_noise_level.get(),
            log2_p_fail,
            modulus_power_of_2_exponent: convert_modulus(ciphertext_modulus),
            encryption_key_choice: ShortintEncryptionKeyChoice::convert(encryption_key_choice),
            modulus_switch_noise_reduction_params: modulus_switch_noise_reduction_params
                .convert_to_c(),
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
        let crate::shortint::parameters::key_switching::ShortintKeySwitchingParameters {
            ks_base_log,
            ks_level,
            destination_key,
        } = rust_params;

        Self {
            ks_base_log: ks_base_log.0,
            ks_level: ks_level.0,
            destination_key: ShortintEncryptionKeyChoice::convert(destination_key),
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub enum SupportedCompactPkeZkScheme {
    ZkNotSupported,
    V1,
    V2,
}

impl From<SupportedCompactPkeZkScheme>
    for crate::shortint::parameters::SupportedCompactPkeZkScheme
{
    fn from(value: SupportedCompactPkeZkScheme) -> Self {
        match value {
            SupportedCompactPkeZkScheme::ZkNotSupported => Self::ZkNotSupported,
            SupportedCompactPkeZkScheme::V1 => Self::V1,
            SupportedCompactPkeZkScheme::V2 => Self::V2,
        }
    }
}

impl SupportedCompactPkeZkScheme {
    const fn convert(value: crate::shortint::parameters::SupportedCompactPkeZkScheme) -> Self {
        match value {
            crate::shortint::parameters::SupportedCompactPkeZkScheme::ZkNotSupported => {
                Self::ZkNotSupported
            }
            crate::shortint::parameters::SupportedCompactPkeZkScheme::V1 => Self::V1,
            crate::shortint::parameters::SupportedCompactPkeZkScheme::V2 => Self::V2,
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ShortintCompactPublicKeyEncryptionParameters {
    pub encryption_lwe_dimension: usize,
    pub encryption_noise_distribution: crate::c_api::core_crypto::DynamicDistribution,
    pub message_modulus: u64,
    pub carry_modulus: u64,
    pub modulus_power_of_2_exponent: usize,
    // Normally the CompactPublicKeyEncryptionParameters has an additional field expansion_kind,
    // but it's only used to manage different kind of parameters internally, for the C API
    // these parameters will always require casting, as they always require casting we add a field
    // for the casting parameters here.
    pub casting_parameters: ShortintCompactCiphertextListCastingParameters,
    pub zk_scheme: SupportedCompactPkeZkScheme,
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
            zk_scheme: c_params.zk_scheme.into(),
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
        (compact_pke_params, casting_parameters): (
            crate::shortint::parameters::CompactPublicKeyEncryptionParameters,
            crate::shortint::parameters::key_switching::ShortintKeySwitchingParameters,
        ),
    ) -> Self {
        let CompactPublicKeyEncryptionParameters {
            encryption_lwe_dimension,
            encryption_noise_distribution,
            message_modulus,
            carry_modulus,
            ciphertext_modulus,
            expansion_kind: _,
            zk_scheme,
        } = compact_pke_params;

        Self {
            encryption_lwe_dimension: encryption_lwe_dimension.0,
            encryption_noise_distribution: encryption_noise_distribution.convert_to_c(),
            message_modulus: message_modulus.0,
            carry_modulus: carry_modulus.0,
            modulus_power_of_2_exponent: convert_modulus(ciphertext_modulus),
            casting_parameters: ShortintCompactCiphertextListCastingParameters::convert(
                casting_parameters,
            ),
            zk_scheme: SupportedCompactPkeZkScheme::convert(zk_scheme),
        }
    }
}

macro_rules! expose_as_shortint_compact_public_key_parameters(
    (
        $(
            ($param_pke_name:ident, $param_ks_name:ident)
        ),*
        $(,)?
    ) => {
        ::paste::paste!{
            $(
                #[no_mangle]
                pub static [<SHORTINT_ $param_pke_name>]: ShortintCompactPublicKeyEncryptionParameters =
                ShortintCompactPublicKeyEncryptionParameters::convert((
                    $param_pke_name,
                    $param_ks_name,
                ));
            )*
        }
    }
);

expose_as_shortint_compact_public_key_parameters!(
    (
        PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
    ),
    (
        V1_5_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        V1_5_PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
    ),
    (
        V1_4_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        V1_4_PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
    ),
    (
        V1_3_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        V1_3_PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
    ),
    (
        V1_2_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        V1_2_PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
    ),
    (
        V1_1_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        V1_1_PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
    ),
    (
        V1_0_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        V1_0_PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
    ),
    (
        V0_11_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        V0_11_PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64
    ),
);

macro_rules! expose_as_shortint_pbs_parameters(
    (
        $(($version:ident, $pfail:ident)),*$(,)?
    ) => {
        expose_as_shortint_pbs_parameters!(inner @
            tuniform =>
            // TUniform
            PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        );
        ::paste::paste!{
        $(
            expose_as_shortint_pbs_parameters!(inner @
                $version =>
                // Gaussian
                [<$version:upper _ PARAM_MESSAGE_1_CARRY_0_KS_PBS_GAUSSIAN_2 $pfail:upper>],
                [<$version:upper _ PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2 $pfail:upper>],
                [<$version:upper _ PARAM_MESSAGE_2_CARRY_0_KS_PBS_GAUSSIAN_2 $pfail:upper>],
                [<$version:upper _ PARAM_MESSAGE_1_CARRY_2_KS_PBS_GAUSSIAN_2 $pfail:upper>],
                [<$version:upper _ PARAM_MESSAGE_2_CARRY_1_KS_PBS_GAUSSIAN_2 $pfail:upper>],
                [<$version:upper _ PARAM_MESSAGE_3_CARRY_0_KS_PBS_GAUSSIAN_2 $pfail:upper>],
                [<$version:upper _ PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2 $pfail:upper>],
                [<$version:upper _ PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2 $pfail:upper>],
                [<$version:upper _ PARAM_MESSAGE_3_CARRY_1_KS_PBS_GAUSSIAN_2 $pfail:upper>],
                [<$version:upper _ PARAM_MESSAGE_4_CARRY_0_KS_PBS_GAUSSIAN_2 $pfail:upper>],
                [<$version:upper _ PARAM_MESSAGE_1_CARRY_4_KS_PBS_GAUSSIAN_2 $pfail:upper>],
                [<$version:upper _ PARAM_MESSAGE_2_CARRY_3_KS_PBS_GAUSSIAN_2 $pfail:upper>],
                [<$version:upper _ PARAM_MESSAGE_3_CARRY_2_KS_PBS_GAUSSIAN_2 $pfail:upper>],
                [<$version:upper _ PARAM_MESSAGE_4_CARRY_1_KS_PBS_GAUSSIAN_2 $pfail:upper>],
                [<$version:upper _ PARAM_MESSAGE_5_CARRY_0_KS_PBS_GAUSSIAN_2 $pfail:upper>],
                [<$version:upper _ PARAM_MESSAGE_1_CARRY_5_KS_PBS_GAUSSIAN_2 $pfail:upper>],
                [<$version:upper _ PARAM_MESSAGE_2_CARRY_4_KS_PBS_GAUSSIAN_2 $pfail:upper>],
                [<$version:upper _ PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2 $pfail:upper>],
                [<$version:upper _ PARAM_MESSAGE_4_CARRY_2_KS_PBS_GAUSSIAN_2 $pfail:upper>],
                [<$version:upper _ PARAM_MESSAGE_5_CARRY_1_KS_PBS_GAUSSIAN_2 $pfail:upper>],
                [<$version:upper _ PARAM_MESSAGE_6_CARRY_0_KS_PBS_GAUSSIAN_2 $pfail:upper>],
                [<$version:upper _ PARAM_MESSAGE_1_CARRY_6_KS_PBS_GAUSSIAN_2 $pfail:upper>],
                [<$version:upper _ PARAM_MESSAGE_2_CARRY_5_KS_PBS_GAUSSIAN_2 $pfail:upper>],
                [<$version:upper _ PARAM_MESSAGE_3_CARRY_4_KS_PBS_GAUSSIAN_2 $pfail:upper>],
                [<$version:upper _ PARAM_MESSAGE_4_CARRY_3_KS_PBS_GAUSSIAN_2 $pfail:upper>],
                [<$version:upper _ PARAM_MESSAGE_5_CARRY_2_KS_PBS_GAUSSIAN_2 $pfail:upper>],
                [<$version:upper _ PARAM_MESSAGE_6_CARRY_1_KS_PBS_GAUSSIAN_2 $pfail:upper>],
                [<$version:upper _ PARAM_MESSAGE_7_CARRY_0_KS_PBS_GAUSSIAN_2 $pfail:upper>],
                [<$version:upper _ PARAM_MESSAGE_1_CARRY_7_KS_PBS_GAUSSIAN_2 $pfail:upper>],
                [<$version:upper _ PARAM_MESSAGE_2_CARRY_6_KS_PBS_GAUSSIAN_2 $pfail:upper>],
                [<$version:upper _ PARAM_MESSAGE_3_CARRY_5_KS_PBS_GAUSSIAN_2 $pfail:upper>],
                [<$version:upper _ PARAM_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2 $pfail:upper>],
                [<$version:upper _ PARAM_MESSAGE_5_CARRY_3_KS_PBS_GAUSSIAN_2 $pfail:upper>],
                [<$version:upper _ PARAM_MESSAGE_6_CARRY_2_KS_PBS_GAUSSIAN_2 $pfail:upper>],
                [<$version:upper _ PARAM_MESSAGE_7_CARRY_1_KS_PBS_GAUSSIAN_2 $pfail:upper>],
                [<$version:upper _ PARAM_MESSAGE_8_CARRY_0_KS_PBS_GAUSSIAN_2 $pfail:upper>],
                // Small params
                [<$version:upper _ PARAM_MESSAGE_1_CARRY_1_PBS_KS_GAUSSIAN_2 $pfail:upper>],
                [<$version:upper _ PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2 $pfail:upper>],
                [<$version:upper _ PARAM_MESSAGE_3_CARRY_3_PBS_KS_GAUSSIAN_2 $pfail:upper>],
                [<$version:upper _ PARAM_MESSAGE_4_CARRY_4_PBS_KS_GAUSSIAN_2 $pfail:upper>],
                // CPK
                [<$version:upper _ PARAM_MESSAGE_1_CARRY_1_COMPACT_PK_KS_PBS_GAUSSIAN_2 $pfail:upper>],
                [<$version:upper _ PARAM_MESSAGE_1_CARRY_2_COMPACT_PK_KS_PBS_GAUSSIAN_2 $pfail:upper>],
                [<$version:upper _ PARAM_MESSAGE_1_CARRY_3_COMPACT_PK_KS_PBS_GAUSSIAN_2 $pfail:upper>],
                [<$version:upper _ PARAM_MESSAGE_1_CARRY_4_COMPACT_PK_KS_PBS_GAUSSIAN_2 $pfail:upper>],
                [<$version:upper _ PARAM_MESSAGE_1_CARRY_5_COMPACT_PK_KS_PBS_GAUSSIAN_2 $pfail:upper>],
                [<$version:upper _ PARAM_MESSAGE_1_CARRY_6_COMPACT_PK_KS_PBS_GAUSSIAN_2 $pfail:upper>],
                [<$version:upper _ PARAM_MESSAGE_1_CARRY_7_COMPACT_PK_KS_PBS_GAUSSIAN_2 $pfail:upper>],
                [<$version:upper _ PARAM_MESSAGE_2_CARRY_1_COMPACT_PK_KS_PBS_GAUSSIAN_2 $pfail:upper>],
                [<$version:upper _ PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS_GAUSSIAN_2 $pfail:upper>],
                [<$version:upper _ PARAM_MESSAGE_2_CARRY_3_COMPACT_PK_KS_PBS_GAUSSIAN_2 $pfail:upper>],
                [<$version:upper _ PARAM_MESSAGE_2_CARRY_4_COMPACT_PK_KS_PBS_GAUSSIAN_2 $pfail:upper>],
                [<$version:upper _ PARAM_MESSAGE_2_CARRY_5_COMPACT_PK_KS_PBS_GAUSSIAN_2 $pfail:upper>],
                [<$version:upper _ PARAM_MESSAGE_2_CARRY_6_COMPACT_PK_KS_PBS_GAUSSIAN_2 $pfail:upper>],
                [<$version:upper _ PARAM_MESSAGE_3_CARRY_1_COMPACT_PK_KS_PBS_GAUSSIAN_2 $pfail:upper>],
                [<$version:upper _ PARAM_MESSAGE_3_CARRY_2_COMPACT_PK_KS_PBS_GAUSSIAN_2 $pfail:upper>],
                [<$version:upper _ PARAM_MESSAGE_3_CARRY_3_COMPACT_PK_KS_PBS_GAUSSIAN_2 $pfail:upper>],
                [<$version:upper _ PARAM_MESSAGE_3_CARRY_4_COMPACT_PK_KS_PBS_GAUSSIAN_2 $pfail:upper>],
                [<$version:upper _ PARAM_MESSAGE_3_CARRY_5_COMPACT_PK_KS_PBS_GAUSSIAN_2 $pfail:upper>],
                [<$version:upper _ PARAM_MESSAGE_4_CARRY_1_COMPACT_PK_KS_PBS_GAUSSIAN_2 $pfail:upper>],
                [<$version:upper _ PARAM_MESSAGE_4_CARRY_2_COMPACT_PK_KS_PBS_GAUSSIAN_2 $pfail:upper>],
                [<$version:upper _ PARAM_MESSAGE_4_CARRY_3_COMPACT_PK_KS_PBS_GAUSSIAN_2 $pfail:upper>],
                [<$version:upper _ PARAM_MESSAGE_4_CARRY_4_COMPACT_PK_KS_PBS_GAUSSIAN_2 $pfail:upper>],
                [<$version:upper _ PARAM_MESSAGE_5_CARRY_1_COMPACT_PK_KS_PBS_GAUSSIAN_2 $pfail:upper>],
                [<$version:upper _ PARAM_MESSAGE_5_CARRY_2_COMPACT_PK_KS_PBS_GAUSSIAN_2 $pfail:upper>],
                [<$version:upper _ PARAM_MESSAGE_5_CARRY_3_COMPACT_PK_KS_PBS_GAUSSIAN_2 $pfail:upper>],
                [<$version:upper _ PARAM_MESSAGE_6_CARRY_1_COMPACT_PK_KS_PBS_GAUSSIAN_2 $pfail:upper>],
                [<$version:upper _ PARAM_MESSAGE_6_CARRY_2_COMPACT_PK_KS_PBS_GAUSSIAN_2 $pfail:upper>],
                [<$version:upper _ PARAM_MESSAGE_7_CARRY_1_COMPACT_PK_KS_PBS_GAUSSIAN_2 $pfail:upper>],
                // CPK SMALL
                [<$version:upper _ PARAM_MESSAGE_1_CARRY_1_COMPACT_PK_PBS_KS_GAUSSIAN_2 $pfail:upper>],
                [<$version:upper _ PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_PBS_KS_GAUSSIAN_2 $pfail:upper>],
                [<$version:upper _ PARAM_MESSAGE_3_CARRY_3_COMPACT_PK_PBS_KS_GAUSSIAN_2 $pfail:upper>],
                [<$version:upper _ PARAM_MESSAGE_4_CARRY_4_COMPACT_PK_PBS_KS_GAUSSIAN_2 $pfail:upper>],
            );
        )*
        }
    };
    (
        inner @ $test_id:ident => $(
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
        ::paste::paste!{
            #[test]
            fn [<test_shortint_pbs_parameters_roundtrip_c_rust _ $test_id:lower>]() {
                $(
                    // 1 scope for each parameters
                    {
                        let rust_params = $param_name;
                        let c_params = ShortintPBSParameters::from(rust_params);
                        let rust_params_from_c = crate::shortint::parameters::ClassicPBSParameters::try_from(c_params).unwrap();
                        assert_eq!(rust_params, rust_params_from_c);
                    }
                )*
            }
        }
    };
);

expose_as_shortint_pbs_parameters!(
    (V1_5, M128),
    (V1_4, M128),
    (V1_3, M128),
    (V1_2, M128),
    (V1_1, M128),
    (V1_0, M128),
    (V0_11, M64),
);

pub struct CompressionParameters(
    pub(crate) crate::shortint::parameters::list_compression::CompressionParameters,
);

macro_rules! expose_as_shortint_compression_parameters(
    (
        $(
            $param_name:ident
        ),*
        $(,)?
    ) => {
        ::paste::paste!{
            $(
                #[no_mangle]
                pub static [<SHORTINT_ $param_name>]: CompressionParameters =
                    CompressionParameters(
                        $param_name,
                    );
            )*
        }
    }
);

expose_as_shortint_compression_parameters!(
    COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    // v1.5
    V1_5_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    V1_5_COMP_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    // v1.4
    V1_4_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    V1_4_COMP_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    // v1.3
    V1_3_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    V1_3_COMP_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    // v1.2
    V1_2_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    V1_2_COMP_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    // v1.1
    V1_1_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    V1_1_COMP_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    // v1.0
    V1_0_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    // v0.11
    V0_11_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64
);
