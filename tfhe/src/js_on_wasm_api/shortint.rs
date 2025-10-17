#![allow(clippy::use_self)]
use crate::core_crypto::commons::generators::DeterministicSeeder;
use crate::core_crypto::commons::math::random::Seed;
use crate::core_crypto::prelude::DefaultRandomGenerator;
use crate::js_on_wasm_api::into_js_error;
use crate::shortint::parameters::v0_11::classic::compact_pk::*;
use crate::shortint::parameters::v0_11::classic::gaussian::*;
use crate::shortint::parameters::v0_11::compact_public_key_only::p_fail_2_minus_64::ks_pbs::*;
use crate::shortint::parameters::v0_11::key_switching::p_fail_2_minus_64::ks_pbs::*;
use crate::shortint::parameters::v1_0::*;
use crate::shortint::parameters::v1_1::*;
use crate::shortint::parameters::v1_2::*;
use crate::shortint::parameters::v1_3::*;
use crate::shortint::parameters::v1_4::*;
use crate::shortint::parameters::v1_5::*;
use crate::shortint::parameters::*;
use std::panic::set_hook;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct ShortintCiphertext(pub(crate) crate::shortint::Ciphertext);

#[wasm_bindgen]
pub struct ShortintCompressedCiphertext(pub(crate) crate::shortint::CompressedCiphertext);

#[wasm_bindgen]
pub struct ShortintClientKey(pub(crate) crate::shortint::ClientKey);

#[wasm_bindgen]
pub struct ShortintPublicKey(pub(crate) crate::shortint::PublicKey);

#[wasm_bindgen]
pub struct ShortintCompressedPublicKey(pub(crate) crate::shortint::CompressedPublicKey);

#[wasm_bindgen]
pub struct ShortintCompressedServerKey(pub(crate) crate::shortint::CompressedServerKey);

#[wasm_bindgen]
pub struct Shortint {}

#[wasm_bindgen]
pub struct ShortintParameters(pub(crate) crate::shortint::ClassicPBSParameters);

#[wasm_bindgen]
pub struct ShortintCompactPublicKeyEncryptionParameters {
    pub(crate) compact_pke_params:
        crate::shortint::parameters::compact_public_key_only::CompactPublicKeyEncryptionParameters,
    pub(crate) casting_parameters:
        crate::shortint::parameters::key_switching::ShortintKeySwitchingParameters,
}

#[wasm_bindgen]
impl ShortintParameters {
    #[wasm_bindgen]
    pub fn lwe_dimension(&self) -> usize {
        self.0.lwe_dimension.0
    }

    #[wasm_bindgen]
    pub fn set_lwe_dimension(&mut self, new_value: usize) {
        self.0.lwe_dimension.0 = new_value;
    }

    #[wasm_bindgen]
    pub fn glwe_dimension(&self) -> usize {
        self.0.glwe_dimension.0
    }

    #[wasm_bindgen]
    pub fn set_glwe_dimension(&mut self, new_value: usize) {
        self.0.glwe_dimension.0 = new_value;
    }

    #[wasm_bindgen]
    pub fn polynomial_size(&self) -> usize {
        self.0.polynomial_size.0
    }

    #[wasm_bindgen]
    pub fn set_polynomial_size(&mut self, new_value: usize) {
        self.0.polynomial_size.0 = new_value;
    }

    #[wasm_bindgen]
    pub fn lwe_noise_distribution(&self) -> ShortintNoiseDistribution {
        ShortintNoiseDistribution(self.0.lwe_noise_distribution)
    }

    #[wasm_bindgen]
    pub fn set_lwe_noise_distribution(&mut self, new_value: &ShortintNoiseDistribution) {
        self.0.lwe_noise_distribution = new_value.0;
    }

    #[wasm_bindgen]
    pub fn glwe_noise_distribution(&self) -> ShortintNoiseDistribution {
        ShortintNoiseDistribution(self.0.lwe_noise_distribution)
    }

    #[wasm_bindgen]
    pub fn set_glwe_noise_distribution(&mut self, new_value: &ShortintNoiseDistribution) {
        self.0.glwe_noise_distribution = new_value.0;
    }

    #[wasm_bindgen]
    pub fn pbs_base_log(&self) -> usize {
        self.0.pbs_base_log.0
    }

    #[wasm_bindgen]
    pub fn set_pbs_base_log(&mut self, new_value: usize) {
        self.0.pbs_base_log.0 = new_value;
    }

    #[wasm_bindgen]
    pub fn pbs_level(&self) -> usize {
        self.0.pbs_level.0
    }

    #[wasm_bindgen]
    pub fn set_pbs_level(&mut self, new_value: usize) {
        self.0.pbs_level.0 = new_value;
    }

    #[wasm_bindgen]
    pub fn ks_base_log(&self) -> usize {
        self.0.ks_base_log.0
    }

    #[wasm_bindgen]
    pub fn set_ks_base_log(&mut self, new_value: usize) {
        self.0.ks_base_log.0 = new_value;
    }

    #[wasm_bindgen]
    pub fn ks_level(&self) -> usize {
        self.0.ks_level.0
    }

    #[wasm_bindgen]
    pub fn set_ks_level(&mut self, new_value: usize) {
        self.0.ks_level.0 = new_value;
    }

    #[wasm_bindgen]
    pub fn message_modulus(&self) -> u64 {
        self.0.message_modulus.0
    }

    #[wasm_bindgen]
    pub fn set_message_modulus(&mut self, new_value: u64) {
        self.0.message_modulus.0 = new_value;
    }

    #[wasm_bindgen]
    pub fn carry_modulus(&self) -> u64 {
        self.0.carry_modulus.0
    }

    #[wasm_bindgen]
    pub fn set_carry_modulus(&mut self, new_value: u64) {
        self.0.carry_modulus.0 = new_value;
    }

    #[wasm_bindgen]
    pub fn encryption_key_choice(&self) -> ShortintEncryptionKeyChoice {
        self.0.encryption_key_choice.into()
    }

    #[wasm_bindgen]
    pub fn set_encryption_key_choice(&mut self, new_value: ShortintEncryptionKeyChoice) {
        self.0.encryption_key_choice = new_value.into();
    }
}

#[wasm_bindgen]
pub enum ShortintEncryptionKeyChoice {
    Big,
    Small,
}

impl From<ShortintEncryptionKeyChoice> for EncryptionKeyChoice {
    fn from(value: ShortintEncryptionKeyChoice) -> Self {
        match value {
            ShortintEncryptionKeyChoice::Big => Self::Big,
            ShortintEncryptionKeyChoice::Small => Self::Small,
        }
    }
}

impl From<EncryptionKeyChoice> for ShortintEncryptionKeyChoice {
    fn from(value: EncryptionKeyChoice) -> Self {
        match value {
            EncryptionKeyChoice::Big => Self::Big,
            EncryptionKeyChoice::Small => Self::Small,
        }
    }
}

#[derive(Copy, Clone)]
#[wasm_bindgen]
pub enum ShortintPBSOrder {
    KeyswitchBootstrap,
    BootstrapKeyswitch,
}

impl From<ShortintPBSOrder> for crate::shortint::parameters::PBSOrder {
    fn from(value: ShortintPBSOrder) -> Self {
        match value {
            ShortintPBSOrder::KeyswitchBootstrap => Self::KeyswitchBootstrap,
            ShortintPBSOrder::BootstrapKeyswitch => Self::BootstrapKeyswitch,
        }
    }
}

#[wasm_bindgen]
pub struct ShortintNoiseDistribution(
    pub(crate) crate::core_crypto::commons::math::random::DynamicDistribution<u64>,
);

macro_rules! expose_predefined_pke_parameters {
    (
        $(
            ($param_pke_name:ident, $param_ks_name:ident)
        ),*
        $(,)?
    ) => {
        #[wasm_bindgen]
        #[derive(Clone, Copy)]
        #[allow(non_camel_case_types)]
        pub enum ShortintCompactPublicKeyEncryptionParametersName {
            $(
                $param_pke_name,
            )*
        }

        // wasm bindgen does not support methods on enums
        #[wasm_bindgen]
        pub fn shortint_pke_params_name(param: ShortintCompactPublicKeyEncryptionParametersName) -> String {
            match param {
                $(
                    ShortintCompactPublicKeyEncryptionParametersName::$param_pke_name => stringify!($param_pke_name).to_string(),
                )*
            }
        }


        #[wasm_bindgen]
        impl ShortintCompactPublicKeyEncryptionParameters {
            #[allow(clippy::needless_pass_by_value)]
            #[wasm_bindgen(constructor)]
            pub fn new(name: ShortintCompactPublicKeyEncryptionParametersName) -> Self {
                match name {
                    $(
                        ShortintCompactPublicKeyEncryptionParametersName::$param_pke_name => {
                            Self {
                                compact_pke_params: $param_pke_name,
                                casting_parameters: $param_ks_name,
                            }
                        },
                    )*
                }
            }
        }
    }
}

// WARNING: add new versions at the END of the macro to keep identifiers consistent across versions
expose_predefined_pke_parameters!(
    (
        PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
    ),
    (
        V1_1_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        V1_1_PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
    ),
    (
        V1_1_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV1,
        V1_1_PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV1
    ),
    (
        V1_0_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        V1_0_PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
    ),
    (
        V1_0_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV1,
        V1_0_PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV1
    ),
    (
        V0_11_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        V0_11_PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64
    ),
    (
        V0_11_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64_ZKV1,
        V0_11_PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64_ZKV1
    ),
    // A mistake was made from 1.0 to 1.1, starting with 1.2 we put new parameters at the end
    // to retain the order of previous parameters and compatibility for them
    (
        V1_2_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        V1_2_PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
    ),
    (
        V1_2_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV1,
        V1_2_PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV1
    ),
    (
        V1_3_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        V1_3_PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
    ),
    (
        V1_3_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV1,
        V1_3_PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV1
    ),
    (
        V1_4_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        V1_4_PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
    ),
    (
        V1_4_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV1,
        V1_4_PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV1
    ),
    (
        V1_5_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        V1_5_PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
    ),
    (
        V1_5_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV1,
        V1_5_PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV1
    ),
);

#[wasm_bindgen]
impl ShortintCompactPublicKeyEncryptionParameters {
    #[wasm_bindgen]
    #[allow(clippy::too_many_arguments)]
    pub fn new_parameters(
        // Public Key Parameters
        encryption_lwe_dimension: usize,
        encryption_noise_distribution: &ShortintNoiseDistribution,
        message_modulus: u64,
        carry_modulus: u64,
        modulus_power_of_2_exponent: usize,
        // Casting Parameters
        ks_base_log: usize,
        ks_level: usize,
        encryption_key_choice: ShortintEncryptionKeyChoice,
    ) -> Result<ShortintCompactPublicKeyEncryptionParameters, JsError> {
        let ciphertext_modulus =
            crate::shortint::parameters::CiphertextModulus::try_new_power_of_2(
                modulus_power_of_2_exponent,
            )
            .map_err(into_js_error)?;

        let compact_pke_params = crate::shortint::parameters::compact_public_key_only::CompactPublicKeyEncryptionParameters::try_new(
            LweDimension(encryption_lwe_dimension),
            encryption_noise_distribution.0,
            MessageModulus(message_modulus),
            CarryModulus(carry_modulus),
            ciphertext_modulus,
            // These parameters always requires casting
            crate::shortint::parameters::CompactCiphertextListExpansionKind::RequiresCasting,
            crate::shortint::parameters::SupportedCompactPkeZkScheme::ZkNotSupported
        ).map_err(into_js_error)?;

        let casting_parameters =
            crate::shortint::parameters::key_switching::ShortintKeySwitchingParameters {
                ks_base_log: DecompositionBaseLog(ks_base_log),
                ks_level: DecompositionLevelCount(ks_level),
                destination_key: encryption_key_choice.into(),
            };

        Ok(Self {
            compact_pke_params,
            casting_parameters,
        })
    }
}

macro_rules! expose_predefined_pbs_parameters {
    ($(($version:ident, $pfail:ident)),*$(,)? @ $($param_base_name:ident),*$(,)?) => {
        expose_predefined_pbs_parameters_helper_1!([$([($version, $pfail)])*][$([$param_base_name])*]);
    }
}
macro_rules! expose_predefined_pbs_parameters_helper_1 {
    ([$([($version:ident, $pfail:ident)])*]$param_base_name:tt) => {
        expose_predefined_pbs_parameters_helper_2!($([[($version, $pfail)]$param_base_name])*);
    }
}
macro_rules! expose_predefined_pbs_parameters_helper_2 {
    ($([[($version:ident, $pfail:ident)][$([$param_base_name:ident])*]])*) => {
        ::paste::paste! {
            #[wasm_bindgen]
            #[derive(Clone, Copy)]
            #[allow(non_camel_case_types)]
            pub enum ShortintParametersName {
                PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
                $($([<$version:upper _ $param_base_name $pfail:upper>]),*),*
            }

            // wasm bindgen does not support methods on enums
            #[wasm_bindgen]
            pub fn shortint_params_name(param: Option<ShortintParametersName>) -> Result<String, JsError> {
                let Some(param) = param else {
                    return Err(JsError::new("invalid variant for ShortintParametersName"));
                };

                match param {
                    ShortintParametersName::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128 => Ok("PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128".to_string()),
                    $(
                        $(
                            ShortintParametersName::[<$version:upper _ $param_base_name $pfail:upper>] => Ok(stringify!([<$version:upper _ $param_base_name $pfail:upper>]).to_string()),
                        )*
                    )*
                }
            }

            #[wasm_bindgen]
            impl ShortintParameters {
                #[wasm_bindgen(constructor)]
                pub fn new(name: Option<ShortintParametersName>) -> Result<Self, JsError> {
                    let Some(name) = name else {
                        return Err(JsError::new("invalid variant for ShortintParametersName"));
                    };
                    match name {
                        ShortintParametersName::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128 => {
                            Ok(Self(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128))
                        },
                        $(
                            $(
                                ShortintParametersName::[<$version:upper _ $param_base_name $pfail:upper>] => {
                                    Ok(Self([<$version:upper _ $param_base_name $pfail:upper>]))
                                }
                            )*
                        )*
                    }
                }
            }
        }
    }
}

// Add new versions at THE END to conserve orders in macros
// A mistake was made in 1.1 and versions were added at the start, to conserve the backward
// compatible order starting with 1.1, new versions are now added at the END
expose_predefined_pbs_parameters!(
    (V1_1, M128), (V1_0, M128), (V0_11, M64), (V1_2, M128), (V1_3, M128), (V1_4, M128), (V1_5, M128) @
    PARAM_MESSAGE_1_CARRY_0_KS_PBS_GAUSSIAN_2,
    PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2,
    PARAM_MESSAGE_2_CARRY_0_KS_PBS_GAUSSIAN_2,
    PARAM_MESSAGE_1_CARRY_2_KS_PBS_GAUSSIAN_2,
    PARAM_MESSAGE_2_CARRY_1_KS_PBS_GAUSSIAN_2,
    PARAM_MESSAGE_3_CARRY_0_KS_PBS_GAUSSIAN_2,
    PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2,
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2,
    PARAM_MESSAGE_3_CARRY_1_KS_PBS_GAUSSIAN_2,
    PARAM_MESSAGE_4_CARRY_0_KS_PBS_GAUSSIAN_2,
    PARAM_MESSAGE_1_CARRY_4_KS_PBS_GAUSSIAN_2,
    PARAM_MESSAGE_2_CARRY_3_KS_PBS_GAUSSIAN_2,
    PARAM_MESSAGE_3_CARRY_2_KS_PBS_GAUSSIAN_2,
    PARAM_MESSAGE_4_CARRY_1_KS_PBS_GAUSSIAN_2,
    PARAM_MESSAGE_5_CARRY_0_KS_PBS_GAUSSIAN_2,
    PARAM_MESSAGE_1_CARRY_5_KS_PBS_GAUSSIAN_2,
    PARAM_MESSAGE_2_CARRY_4_KS_PBS_GAUSSIAN_2,
    PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2,
    PARAM_MESSAGE_4_CARRY_2_KS_PBS_GAUSSIAN_2,
    PARAM_MESSAGE_5_CARRY_1_KS_PBS_GAUSSIAN_2,
    PARAM_MESSAGE_6_CARRY_0_KS_PBS_GAUSSIAN_2,
    PARAM_MESSAGE_1_CARRY_6_KS_PBS_GAUSSIAN_2,
    PARAM_MESSAGE_2_CARRY_5_KS_PBS_GAUSSIAN_2,
    PARAM_MESSAGE_3_CARRY_4_KS_PBS_GAUSSIAN_2,
    PARAM_MESSAGE_4_CARRY_3_KS_PBS_GAUSSIAN_2,
    PARAM_MESSAGE_5_CARRY_2_KS_PBS_GAUSSIAN_2,
    PARAM_MESSAGE_6_CARRY_1_KS_PBS_GAUSSIAN_2,
    PARAM_MESSAGE_7_CARRY_0_KS_PBS_GAUSSIAN_2,
    PARAM_MESSAGE_1_CARRY_7_KS_PBS_GAUSSIAN_2,
    PARAM_MESSAGE_2_CARRY_6_KS_PBS_GAUSSIAN_2,
    PARAM_MESSAGE_3_CARRY_5_KS_PBS_GAUSSIAN_2,
    PARAM_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2,
    PARAM_MESSAGE_5_CARRY_3_KS_PBS_GAUSSIAN_2,
    PARAM_MESSAGE_6_CARRY_2_KS_PBS_GAUSSIAN_2,
    PARAM_MESSAGE_7_CARRY_1_KS_PBS_GAUSSIAN_2,
    PARAM_MESSAGE_8_CARRY_0_KS_PBS_GAUSSIAN_2,
    // Small params
    PARAM_MESSAGE_1_CARRY_1_PBS_KS_GAUSSIAN_2,
    PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2,
    PARAM_MESSAGE_3_CARRY_3_PBS_KS_GAUSSIAN_2,
    PARAM_MESSAGE_4_CARRY_4_PBS_KS_GAUSSIAN_2,
    // CPK
    PARAM_MESSAGE_1_CARRY_2_COMPACT_PK_KS_PBS_GAUSSIAN_2,
    PARAM_MESSAGE_1_CARRY_3_COMPACT_PK_KS_PBS_GAUSSIAN_2,
    PARAM_MESSAGE_1_CARRY_4_COMPACT_PK_KS_PBS_GAUSSIAN_2,
    PARAM_MESSAGE_1_CARRY_5_COMPACT_PK_KS_PBS_GAUSSIAN_2,
    PARAM_MESSAGE_1_CARRY_6_COMPACT_PK_KS_PBS_GAUSSIAN_2,
    PARAM_MESSAGE_1_CARRY_7_COMPACT_PK_KS_PBS_GAUSSIAN_2,
    PARAM_MESSAGE_2_CARRY_1_COMPACT_PK_KS_PBS_GAUSSIAN_2,
    PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS_GAUSSIAN_2,
    PARAM_MESSAGE_2_CARRY_3_COMPACT_PK_KS_PBS_GAUSSIAN_2,
    PARAM_MESSAGE_2_CARRY_4_COMPACT_PK_KS_PBS_GAUSSIAN_2,
    PARAM_MESSAGE_2_CARRY_5_COMPACT_PK_KS_PBS_GAUSSIAN_2,
    PARAM_MESSAGE_2_CARRY_6_COMPACT_PK_KS_PBS_GAUSSIAN_2,
    PARAM_MESSAGE_3_CARRY_1_COMPACT_PK_KS_PBS_GAUSSIAN_2,
    PARAM_MESSAGE_3_CARRY_2_COMPACT_PK_KS_PBS_GAUSSIAN_2,
    PARAM_MESSAGE_3_CARRY_3_COMPACT_PK_KS_PBS_GAUSSIAN_2,
    PARAM_MESSAGE_3_CARRY_4_COMPACT_PK_KS_PBS_GAUSSIAN_2,
    PARAM_MESSAGE_3_CARRY_5_COMPACT_PK_KS_PBS_GAUSSIAN_2,
    PARAM_MESSAGE_4_CARRY_1_COMPACT_PK_KS_PBS_GAUSSIAN_2,
    PARAM_MESSAGE_4_CARRY_2_COMPACT_PK_KS_PBS_GAUSSIAN_2,
    PARAM_MESSAGE_4_CARRY_3_COMPACT_PK_KS_PBS_GAUSSIAN_2,
    PARAM_MESSAGE_4_CARRY_4_COMPACT_PK_KS_PBS_GAUSSIAN_2,
    PARAM_MESSAGE_5_CARRY_1_COMPACT_PK_KS_PBS_GAUSSIAN_2,
    PARAM_MESSAGE_5_CARRY_2_COMPACT_PK_KS_PBS_GAUSSIAN_2,
    PARAM_MESSAGE_5_CARRY_3_COMPACT_PK_KS_PBS_GAUSSIAN_2,
    PARAM_MESSAGE_6_CARRY_1_COMPACT_PK_KS_PBS_GAUSSIAN_2,
    PARAM_MESSAGE_6_CARRY_2_COMPACT_PK_KS_PBS_GAUSSIAN_2,
    PARAM_MESSAGE_7_CARRY_1_COMPACT_PK_KS_PBS_GAUSSIAN_2,
    // CPK Small
    PARAM_MESSAGE_1_CARRY_1_COMPACT_PK_PBS_KS_GAUSSIAN_2,
    PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_PBS_KS_GAUSSIAN_2,
    PARAM_MESSAGE_3_CARRY_3_COMPACT_PK_PBS_KS_GAUSSIAN_2,
    PARAM_MESSAGE_4_CARRY_4_COMPACT_PK_PBS_KS_GAUSSIAN_2
);

#[wasm_bindgen]
impl Shortint {
    #[wasm_bindgen]
    pub fn new_gaussian_from_std_dev(std_dev: f64) -> ShortintNoiseDistribution {
        use crate::core_crypto::prelude::*;
        ShortintNoiseDistribution(DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            std_dev,
        )))
    }

    #[wasm_bindgen]
    pub fn try_new_t_uniform(bound_log2: u32) -> Result<ShortintNoiseDistribution, JsError> {
        use crate::core_crypto::prelude::*;
        DynamicDistribution::try_new_t_uniform(bound_log2)
            .map(ShortintNoiseDistribution)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{e:?}").as_str()))
    }

    #[wasm_bindgen]
    #[allow(clippy::too_many_arguments)]
    pub fn new_parameters(
        lwe_dimension: usize,
        glwe_dimension: usize,
        polynomial_size: usize,
        lwe_noise_distribution: &ShortintNoiseDistribution,
        glwe_noise_distribution: &ShortintNoiseDistribution,
        pbs_base_log: usize,
        pbs_level: usize,
        ks_base_log: usize,
        ks_level: usize,
        message_modulus: u64,
        carry_modulus: u64,
        max_noise_level: u64,
        log2_p_fail: f64,
        modulus_power_of_2_exponent: usize,
        encryption_key_choice: ShortintEncryptionKeyChoice,
    ) -> ShortintParameters {
        set_hook(Box::new(console_error_panic_hook::hook));
        use crate::core_crypto::prelude::*;
        ShortintParameters(crate::shortint::ClassicPBSParameters {
            lwe_dimension: LweDimension(lwe_dimension),
            glwe_dimension: GlweDimension(glwe_dimension),
            polynomial_size: PolynomialSize(polynomial_size),
            lwe_noise_distribution: lwe_noise_distribution.0,
            glwe_noise_distribution: glwe_noise_distribution.0,
            pbs_base_log: DecompositionBaseLog(pbs_base_log),
            pbs_level: DecompositionLevelCount(pbs_level),
            ks_base_log: DecompositionBaseLog(ks_base_log),
            ks_level: DecompositionLevelCount(ks_level),
            message_modulus: crate::shortint::parameters::MessageModulus(message_modulus),
            carry_modulus: crate::shortint::parameters::CarryModulus(carry_modulus),
            max_noise_level: crate::shortint::parameters::MaxNoiseLevel::new(max_noise_level),
            log2_p_fail,
            ciphertext_modulus: crate::shortint::parameters::CiphertextModulus::try_new_power_of_2(
                modulus_power_of_2_exponent,
            )
            .unwrap(),
            encryption_key_choice: encryption_key_choice.into(),
            modulus_switch_noise_reduction_params: ModulusSwitchType::Standard,
        })
    }

    #[wasm_bindgen]
    pub fn new_client_key_from_seed_and_parameters(
        seed_high_bytes: u64,
        seed_low_bytes: u64,
        parameters: &ShortintParameters,
    ) -> ShortintClientKey {
        set_hook(Box::new(console_error_panic_hook::hook));
        let seed_high_bytes: u128 = seed_high_bytes.into();
        let seed_low_bytes: u128 = seed_low_bytes.into();
        let seed: u128 = (seed_high_bytes << 64) | seed_low_bytes;

        let mut seeder = DeterministicSeeder::<DefaultRandomGenerator>::new(Seed(seed));
        ShortintClientKey(
            crate::shortint::engine::ShortintEngine::new_from_seeder(&mut seeder)
                .new_client_key(parameters.0),
        )
    }

    #[wasm_bindgen]
    pub fn new_client_key(parameters: &ShortintParameters) -> ShortintClientKey {
        set_hook(Box::new(console_error_panic_hook::hook));

        ShortintClientKey(crate::shortint::client_key::ClientKey::new(parameters.0))
    }

    #[wasm_bindgen]
    pub fn new_public_key(client_key: &ShortintClientKey) -> ShortintPublicKey {
        set_hook(Box::new(console_error_panic_hook::hook));

        ShortintPublicKey(crate::shortint::public_key::PublicKey::new(&client_key.0))
    }

    #[wasm_bindgen]
    pub fn new_compressed_public_key(
        client_key: &ShortintClientKey,
    ) -> ShortintCompressedPublicKey {
        set_hook(Box::new(console_error_panic_hook::hook));

        ShortintCompressedPublicKey(crate::shortint::public_key::CompressedPublicKey::new(
            &client_key.0,
        ))
    }

    #[wasm_bindgen]
    pub fn new_compressed_server_key(
        client_key: &ShortintClientKey,
    ) -> ShortintCompressedServerKey {
        set_hook(Box::new(console_error_panic_hook::hook));

        ShortintCompressedServerKey(crate::shortint::server_key::CompressedServerKey::new(
            &client_key.0,
        ))
    }

    #[wasm_bindgen]
    pub fn encrypt(client_key: &ShortintClientKey, message: u64) -> ShortintCiphertext {
        set_hook(Box::new(console_error_panic_hook::hook));

        ShortintCiphertext(client_key.0.encrypt(message))
    }

    #[wasm_bindgen]
    pub fn encrypt_compressed(
        client_key: &ShortintClientKey,
        message: u64,
    ) -> ShortintCompressedCiphertext {
        set_hook(Box::new(console_error_panic_hook::hook));

        ShortintCompressedCiphertext(client_key.0.encrypt_compressed(message))
    }

    #[wasm_bindgen]
    pub fn decompress_ciphertext(
        compressed_ciphertext: &ShortintCompressedCiphertext,
    ) -> ShortintCiphertext {
        set_hook(Box::new(console_error_panic_hook::hook));
        ShortintCiphertext(compressed_ciphertext.0.decompress())
    }

    #[wasm_bindgen]
    pub fn encrypt_with_public_key(
        public_key: &ShortintPublicKey,
        message: u64,
    ) -> ShortintCiphertext {
        set_hook(Box::new(console_error_panic_hook::hook));

        ShortintCiphertext(public_key.0.encrypt(message))
    }

    #[wasm_bindgen]
    pub fn encrypt_with_compressed_public_key(
        public_key: &ShortintCompressedPublicKey,
        message: u64,
    ) -> ShortintCiphertext {
        set_hook(Box::new(console_error_panic_hook::hook));

        ShortintCiphertext(public_key.0.encrypt(message))
    }

    #[wasm_bindgen]
    pub fn decrypt(client_key: &ShortintClientKey, ct: &ShortintCiphertext) -> u64 {
        set_hook(Box::new(console_error_panic_hook::hook));
        client_key.0.decrypt(&ct.0)
    }

    #[wasm_bindgen]
    pub fn serialize_ciphertext(ciphertext: &ShortintCiphertext) -> Result<Vec<u8>, JsError> {
        set_hook(Box::new(console_error_panic_hook::hook));
        bincode::serialize(&ciphertext.0)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{e:?}").as_str()))
    }

    #[wasm_bindgen]
    pub fn deserialize_ciphertext(buffer: &[u8]) -> Result<ShortintCiphertext, JsError> {
        set_hook(Box::new(console_error_panic_hook::hook));
        bincode::deserialize(buffer)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{e:?}").as_str()))
            .map(ShortintCiphertext)
    }

    #[wasm_bindgen]
    pub fn serialize_compressed_ciphertext(
        ciphertext: &ShortintCompressedCiphertext,
    ) -> Result<Vec<u8>, JsError> {
        set_hook(Box::new(console_error_panic_hook::hook));
        bincode::serialize(&ciphertext.0)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{e:?}").as_str()))
    }

    #[wasm_bindgen]
    pub fn deserialize_compressed_ciphertext(
        buffer: &[u8],
    ) -> Result<ShortintCompressedCiphertext, JsError> {
        set_hook(Box::new(console_error_panic_hook::hook));
        bincode::deserialize(buffer)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{e:?}").as_str()))
            .map(ShortintCompressedCiphertext)
    }

    #[wasm_bindgen]
    pub fn serialize_client_key(client_key: &ShortintClientKey) -> Result<Vec<u8>, JsError> {
        set_hook(Box::new(console_error_panic_hook::hook));
        bincode::serialize(&client_key.0)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{e:?}").as_str()))
    }

    #[wasm_bindgen]
    pub fn deserialize_client_key(buffer: &[u8]) -> Result<ShortintClientKey, JsError> {
        set_hook(Box::new(console_error_panic_hook::hook));
        bincode::deserialize(buffer)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{e:?}").as_str()))
            .map(ShortintClientKey)
    }

    #[wasm_bindgen]
    pub fn serialize_public_key(public_key: &ShortintPublicKey) -> Result<Vec<u8>, JsError> {
        set_hook(Box::new(console_error_panic_hook::hook));
        bincode::serialize(&public_key.0)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{e:?}").as_str()))
    }

    #[wasm_bindgen]
    pub fn deserialize_public_key(buffer: &[u8]) -> Result<ShortintPublicKey, JsError> {
        set_hook(Box::new(console_error_panic_hook::hook));
        bincode::deserialize(buffer)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{e:?}").as_str()))
            .map(ShortintPublicKey)
    }

    #[wasm_bindgen]
    pub fn serialize_compressed_public_key(
        public_key: &ShortintCompressedPublicKey,
    ) -> Result<Vec<u8>, JsError> {
        set_hook(Box::new(console_error_panic_hook::hook));
        bincode::serialize(&public_key.0)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{e:?}").as_str()))
    }

    #[wasm_bindgen]
    pub fn deserialize_compressed_public_key(
        buffer: &[u8],
    ) -> Result<ShortintCompressedPublicKey, JsError> {
        set_hook(Box::new(console_error_panic_hook::hook));
        bincode::deserialize(buffer)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{e:?}").as_str()))
            .map(ShortintCompressedPublicKey)
    }

    #[wasm_bindgen]
    pub fn serialize_compressed_server_key(
        server_key: &ShortintCompressedServerKey,
    ) -> Result<Vec<u8>, JsError> {
        set_hook(Box::new(console_error_panic_hook::hook));
        bincode::serialize(&server_key.0)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{e:?}").as_str()))
    }

    #[wasm_bindgen]
    pub fn deserialize_compressed_server_key(
        buffer: &[u8],
    ) -> Result<ShortintCompressedServerKey, JsError> {
        set_hook(Box::new(console_error_panic_hook::hook));
        bincode::deserialize(buffer)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{e:?}").as_str()))
            .map(ShortintCompressedServerKey)
    }
}
