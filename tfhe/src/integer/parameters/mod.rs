#![allow(clippy::excessive_precision)]
use crate::conformance::ListSizeConstraint;
use crate::integer::key_switching_key::KeySwitchingKeyView;
use crate::integer::server_key::ServerKey;
use crate::shortint::parameters::{
    CarryModulus, CiphertextConformanceParams, CompactCiphertextListExpansionKind,
    CompactPublicKeyEncryptionParameters, EncryptionKeyChoice, MessageModulus,
};
pub use crate::shortint::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, DynamicDistribution, GlweDimension,
    LweDimension, PolynomialSize, StandardDev,
};
use crate::shortint::PBSParameters;
pub use crate::shortint::{CiphertextModulus, ClassicPBSParameters, WopbsParameters};

#[derive(Clone, Copy)]
pub enum IntegerCompactCiphertextListExpansionMode<'key> {
    /// The [`KeySwitchingKeyView`] has all the information to both cast and unpack.
    CastAndUnpackIfNecessary(KeySwitchingKeyView<'key>),
    /// This only allows to unpack.
    UnpackAndSanitizeIfNecessary(&'key ServerKey),
    NoCastingAndNoUnpacking,
}

pub const ALL_PARAMETER_VEC_INTEGER_16_BITS: [WopbsParameters; 2] = [
    PARAM_MESSAGE_4_CARRY_4_KS_PBS_16_BITS,
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_16_BITS,
];

pub const PARAM_MESSAGE_4_CARRY_4_KS_PBS_16_BITS: WopbsParameters = WopbsParameters {
    lwe_dimension: LweDimension(481),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.00061200133780220371345,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.00000000000000022148688116005568513645324585951,
    )),
    pbs_base_log: DecompositionBaseLog(9),
    pbs_level: DecompositionLevelCount(4),
    ks_level: DecompositionLevelCount(9),
    ks_base_log: DecompositionBaseLog(1),
    pfks_level: DecompositionLevelCount(4),
    pfks_base_log: DecompositionBaseLog(9),
    pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.00000000000000022148688116005568513645324585951,
    )),
    cbs_level: DecompositionLevelCount(4),
    cbs_base_log: DecompositionBaseLog(6),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_MESSAGE_2_CARRY_2_KS_PBS_16_BITS: WopbsParameters = WopbsParameters {
    lwe_dimension: LweDimension(493),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.00049144710341316649172,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.00000000000000022148688116005568513645324585951,
    )),
    pbs_base_log: DecompositionBaseLog(16),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(5),
    ks_base_log: DecompositionBaseLog(2),
    pfks_level: DecompositionLevelCount(2),
    pfks_base_log: DecompositionBaseLog(16),
    pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.00000000000000022148688116005568513645324585951,
    )),
    cbs_level: DecompositionLevelCount(6),
    cbs_base_log: DecompositionBaseLog(3),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_MESSAGE_4_CARRY_4_KS_PBS_32_BITS: WopbsParameters = WopbsParameters {
    lwe_dimension: LweDimension(481),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.00061200133780220371345,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.00000000000000022148688116005568513645324585951,
    )),
    pbs_base_log: DecompositionBaseLog(9),
    pbs_level: DecompositionLevelCount(4),
    ks_level: DecompositionLevelCount(9),
    ks_base_log: DecompositionBaseLog(1),
    pfks_level: DecompositionLevelCount(4),
    pfks_base_log: DecompositionBaseLog(9),
    pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.00000000000000022148688116005568513645324585951,
    )),
    cbs_level: DecompositionLevelCount(4),
    cbs_base_log: DecompositionBaseLog(6),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_MESSAGE_2_CARRY_2_KS_PBS_32_BITS: WopbsParameters = WopbsParameters {
    lwe_dimension: LweDimension(481),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.00061200133780220371345,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.00000000000000022148688116005568513645324585951,
    )),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_level: DecompositionLevelCount(9),
    ks_base_log: DecompositionBaseLog(1),
    pfks_level: DecompositionLevelCount(3),
    pfks_base_log: DecompositionBaseLog(11),
    pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.00000000000000022148688116005568513645324585951,
    )),
    cbs_level: DecompositionLevelCount(6),
    cbs_base_log: DecompositionBaseLog(3),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_MESSAGE_1_CARRY_1_KS_PBS_32_BITS: WopbsParameters = WopbsParameters {
    lwe_dimension: LweDimension(493),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.00049144710341316649172,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.00000000000000022148688116005568513645324585951,
    )),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(5),
    ks_base_log: DecompositionBaseLog(2),
    pfks_level: DecompositionLevelCount(2),
    pfks_base_log: DecompositionBaseLog(15),
    pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.00000000000000022148688116005568513645324585951,
    )),
    cbs_level: DecompositionLevelCount(5),
    cbs_base_log: DecompositionBaseLog(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

#[derive(Copy, Clone)]
pub struct RadixCiphertextConformanceParams {
    pub shortint_params: CiphertextConformanceParams,
    pub num_blocks_per_integer: usize,
}

/// Structure to store the expected properties of a ciphertext
/// Can be used on a server to check if client inputs are well formed
/// before running a computation on them
impl RadixCiphertextConformanceParams {
    pub fn from_pbs_parameters<P: Into<PBSParameters>>(
        params: P,
        num_blocks_per_integer: usize,
    ) -> Self {
        let params: PBSParameters = params.into();
        Self {
            shortint_params: params.to_shortint_conformance_param(),
            num_blocks_per_integer,
        }
    }
}

/// Structure to store the expected properties of a ciphertext list
/// Can be used on a server to check if client inputs are well formed
/// before running a computation on them
#[derive(Copy, Clone)]
pub struct CompactCiphertextListConformanceParams {
    pub encryption_lwe_dimension: LweDimension,
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
    pub ciphertext_modulus: CiphertextModulus,
    pub expansion_kind: CompactCiphertextListExpansionKind,
    pub num_elements_constraint: ListSizeConstraint,
    pub allow_unpacked: bool,
}

impl CompactCiphertextListConformanceParams {
    pub fn from_parameters_and_size_constraint(
        value: CompactPublicKeyEncryptionParameters,
        num_elements_constraint: ListSizeConstraint,
    ) -> Self {
        Self {
            encryption_lwe_dimension: value.encryption_lwe_dimension,
            message_modulus: value.message_modulus,
            carry_modulus: value.carry_modulus,
            ciphertext_modulus: value.ciphertext_modulus,
            expansion_kind: value.expansion_kind,
            num_elements_constraint,
            allow_unpacked: false,
        }
    }

    /// Allow the list to be composed of unpacked ciphertexts.
    ///
    /// Note that this means that the ciphertexts won't be sanitized.
    pub fn allow_unpacked(self) -> Self {
        Self {
            allow_unpacked: true,
            ..self
        }
    }
}
