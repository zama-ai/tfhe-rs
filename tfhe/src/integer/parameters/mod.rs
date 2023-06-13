#![allow(clippy::excessive_precision)]
pub use crate::shortint::{CiphertextModulus, ClassicPBSParameters, WopbsParameters};

pub use crate::shortint::parameters::parameters_wopbs::PARAM_4_BITS_5_BLOCKS;
use crate::shortint::parameters::{CarryModulus, EncryptionKeyChoice, MessageModulus};
pub use crate::shortint::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, DispersionParameter, GlweDimension,
    LweDimension, PolynomialSize, StandardDev,
};

pub const ALL_PARAMETER_VEC_INTEGER_16_BITS: [WopbsParameters; 2] = [
    PARAM_MESSAGE_4_CARRY_4_KS_PBS_16_BITS,
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_16_BITS,
];

pub const PARAM_MESSAGE_4_CARRY_4_KS_PBS_16_BITS: WopbsParameters = WopbsParameters {
    lwe_dimension: LweDimension(481),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_modular_std_dev: StandardDev(0.00061200133780220371345),
    glwe_modular_std_dev: StandardDev(0.00000000000000022148688116005568513645324585951),
    pbs_base_log: DecompositionBaseLog(9),
    pbs_level: DecompositionLevelCount(4),
    ks_level: DecompositionLevelCount(9),
    ks_base_log: DecompositionBaseLog(1),
    pfks_level: DecompositionLevelCount(4),
    pfks_base_log: DecompositionBaseLog(9),
    pfks_modular_std_dev: StandardDev(0.00000000000000022148688116005568513645324585951),
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
    lwe_modular_std_dev: StandardDev(0.00049144710341316649172),
    glwe_modular_std_dev: StandardDev(0.00000000000000022148688116005568513645324585951),
    pbs_base_log: DecompositionBaseLog(16),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(5),
    ks_base_log: DecompositionBaseLog(2),
    pfks_level: DecompositionLevelCount(2),
    pfks_base_log: DecompositionBaseLog(16),
    pfks_modular_std_dev: StandardDev(0.00000000000000022148688116005568513645324585951),
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
    lwe_modular_std_dev: StandardDev(0.00061200133780220371345),
    glwe_modular_std_dev: StandardDev(0.00000000000000022148688116005568513645324585951),
    pbs_base_log: DecompositionBaseLog(9),
    pbs_level: DecompositionLevelCount(4),
    ks_level: DecompositionLevelCount(9),
    ks_base_log: DecompositionBaseLog(1),
    pfks_level: DecompositionLevelCount(4),
    pfks_base_log: DecompositionBaseLog(9),
    pfks_modular_std_dev: StandardDev(0.00000000000000022148688116005568513645324585951),
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
    lwe_modular_std_dev: StandardDev(0.00061200133780220371345),
    glwe_modular_std_dev: StandardDev(0.00000000000000022148688116005568513645324585951),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_level: DecompositionLevelCount(9),
    ks_base_log: DecompositionBaseLog(1),
    pfks_level: DecompositionLevelCount(3),
    pfks_base_log: DecompositionBaseLog(11),
    pfks_modular_std_dev: StandardDev(0.00000000000000022148688116005568513645324585951),
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
    lwe_modular_std_dev: StandardDev(0.00049144710341316649172),
    glwe_modular_std_dev: StandardDev(0.00000000000000022148688116005568513645324585951),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(5),
    ks_base_log: DecompositionBaseLog(2),
    pfks_level: DecompositionLevelCount(2),
    pfks_base_log: DecompositionBaseLog(15),
    pfks_modular_std_dev: StandardDev(0.00000000000000022148688116005568513645324585951),
    cbs_level: DecompositionLevelCount(5),
    cbs_base_log: DecompositionBaseLog(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
