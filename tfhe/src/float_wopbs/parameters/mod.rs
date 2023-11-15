#![allow(clippy::excessive_precision)]
pub use crate::shortint::parameters::{EncryptionKeyChoice, WopbsParameters};
use crate::shortint::CiphertextModulus;

use crate::shortint::parameters::{CarryModulus, MessageModulus};
pub use crate::shortint::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, DispersionParameter, GlweDimension,
    LweDimension, PolynomialSize, StandardDev,
};

pub const ALL_PARAMETER_VEC_INTEGER_16_BITS: [WopbsParameters; 4] = [
    PARAM_MESSAGE_8_16_BITS,
    PARAM_MESSAGE_4_16_BITS,
    PARAM_MESSAGE_2_16_BITS,
    PARAM_TEST_WOP,
];

//TODO toy parameters
// /!\ unsecure
pub const PARAM_TEST_WOP: WopbsParameters = WopbsParameters {
    lwe_dimension: LweDimension(10),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(1024),
    lwe_modular_std_dev: StandardDev(0.0000000000000000000004168323308734758),
    glwe_modular_std_dev: StandardDev(0.00000000000000000000000000000000000004905643852600863),
    pbs_base_log: DecompositionBaseLog(7),
    pbs_level: DecompositionLevelCount(6),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(14),
    pfks_level: DecompositionLevelCount(6),
    pfks_base_log: DecompositionBaseLog(7),
    pfks_modular_std_dev: StandardDev(0.000000000000000000000000000000000000004905643852600863),
    cbs_level: DecompositionLevelCount(7),
    cbs_base_log: DecompositionBaseLog(4),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(1),
    encryption_key_choice: EncryptionKeyChoice::Big,
    ciphertext_modulus: CiphertextModulus::new_native(),
};


pub const PARAM_MESSAGE_2_4_8_BITS_BIV: WopbsParameters = WopbsParameters {
    lwe_dimension: LweDimension(592),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_modular_std_dev: StandardDev(0.00014316832876365714),
    glwe_modular_std_dev: StandardDev(0.0000000000000003162026630747649),
    pbs_base_log: DecompositionBaseLog(9),
    pbs_level: DecompositionLevelCount(4),
    ks_base_log: DecompositionBaseLog(2),
    ks_level: DecompositionLevelCount(5),
    pfks_level: DecompositionLevelCount(2),
    pfks_base_log: DecompositionBaseLog(17),
    pfks_modular_std_dev: StandardDev(0.0000000000000003162026630747649),
    cbs_level: DecompositionLevelCount(1),
    cbs_base_log: DecompositionBaseLog(14),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(1),
    encryption_key_choice: EncryptionKeyChoice::Big,
    ciphertext_modulus: CiphertextModulus::new_native(),
};

pub const PARAM_MESSAGE_4_2_8_BITS_BIV: WopbsParameters = WopbsParameters {
    lwe_dimension: LweDimension(564),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_modular_std_dev: StandardDev(0.00024077946887044908),
    glwe_modular_std_dev: StandardDev(0.0000000000000003162026630747649),
    pbs_base_log: DecompositionBaseLog(12),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(2),
    ks_level: DecompositionLevelCount(5),
    pfks_level: DecompositionLevelCount(2),
    pfks_base_log: DecompositionBaseLog(17),
    pfks_modular_std_dev: StandardDev(0.0000000000000003162026630747649),
    cbs_level: DecompositionLevelCount(1),
    cbs_base_log: DecompositionBaseLog(13),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(1),
    encryption_key_choice: EncryptionKeyChoice::Big,
    ciphertext_modulus: CiphertextModulus::new_native(),
};


pub const PARAM_MESSAGE_5_2_8_BITS_BIV: WopbsParameters = WopbsParameters {
    lwe_dimension: LweDimension(635),
    glwe_dimension: GlweDimension(4),
    polynomial_size: PolynomialSize(512),
    lwe_modular_std_dev: StandardDev(-13.91),
    glwe_modular_std_dev: StandardDev(-51.49),
    pbs_base_log: DecompositionBaseLog(8),
    pbs_level: DecompositionLevelCount(5),
    ks_base_log: DecompositionBaseLog(2),
    ks_level: DecompositionLevelCount(6),
    pfks_level: DecompositionLevelCount(2),
    pfks_base_log: DecompositionBaseLog(17),
    pfks_modular_std_dev: StandardDev(-51.49),
    cbs_level: DecompositionLevelCount(1),
    cbs_base_log: DecompositionBaseLog(14),
    message_modulus: MessageModulus(32),
    carry_modulus: CarryModulus(1),
    encryption_key_choice: EncryptionKeyChoice::Big,
    ciphertext_modulus: CiphertextModulus::new_native(),
};


pub const PARAM_MESSAGE_2_4_8_BITS_TRI: WopbsParameters = WopbsParameters {
    lwe_dimension: LweDimension(589),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_modular_std_dev: StandardDev(0.00015133150634020836),
    glwe_modular_std_dev: StandardDev(0.0000000000000003162026630747649),
    pbs_base_log: DecompositionBaseLog(8),
    pbs_level: DecompositionLevelCount(5),
    ks_base_log: DecompositionBaseLog(2),
    ks_level: DecompositionLevelCount(5),
    pfks_level: DecompositionLevelCount(2),
    pfks_base_log: DecompositionBaseLog(17),
    pfks_modular_std_dev: StandardDev(0.0000000000000003162026630747649),
    cbs_level: DecompositionLevelCount(1),
    cbs_base_log: DecompositionBaseLog(14),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(1),
    encryption_key_choice: EncryptionKeyChoice::Big,
    ciphertext_modulus: CiphertextModulus::new_native(),
};


pub const PARAM_MESSAGE_4_2_8_BITS_TRI: WopbsParameters = WopbsParameters {
    lwe_dimension: LweDimension(573),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_modular_std_dev: StandardDev(0.00020387888657919176),
    glwe_modular_std_dev: StandardDev(0.0000000000000003162026630747649),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(2),
    ks_level: DecompositionLevelCount(5),
    pfks_level: DecompositionLevelCount(2),
    pfks_base_log: DecompositionBaseLog(17),
    pfks_modular_std_dev: StandardDev(0.0000000000000003162026630747649),
    cbs_level: DecompositionLevelCount(1),
    cbs_base_log: DecompositionBaseLog(12),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(1),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};


pub const PARAM_MESSAGE_2_16_BITS: WopbsParameters = WopbsParameters {
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
    carry_modulus: CarryModulus(1),
    encryption_key_choice: EncryptionKeyChoice::Big,
    ciphertext_modulus: CiphertextModulus::new_native(),
};


pub const PARAM_MESSAGE_8_16_BITS: WopbsParameters = WopbsParameters {
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
    message_modulus: MessageModulus(256),
    carry_modulus: CarryModulus(1),
    encryption_key_choice: EncryptionKeyChoice::Big,
    ciphertext_modulus: CiphertextModulus::new_native(),
};

pub const PARAM_MESSAGE_4_16_BITS: WopbsParameters = WopbsParameters {
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
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(1),
    encryption_key_choice: EncryptionKeyChoice::Big,
    ciphertext_modulus: CiphertextModulus::new_native(),
};
