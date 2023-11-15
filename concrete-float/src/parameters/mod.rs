use tfhe::shortint;
use shortint::prelude::{
    DecompositionBaseLog, DecompositionLevelCount, EncryptionKeyChoice, GlweDimension,
    LweDimension, PolynomialSize, StandardDev,
};

use tfhe::shortint::{
    CarryModulus, CiphertextModulus, ClassicPBSParameters, MessageModulus, WopbsParameters,
};


pub const FINAL_PARAM_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(728),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_modular_std_dev: StandardDev(0.000011702161815931298),
    glwe_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    pbs_base_log: DecompositionBaseLog(12),
    pbs_level: DecompositionLevelCount(3),
    ks_level: DecompositionLevelCount(14),
    ks_base_log: DecompositionBaseLog(1),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const FINAL_WOP_PARAM_64: WopbsParameters = WopbsParameters {
    lwe_dimension: LweDimension(728),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_modular_std_dev: StandardDev(0.000011702161815931298),
    glwe_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    pbs_base_log: DecompositionBaseLog(12),
    pbs_level: DecompositionLevelCount(3),
    ks_level: DecompositionLevelCount(14),
    ks_base_log: DecompositionBaseLog(1),
    pfks_level: DecompositionLevelCount(4),
    pfks_base_log: DecompositionBaseLog(8),
    pfks_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    cbs_level: DecompositionLevelCount(4),
    cbs_base_log: DecompositionBaseLog(8),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};


pub const FINAL_PARAM_32: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(720),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_modular_std_dev: StandardDev(0.000013562007726094114),
    glwe_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    pbs_base_log: DecompositionBaseLog(12),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(14),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const FINAL_WOP_PARAM_32: WopbsParameters = WopbsParameters {
    lwe_dimension: LweDimension(720),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_modular_std_dev: StandardDev(0.000013562007726094114),
    glwe_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    pbs_base_log: DecompositionBaseLog(12),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(14),
    pfks_level: DecompositionLevelCount(4),
    pfks_base_log: DecompositionBaseLog(8),
    pfks_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    cbs_level: DecompositionLevelCount(4),
    cbs_base_log: DecompositionBaseLog(8),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};


pub const FINAL_PARAM_16: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(720),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_modular_std_dev: StandardDev(0.000013562007726094114),
    glwe_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(15),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const FINAL_WOP_PARAM_16: WopbsParameters = WopbsParameters {
    lwe_dimension: LweDimension(720),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_modular_std_dev: StandardDev(0.000013562007726094114),
    glwe_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(15),
    pfks_level: DecompositionLevelCount(3),
    pfks_base_log: DecompositionBaseLog(9),
    pfks_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    cbs_level: DecompositionLevelCount(3),
    cbs_base_log: DecompositionBaseLog(9),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};


pub const FINAL_PARAM_15: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(720),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_modular_std_dev: StandardDev(0.000013562007726094114),
    glwe_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(14),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const FINAL_WOP_PARAM_15: WopbsParameters = WopbsParameters {
    lwe_dimension: LweDimension(720),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_modular_std_dev: StandardDev(0.000013562007726094114),
    glwe_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(14),
    pfks_level: DecompositionLevelCount(3),
    pfks_base_log: DecompositionBaseLog(9),
    pfks_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    cbs_level: DecompositionLevelCount(3),
    cbs_base_log: DecompositionBaseLog(9),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};


pub const FINAL_PARAM_8: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(740),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_modular_std_dev: StandardDev(0.000009379490908496443),
    glwe_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    pbs_base_log: DecompositionBaseLog(12),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(14),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const FINAL_WOP_PARAM_8: WopbsParameters = WopbsParameters {
    lwe_dimension: LweDimension(740),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_modular_std_dev: StandardDev(0.000009379490908496443),
    glwe_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    pbs_base_log: DecompositionBaseLog(12),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(14),
    pfks_level: DecompositionLevelCount(3),
    pfks_base_log: DecompositionBaseLog(9),
    pfks_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    cbs_level: DecompositionLevelCount(3),
    cbs_base_log: DecompositionBaseLog(9),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};



pub const FINAL_PARAM_64_BIS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(736),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_modular_std_dev: StandardDev(0.000010097368614733835),
    glwe_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    pbs_base_log: DecompositionBaseLog(12),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(14),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const FINAL_WOP_PARAM_64_BIS: WopbsParameters = WopbsParameters {
    lwe_dimension: LweDimension(736),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_modular_std_dev: StandardDev(0.000010097368614733835),
    glwe_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    pbs_base_log: DecompositionBaseLog(12),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(14),
    pfks_level: DecompositionLevelCount(2),
    pfks_base_log: DecompositionBaseLog(17),
    pfks_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    cbs_level: DecompositionLevelCount(2),
    cbs_base_log: DecompositionBaseLog(8),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};


pub const FINAL_PARAM_32_BIS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(720),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_modular_std_dev: StandardDev(0.000013562007726094114),
    glwe_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    pbs_base_log: DecompositionBaseLog(12),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(15),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const FINAL_WOP_PARAM_32_BIS: WopbsParameters = WopbsParameters {
    lwe_dimension: LweDimension(720),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_modular_std_dev: StandardDev(0.000013562007726094114),
    glwe_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    pbs_base_log: DecompositionBaseLog(12),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(15),
    pfks_level: DecompositionLevelCount(2),
    pfks_base_log: DecompositionBaseLog(17),
    pfks_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    cbs_level: DecompositionLevelCount(2),
    cbs_base_log: DecompositionBaseLog(8),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};


pub const FINAL_PARAM_16_BIS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(728),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_modular_std_dev: StandardDev(0.000011702161815931298),
    glwe_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(14),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const FINAL_WOP_PARAM_16_BIS: WopbsParameters = WopbsParameters {
    lwe_dimension: LweDimension(728),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_modular_std_dev: StandardDev(0.000011702161815931298),
    glwe_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(14),
    pfks_level: DecompositionLevelCount(2),
    pfks_base_log: DecompositionBaseLog(17),
    pfks_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    cbs_level: DecompositionLevelCount(3),
    cbs_base_log: DecompositionBaseLog(6),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};


pub const FINAL_PARAM_15_BIS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(720),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_modular_std_dev: StandardDev(0.000013562007726094114),
    glwe_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(14),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const FINAL_WOP_PARAM_15_BIS: WopbsParameters = WopbsParameters {
    lwe_dimension: LweDimension(720),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_modular_std_dev: StandardDev(0.000013562007726094114),
    glwe_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(14),
    pfks_level: DecompositionLevelCount(2),
    pfks_base_log: DecompositionBaseLog(17),
    pfks_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    cbs_level: DecompositionLevelCount(3),
    cbs_base_log: DecompositionBaseLog(6),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};


pub const FINAL_PARAM_8_BIS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(720),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_modular_std_dev: StandardDev(0.000013562007726094114),
    glwe_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(14),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const FINAL_WOP_PARAM_8_BIS: WopbsParameters = WopbsParameters {
    lwe_dimension: LweDimension(720),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_modular_std_dev: StandardDev(0.000013562007726094114),
    glwe_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(14),
    pfks_level: DecompositionLevelCount(2),
    pfks_base_log: DecompositionBaseLog(13),
    pfks_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    cbs_level: DecompositionLevelCount(3),
    cbs_base_log: DecompositionBaseLog(6),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};



/// //////////////////////////////////
//////////////////////////////////////
///          P_ERROR = 1/2         ///
//////////////////////////////////////
/// //////////////////////////////////


pub const FINAL_PARAM_8_ERROR: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(668),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_modular_std_dev: StandardDev(0.00003537531055908156),
    glwe_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(13),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const FINAL_WOP_PARAM_8_ERROR: WopbsParameters = WopbsParameters {
    lwe_dimension: LweDimension(668),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_modular_std_dev: StandardDev(0.00003537531055908156),
    glwe_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(13),
    pfks_level: DecompositionLevelCount(3),
    pfks_base_log: DecompositionBaseLog(9),
    pfks_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    cbs_level: DecompositionLevelCount(3),
    cbs_base_log: DecompositionBaseLog(9),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const FINAL_PARAM_15_ERROR: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(644),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_modular_std_dev: StandardDev(0.000055064782230694654),
    glwe_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(12),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const FINAL_WOP_PARAM_15_ERROR: WopbsParameters = WopbsParameters {
    lwe_dimension: LweDimension(644),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_modular_std_dev: StandardDev(0.000055064782230694654),
    glwe_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(12),
    pfks_level: DecompositionLevelCount(3),
    pfks_base_log: DecompositionBaseLog(9),
    pfks_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    cbs_level: DecompositionLevelCount(3),
    cbs_base_log: DecompositionBaseLog(9),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};


pub const FINAL_PARAM_16_ERROR: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(648),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_modular_std_dev: StandardDev(0.00005114992271922248),
    glwe_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(12),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const FINAL_WOP_PARAM_16_ERROR: WopbsParameters = WopbsParameters {
    lwe_dimension: LweDimension(648),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_modular_std_dev: StandardDev(0.00005114992271922248),
    glwe_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(12),
    pfks_level: DecompositionLevelCount(3),
    pfks_base_log: DecompositionBaseLog(9),
    pfks_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    cbs_level: DecompositionLevelCount(3),
    cbs_base_log: DecompositionBaseLog(9),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const FINAL_PARAM_32_ERROR: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(656),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_modular_std_dev: StandardDev(0.00004413540270892545),
    glwe_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(13),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const FINAL_WOP_PARAM_32_ERROR: WopbsParameters = WopbsParameters {
    lwe_dimension: LweDimension(656),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_modular_std_dev: StandardDev(0.00004413540270892545),
    glwe_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(13),
    pfks_level: DecompositionLevelCount(3),
    pfks_base_log: DecompositionBaseLog(9),
    pfks_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    cbs_level: DecompositionLevelCount(3),
    cbs_base_log: DecompositionBaseLog(9),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};


pub const FINAL_PARAM_64_ERROR: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(676),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_modular_std_dev: StandardDev(0.000030524065227797875),
    glwe_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    pbs_base_log: DecompositionBaseLog(12),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(13),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const FINAL_WOP_PARAM_64_ERROR: WopbsParameters = WopbsParameters {
    lwe_dimension: LweDimension(676),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_modular_std_dev: StandardDev(0.000030524065227797875),
    glwe_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    pbs_base_log: DecompositionBaseLog(12),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(13),
    pfks_level: DecompositionLevelCount(3),
    pfks_base_log: DecompositionBaseLog(9),
    pfks_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    cbs_level: DecompositionLevelCount(3),
    cbs_base_log: DecompositionBaseLog(9),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};


/// //////////////////////////////////
//////////////////////////////////////
///          P_ERROR = 1/2  BIS    ///
//////////////////////////////////////
/// //////////////////////////////////


pub const FINAL_PARAM_8_ERROR_BIS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(644),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_modular_std_dev: StandardDev(0.000055064782230694654),
    glwe_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(13),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const FINAL_WOP_PARAM_8_ERROR_BIS: WopbsParameters = WopbsParameters {
    lwe_dimension: LweDimension(644),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_modular_std_dev: StandardDev(0.000055064782230694654),
    glwe_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(13),
    pfks_level: DecompositionLevelCount(2),
    pfks_base_log: DecompositionBaseLog(13),
    pfks_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    cbs_level: DecompositionLevelCount(2),
    cbs_base_log: DecompositionBaseLog(8),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};


pub const FINAL_PARAM_15_ERROR_BIS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(648),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_modular_std_dev: StandardDev(0.00005114992271922248),
    glwe_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(13),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const FINAL_WOP_PARAM_15_ERROR_BIS: WopbsParameters = WopbsParameters {
    lwe_dimension: LweDimension(648),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_modular_std_dev: StandardDev(0.00005114992271922248),
    glwe_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(13),
    pfks_level: DecompositionLevelCount(2),
    pfks_base_log: DecompositionBaseLog(13),
    pfks_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    cbs_level: DecompositionLevelCount(2),
    cbs_base_log: DecompositionBaseLog(8),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};


pub const FINAL_PARAM_16_ERROR_BIS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(656),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_modular_std_dev: StandardDev(0.00004413540270892545),
    glwe_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(12),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const FINAL_WOP_PARAM_16_ERROR_BIS: WopbsParameters = WopbsParameters {
    lwe_dimension: LweDimension(656),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_modular_std_dev: StandardDev(0.00004413540270892545),
    glwe_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(12),
    pfks_level: DecompositionLevelCount(2),
    pfks_base_log: DecompositionBaseLog(17),
    pfks_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    cbs_level: DecompositionLevelCount(2),
    cbs_base_log: DecompositionBaseLog(8),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const FINAL_PARAM_32_ERROR_BIS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(700),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_modular_std_dev: StandardDev(0.0000196095987892077),
    glwe_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(14),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const FINAL_WOP_PARAM_32_ERROR_BIS: WopbsParameters = WopbsParameters {
    lwe_dimension: LweDimension(700),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_modular_std_dev: StandardDev(0.0000196095987892077),
    glwe_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(14),
    pfks_level: DecompositionLevelCount(2),
    pfks_base_log: DecompositionBaseLog(17),
    pfks_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    cbs_level: DecompositionLevelCount(2),
    cbs_base_log: DecompositionBaseLog(8),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};


pub const FINAL_PARAM_64_ERROR_BIS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(660),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_modular_std_dev: StandardDev(0.000040997573154568715),
    glwe_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(13),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const FINAL_WOP_PARAM_64_ERROR_BIS: WopbsParameters = WopbsParameters {
    lwe_dimension: LweDimension(660),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_modular_std_dev: StandardDev(0.000040997573154568715),
    glwe_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(13),
    pfks_level: DecompositionLevelCount(2),
    pfks_base_log: DecompositionBaseLog(17),
    pfks_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    cbs_level: DecompositionLevelCount(3),
    cbs_base_log: DecompositionBaseLog(6),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

//TODO toy parameters
// /!\ unsecure
pub const WOP_PARAM_TEST: WopbsParameters = WopbsParameters {
    lwe_dimension: LweDimension(10),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_modular_std_dev: StandardDev(
        0.000000000000000000000000000000000000002886954936071319246944,
    ),
    glwe_modular_std_dev: StandardDev(
        0.0000000000000000000000000000000000000022148688116005568513645324585951,
    ),
    pbs_base_log: DecompositionBaseLog(7),
    pbs_level: DecompositionLevelCount(6),
    ks_level: DecompositionLevelCount(14),
    ks_base_log: DecompositionBaseLog(1),
    pfks_level: DecompositionLevelCount(3),
    pfks_base_log: DecompositionBaseLog(10),
    pfks_modular_std_dev: StandardDev(
        0.00000000000000000000000000000000000000022148688116005568513645324585951,
    ),
    cbs_level: DecompositionLevelCount(3),
    cbs_base_log: DecompositionBaseLog(10),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_TEST: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(10),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_modular_std_dev: StandardDev(
        0.000000000000000000000000000000000000002886954936071319246944,
    ),
    glwe_modular_std_dev: StandardDev(
        0.0000000000000000000000000000000000000022148688116005568513645324585951,
    ),
    pbs_base_log: DecompositionBaseLog(7),
    pbs_level: DecompositionLevelCount(6),
    ks_level: DecompositionLevelCount(14),
    ks_base_log: DecompositionBaseLog(1),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};



pub const FINAL_PARAM_2_2_32: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(728),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_modular_std_dev: StandardDev(0.000011702161815931298),
    glwe_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    pbs_base_log: DecompositionBaseLog(12),
    pbs_level: DecompositionLevelCount(3),
    ks_level: DecompositionLevelCount(14),
    ks_base_log: DecompositionBaseLog(1),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const FINAL_WOP_PARAM_2_2_32: WopbsParameters = WopbsParameters {
    lwe_dimension: LweDimension(728),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_modular_std_dev: StandardDev(0.000011702161815931298),
    glwe_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    pbs_base_log: DecompositionBaseLog(12),
    pbs_level: DecompositionLevelCount(3),
    ks_level: DecompositionLevelCount(14),
    ks_base_log: DecompositionBaseLog(1),
    pfks_level: DecompositionLevelCount(4),
    pfks_base_log: DecompositionBaseLog(8),
    pfks_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    cbs_level: DecompositionLevelCount(4),
    cbs_base_log: DecompositionBaseLog(8),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

//pub const PARAM_MESSAGE_3_CARRY_2: Parameters = Parameters {
pub const PARAM_MESSAGE_2_CARRY_2_32: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(774),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_modular_std_dev: StandardDev(0.000004998754134591537),
    glwe_modular_std_dev: StandardDev(0.0000000000000003162026630747649),
    pbs_base_log: DecompositionBaseLog(7),
    pbs_level: DecompositionLevelCount(6),
    ks_level: DecompositionLevelCount(14),
    ks_base_log: DecompositionBaseLog(1),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const WOP_PARAM_MESSAGE_2_CARRY_2_32: WopbsParameters = WopbsParameters {
    lwe_dimension: LweDimension(774),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_modular_std_dev: StandardDev(0.000004998754134591537),
    glwe_modular_std_dev: StandardDev(0.0000000000000003162026630747649),
    pbs_base_log: DecompositionBaseLog(7),
    pbs_level: DecompositionLevelCount(6),
    ks_level: DecompositionLevelCount(14),
    ks_base_log: DecompositionBaseLog(1),
    pfks_level: DecompositionLevelCount(3),
    pfks_base_log: DecompositionBaseLog(10),
    pfks_modular_std_dev: StandardDev(0.0000000000000003162026630747649),
    cbs_level: DecompositionLevelCount(3),
    cbs_base_log: DecompositionBaseLog(10),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_SAM_32: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(728),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_modular_std_dev: StandardDev(0.000011702161815931298),
    glwe_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    pbs_base_log: DecompositionBaseLog(12),
    pbs_level: DecompositionLevelCount(3),
    ks_level: DecompositionLevelCount(14),
    ks_base_log: DecompositionBaseLog(1),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const WOP_PARAM_SAM_32: WopbsParameters = WopbsParameters {
    lwe_dimension: LweDimension(728),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_modular_std_dev: StandardDev(0.000011702161815931298),
    glwe_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    pbs_base_log: DecompositionBaseLog(12), //(22);
    pbs_level: DecompositionLevelCount(3), //(1);
    ks_level: DecompositionLevelCount(14),
    ks_base_log: DecompositionBaseLog(1),
    pfks_level: DecompositionLevelCount(4), //(2);
    pfks_base_log: DecompositionBaseLog(8),
    pfks_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    cbs_level: DecompositionLevelCount(4), //(2);
    cbs_base_log: DecompositionBaseLog(8),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};


pub const PARAM_MESSAGE_2_CARRY_2_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(774),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_modular_std_dev: StandardDev(0.000004998754134591537),
    glwe_modular_std_dev: StandardDev(0.0000000000000003162026630747649),
    pbs_base_log: DecompositionBaseLog(7),
    pbs_level: DecompositionLevelCount(6),
    ks_level: DecompositionLevelCount(14),
    ks_base_log: DecompositionBaseLog(1),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
pub const WOP_PARAM_MESSAGE_2_CARRY_2_64: WopbsParameters = WopbsParameters {
    lwe_dimension: LweDimension(774),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_modular_std_dev: StandardDev(0.000004998754134591537),
    glwe_modular_std_dev: StandardDev(0.0000000000000003162026630747649),
    pbs_base_log: DecompositionBaseLog(7),
    pbs_level: DecompositionLevelCount(6),
    ks_level: DecompositionLevelCount(14),
    ks_base_log: DecompositionBaseLog(1),
    pfks_level: DecompositionLevelCount(3),
    pfks_base_log: DecompositionBaseLog(10),
    pfks_modular_std_dev: StandardDev(0.0000000000000003162026630747649),
    cbs_level: DecompositionLevelCount(3),
    cbs_base_log: DecompositionBaseLog(10),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const FINAL_PARAM_64_TCHESS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(752),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_modular_std_dev: StandardDev(0.000007517828849606135),
    glwe_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(15),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const FINAL_WOP_PARAM_64_TCHESS: WopbsParameters = WopbsParameters {
    lwe_dimension: LweDimension(752),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_modular_std_dev: StandardDev(0.000007517828849606135),
    glwe_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(15),
    pfks_level: DecompositionLevelCount(2),
    pfks_base_log: DecompositionBaseLog(17),
    pfks_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    cbs_level: DecompositionLevelCount(2),
    cbs_base_log: DecompositionBaseLog(8),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};


pub const FINAL_PARAM_32_TCHESS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(728),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_modular_std_dev: StandardDev(0.000011702161815931298),
    glwe_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(15),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const FINAL_WOP_PARAM_32_TCHESS: WopbsParameters = WopbsParameters {
    lwe_dimension: LweDimension(728),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_modular_std_dev: StandardDev(0.000011702161815931298),
    glwe_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(15),
    pfks_level: DecompositionLevelCount(2),
    pfks_base_log: DecompositionBaseLog(17),
    pfks_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    cbs_level: DecompositionLevelCount(2),
    cbs_base_log: DecompositionBaseLog(8),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
