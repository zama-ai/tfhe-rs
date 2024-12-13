//! #Warning test-only
//!
//! This module provides the structure containing the cryptographic parameters only intended to be
//! used to speed up test coverage operations.
//! These parameters are *NOT safe*.
use crate::core_crypto::prelude::LweBskGroupingFactor;
use crate::shortint::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, DynamicDistribution, GlweDimension,
    LweDimension, PolynomialSize, StandardDev,
};
use crate::shortint::{
    CarryModulus, CiphertextModulus, ClassicPBSParameters, EncryptionKeyChoice, MaxNoiseLevel,
    MessageModulus, MultiBitPBSParameters,
};

pub const COVERAGE_PARAM_MESSAGE_2_CARRY_2_KS_PBS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(256),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.000007069849454709433,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.00000000000000029403601535432533,
    )),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(5),
    ks_base_log: DecompositionBaseLog(3),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(5),
    log2_p_fail: -40.,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const COVERAGE_PARAM_MESSAGE_2_CARRY_3_KS_PBS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(256),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.0000008775214009854235,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.0000000000000000002168404344971009,
    )),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(6),
    ks_base_log: DecompositionBaseLog(3),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(10),
    log2_p_fail: -40.,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const COVERAGE_PARAM_MESSAGE_5_CARRY_1_KS_PBS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(256),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.0000006197725091905067,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.0000000000000000002168404344971009,
    )),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(6),
    ks_base_log: DecompositionBaseLog(3),
    message_modulus: MessageModulus(32),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(2),
    log2_p_fail: -40.,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const COVERAGE_PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(2),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(256),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            0.000002226459789930014,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            0.0000000000000003152931493498455,
        )),
        pbs_base_log: DecompositionBaseLog(22),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(5),
        ks_level: DecompositionLevelCount(3),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(4),
        max_noise_level: MaxNoiseLevel::new(5),
        log2_p_fail: -40.,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(2),
        deterministic_execution: false,
    };

pub const COVERAGE_PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_PBS_KS_GAUSSIAN_2M64: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(256),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            4.99029381172945e-8,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.15283466779972e-16,
        )),
        pbs_base_log: DecompositionBaseLog(21),
        pbs_level: DecompositionLevelCount(1),
        ks_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(8),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(4),
        max_noise_level: MaxNoiseLevel::new(5),
        log2_p_fail: -40.,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Small,
    };

pub const COVERAGE_PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS_GAUSSIAN_2M64: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(256),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            6.983104533665408e-06,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.152834667799722e-16,
        )),
        pbs_base_log: DecompositionBaseLog(22),
        pbs_level: DecompositionLevelCount(1),
        ks_level: DecompositionLevelCount(5),
        ks_base_log: DecompositionBaseLog(3),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(4),
        max_noise_level: MaxNoiseLevel::new(5),
        log2_p_fail: -40.,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
