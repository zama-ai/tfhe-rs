use crate::core_crypto::prelude::*;
use crate::shortint::ciphertext::MaxNoiseLevel;
use crate::shortint::parameters::{CarryModulus, ClassicPBSParameters, MessageModulus};

// p-fail = 2^-80.139, algorithmic cost ~ 67, 2-norm = 3
pub const V1_0_PARAM_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(839),
        glwe_dimension: GlweDimension(4),
        polynomial_size: PolynomialSize(512),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(47),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(17),
        pbs_base_log: DecompositionBaseLog(23),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(4),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(2),
        max_noise_level: MaxNoiseLevel::new(3),
        log2_p_fail: -80.139,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-80.702, algorithmic cost ~ 202, 2-norm = 5
pub const V1_0_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(879),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(2048),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(46),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(17),
        pbs_base_log: DecompositionBaseLog(15),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(1),
        ks_level: DecompositionLevelCount(16),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(4),
        max_noise_level: MaxNoiseLevel::new(5),
        log2_p_fail: -80.702,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-126.582, algorithmic cost ~ 1799, 2-norm = 9
pub const V1_0_PARAM_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(998),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(16384),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(43),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(4),
        pbs_base_log: DecompositionBaseLog(15),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(6),
        message_modulus: MessageModulus(8),
        carry_modulus: CarryModulus(8),
        max_noise_level: MaxNoiseLevel::new(9),
        log2_p_fail: -126.582,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
