// p-fail = 2^-56.089, algorithmic cost ~ 57, 2-norm = 3
pub const PARAM_MESSAGE_1_CARRY_1_COMPACT_PK_PBS_KS_TUNIFORM_2M40: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1024),
        glwe_dimension: GlweDimension(3),
        polynomial_size: PolynomialSize(512),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(41),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(27),
        pbs_base_log: DecompositionBaseLog(18),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(8),
        ks_level: DecompositionLevelCount(2),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(2),
        max_noise_level: MaxNoiseLevel::new(3),
        log2_p_fail: -56.089,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Small,
    };
// p-fail = 2^-55.72, algorithmic cost ~ 122, 2-norm = 5
pub const PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_PBS_KS_TUNIFORM_2M40: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1024),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(2048),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(41),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(14),
        pbs_base_log: DecompositionBaseLog(21),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(6),
        ks_level: DecompositionLevelCount(3),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(4),
        max_noise_level: MaxNoiseLevel::new(5),
        log2_p_fail: -55.72,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Small,
    };
// p-fail = 2^-41.82, algorithmic cost ~ 1108, 2-norm = 9
pub const PARAM_MESSAGE_3_CARRY_3_COMPACT_PK_PBS_KS_TUNIFORM_2M40: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1024),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(8192),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(41),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
        pbs_base_log: DecompositionBaseLog(19),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(1),
        ks_level: DecompositionLevelCount(20),
        message_modulus: MessageModulus(8),
        carry_modulus: CarryModulus(8),
        max_noise_level: MaxNoiseLevel::new(9),
        log2_p_fail: -41.82,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Small,
    };
// p-fail = 2^-82.73, algorithmic cost ~ 20133, 2-norm = 17
pub const PARAM_MESSAGE_4_CARRY_4_COMPACT_PK_PBS_KS_TUNIFORM_2M40: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(2048),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(65536),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(14),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
        pbs_base_log: DecompositionBaseLog(10),
        pbs_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(26),
        ks_level: DecompositionLevelCount(1),
        message_modulus: MessageModulus(16),
        carry_modulus: CarryModulus(16),
        max_noise_level: MaxNoiseLevel::new(17),
        log2_p_fail: -82.73,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Small,
    };
use crate::core_crypto::prelude::*;
use crate::shortint::ciphertext::MaxNoiseLevel;
use crate::shortint::parameters::{CarryModulus, ClassicPBSParameters, MessageModulus};
