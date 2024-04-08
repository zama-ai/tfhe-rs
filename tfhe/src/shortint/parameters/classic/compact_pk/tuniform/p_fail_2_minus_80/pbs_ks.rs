// p-fail = 2^-192.263, algorithmic cost ~ 87, 2-norm = 3
pub const PARAM_MESSAGE_1_CARRY_1_COMPACT_PK_PBS_KS_TUNIFORM_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1024),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(1024),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(41),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(14),
        pbs_base_log: DecompositionBaseLog(19),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(7),
        ks_level: DecompositionLevelCount(2),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(2),
        max_noise_level: MaxNoiseLevel::new(3),
        log2_p_fail: -192.263,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Small,
    };
// p-fail = 2^-94.996, algorithmic cost ~ 260, 2-norm = 5
pub const PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_PBS_KS_TUNIFORM_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1024),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(4096),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(41),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
        pbs_base_log: DecompositionBaseLog(22),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(6),
        ks_level: DecompositionLevelCount(3),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(4),
        max_noise_level: MaxNoiseLevel::new(5),
        log2_p_fail: -94.996,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Small,
    };
// p-fail = 2^-88.256, algorithmic cost ~ 3355, 2-norm = 9
pub const PARAM_MESSAGE_3_CARRY_3_COMPACT_PK_PBS_KS_TUNIFORM_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(2048),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(16384),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(14),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
        pbs_base_log: DecompositionBaseLog(15),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(20),
        ks_level: DecompositionLevelCount(1),
        message_modulus: MessageModulus(8),
        carry_modulus: CarryModulus(8),
        max_noise_level: MaxNoiseLevel::new(9),
        log2_p_fail: -88.256,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Small,
    };
// p-fail = 2^-84.739, algorithmic cost ~ 20133, 2-norm = 17
pub const PARAM_MESSAGE_4_CARRY_4_COMPACT_PK_PBS_KS_TUNIFORM_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(2048),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(65536),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(14),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
        pbs_base_log: DecompositionBaseLog(13),
        pbs_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(25),
        ks_level: DecompositionLevelCount(1),
        message_modulus: MessageModulus(16),
        carry_modulus: CarryModulus(16),
        max_noise_level: MaxNoiseLevel::new(17),
        log2_p_fail: -84.739,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Small,
    };
use crate::core_crypto::prelude::*;
use crate::shortint::ciphertext::MaxNoiseLevel;
use crate::shortint::parameters::{CarryModulus, ClassicPBSParameters, MessageModulus};
