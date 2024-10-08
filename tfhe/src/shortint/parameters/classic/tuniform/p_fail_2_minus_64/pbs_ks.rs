use crate::core_crypto::prelude::*;
use crate::shortint::ciphertext::MaxNoiseLevel;
use crate::shortint::parameters::{CarryModulus, ClassicPBSParameters, MessageModulus};

// security = 132 bits, p-fail = 2^-64.301, algorithmic cost ~ 78, 2-norm = 3
pub const PARAM_MESSAGE_1_CARRY_1_PBS_KS_TUNIFORM_2M64: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1024),
        glwe_dimension: GlweDimension(4),
        polynomial_size: PolynomialSize(512),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
        pbs_base_log: DecompositionBaseLog(25),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(7),
        ks_level: DecompositionLevelCount(3),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(2),
        max_noise_level: MaxNoiseLevel::new(3),
        log2_p_fail: -64.301,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Small,
    };
// security = 132 bits, p-fail = 2^-66.624, algorithmic cost ~ 134, 2-norm = 5
pub const PARAM_MESSAGE_2_CARRY_2_PBS_KS_TUNIFORM_2M64: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1024),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(2048),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
        pbs_base_log: DecompositionBaseLog(23),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(6),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(4),
        max_noise_level: MaxNoiseLevel::new(5),
        log2_p_fail: -66.624,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Small,
    };
// security = 132 bits, p-fail = 2^-64.112, algorithmic cost ~ 3355, 2-norm = 9
pub const PARAM_MESSAGE_3_CARRY_3_PBS_KS_TUNIFORM_2M64: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(2048),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(16384),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
        pbs_base_log: DecompositionBaseLog(19),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(23),
        ks_level: DecompositionLevelCount(1),
        message_modulus: MessageModulus(8),
        carry_modulus: CarryModulus(8),
        max_noise_level: MaxNoiseLevel::new(9),
        log2_p_fail: -64.112,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Small,
    };
// security = 132 bits, p-fail = 2^-73.197, algorithmic cost ~ 20401, 2-norm = 17
pub const PARAM_MESSAGE_4_CARRY_4_PBS_KS_TUNIFORM_2M64: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(2048),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(65536),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
        pbs_base_log: DecompositionBaseLog(13),
        pbs_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(12),
        ks_level: DecompositionLevelCount(2),
        message_modulus: MessageModulus(16),
        carry_modulus: CarryModulus(16),
        max_noise_level: MaxNoiseLevel::new(17),
        log2_p_fail: -73.197,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Small,
    };
