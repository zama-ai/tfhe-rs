// p-fail = 2^-40.286, algorithmic cost ~ 47, 2-norm = 3
pub const PARAM_MESSAGE_1_CARRY_1_PBS_KS_GAUSSIAN_2M40: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(798),
        glwe_dimension: GlweDimension(3),
        polynomial_size: PolynomialSize(512),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.2192861177056265e-06,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.966608917163306e-12,
        )),
        pbs_base_log: DecompositionBaseLog(18),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(5),
        ks_level: DecompositionLevelCount(3),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(2),
        max_noise_level: MaxNoiseLevel::new(3),
        log2_p_fail: -40.286,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Small,
    };
// p-fail = 2^-40.448, algorithmic cost ~ 109, 2-norm = 5
pub const PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M40: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(886),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(2048),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            6.3551061035236e-07,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.1529322391500584e-16,
        )),
        pbs_base_log: DecompositionBaseLog(23),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(4),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(4),
        max_noise_level: MaxNoiseLevel::new(5),
        log2_p_fail: -40.448,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Small,
    };
// p-fail = 2^-40.271, algorithmic cost ~ 869, 2-norm = 9
pub const PARAM_MESSAGE_3_CARRY_3_PBS_KS_GAUSSIAN_2M40: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1040),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(8192),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.715424637458287e-08,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(15),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(5),
        message_modulus: MessageModulus(8),
        carry_modulus: CarryModulus(8),
        max_noise_level: MaxNoiseLevel::new(9),
        log2_p_fail: -40.271,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Small,
    };
// p-fail = 2^-40.098, algorithmic cost ~ 4674, 2-norm = 17
pub const PARAM_MESSAGE_4_CARRY_4_PBS_KS_GAUSSIAN_2M40: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1251),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(32768),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            7.594193407931982e-10,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(15),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(5),
        ks_level: DecompositionLevelCount(5),
        message_modulus: MessageModulus(16),
        carry_modulus: CarryModulus(16),
        max_noise_level: MaxNoiseLevel::new(17),
        log2_p_fail: -40.098,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Small,
    };
pub const WITH_CARRY_PARAMETERS_VEC_PBS_KS: [ClassicPBSParameters; 4] = [
    PARAM_MESSAGE_1_CARRY_1_PBS_KS_GAUSSIAN_2M40,
    PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M40,
    PARAM_MESSAGE_3_CARRY_3_PBS_KS_GAUSSIAN_2M40,
    PARAM_MESSAGE_4_CARRY_4_PBS_KS_GAUSSIAN_2M40,
];
use crate::core_crypto::prelude::*;
use crate::shortint::ciphertext::MaxNoiseLevel;
use crate::shortint::parameters::{CarryModulus, ClassicPBSParameters, MessageModulus};
