pub use super::parameters_wopbs::WopbsParameters;
pub use crate::core_crypto::commons::dispersion::StandardDev;
pub use crate::core_crypto::commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, DynamicDistribution, GlweDimension,
    LweDimension, PolynomialSize,
};
use crate::shortint::parameters::{
    CarryModulus, CiphertextModulus, EncryptionKeyChoice, MessageModulus,
};

pub const LEGACY_WOPBS_ONLY_8_BLOCKS_PARAM_MESSAGE_1_CARRY_0_KS_PBS: WopbsParameters =
    WopbsParameters {
        lwe_dimension: LweDimension(637),
        glwe_dimension: GlweDimension(4),
        polynomial_size: PolynomialSize(512),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            6.27510880527384e-05,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        pbs_base_log: DecompositionBaseLog(16),
        pbs_level: DecompositionLevelCount(2),
        ks_level: DecompositionLevelCount(6),
        ks_base_log: DecompositionBaseLog(2),
        pfks_level: DecompositionLevelCount(2),
        pfks_base_log: DecompositionBaseLog(17),
        pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        cbs_level: DecompositionLevelCount(1),
        cbs_base_log: DecompositionBaseLog(11),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(1),
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
pub const LEGACY_WOPBS_ONLY_8_BLOCKS_PARAM_MESSAGE_1_CARRY_1_KS_PBS: WopbsParameters =
    WopbsParameters {
        lwe_dimension: LweDimension(637),
        glwe_dimension: GlweDimension(4),
        polynomial_size: PolynomialSize(512),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            6.27510880527384e-05,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        pbs_base_log: DecompositionBaseLog(16),
        pbs_level: DecompositionLevelCount(2),
        ks_level: DecompositionLevelCount(6),
        ks_base_log: DecompositionBaseLog(2),
        pfks_level: DecompositionLevelCount(2),
        pfks_base_log: DecompositionBaseLog(17),
        pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        cbs_level: DecompositionLevelCount(1),
        cbs_base_log: DecompositionBaseLog(11),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(2),
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
pub const LEGACY_WOPBS_ONLY_4_BLOCKS_PARAM_MESSAGE_1_CARRY_2_KS_PBS: WopbsParameters =
    WopbsParameters {
        lwe_dimension: LweDimension(589),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(1024),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            0.00015133150634020836,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        pbs_base_log: DecompositionBaseLog(15),
        pbs_level: DecompositionLevelCount(2),
        ks_level: DecompositionLevelCount(5),
        ks_base_log: DecompositionBaseLog(2),
        pfks_level: DecompositionLevelCount(1),
        pfks_base_log: DecompositionBaseLog(25),
        pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        cbs_level: DecompositionLevelCount(2),
        cbs_base_log: DecompositionBaseLog(7),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(4),
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
pub const LEGACY_WOPBS_ONLY_4_BLOCKS_PARAM_MESSAGE_1_CARRY_3_KS_PBS: WopbsParameters =
    WopbsParameters {
        lwe_dimension: LweDimension(589),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(1024),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            0.00015133150634020836,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        pbs_base_log: DecompositionBaseLog(15),
        pbs_level: DecompositionLevelCount(2),
        ks_level: DecompositionLevelCount(5),
        ks_base_log: DecompositionBaseLog(2),
        pfks_level: DecompositionLevelCount(1),
        pfks_base_log: DecompositionBaseLog(25),
        pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        cbs_level: DecompositionLevelCount(2),
        cbs_base_log: DecompositionBaseLog(7),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(8),
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
pub const LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_1_CARRY_4_KS_PBS: WopbsParameters =
    WopbsParameters {
        lwe_dimension: LweDimension(568),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(1024),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            0.00022310338140366212,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        pbs_base_log: DecompositionBaseLog(9),
        pbs_level: DecompositionLevelCount(4),
        ks_level: DecompositionLevelCount(5),
        ks_base_log: DecompositionBaseLog(2),
        pfks_level: DecompositionLevelCount(2),
        pfks_base_log: DecompositionBaseLog(17),
        pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        cbs_level: DecompositionLevelCount(2),
        cbs_base_log: DecompositionBaseLog(9),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(16),
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
pub const LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_1_CARRY_5_KS_PBS: WopbsParameters =
    WopbsParameters {
        lwe_dimension: LweDimension(568),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(1024),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            0.00022310338140366212,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        pbs_base_log: DecompositionBaseLog(9),
        pbs_level: DecompositionLevelCount(4),
        ks_level: DecompositionLevelCount(5),
        ks_base_log: DecompositionBaseLog(2),
        pfks_level: DecompositionLevelCount(2),
        pfks_base_log: DecompositionBaseLog(17),
        pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        cbs_level: DecompositionLevelCount(2),
        cbs_base_log: DecompositionBaseLog(9),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(32),
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
pub const LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_1_CARRY_6_KS_PBS: WopbsParameters =
    WopbsParameters {
        lwe_dimension: LweDimension(568),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(1024),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            0.00022310338140366212,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        pbs_base_log: DecompositionBaseLog(9),
        pbs_level: DecompositionLevelCount(4),
        ks_level: DecompositionLevelCount(5),
        ks_base_log: DecompositionBaseLog(2),
        pfks_level: DecompositionLevelCount(2),
        pfks_base_log: DecompositionBaseLog(17),
        pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        cbs_level: DecompositionLevelCount(2),
        cbs_base_log: DecompositionBaseLog(9),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(64),
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
pub const LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_1_CARRY_7_KS_PBS: WopbsParameters =
    WopbsParameters {
        lwe_dimension: LweDimension(568),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(1024),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            0.00022310338140366212,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        pbs_base_log: DecompositionBaseLog(9),
        pbs_level: DecompositionLevelCount(4),
        ks_level: DecompositionLevelCount(5),
        ks_base_log: DecompositionBaseLog(2),
        pfks_level: DecompositionLevelCount(2),
        pfks_base_log: DecompositionBaseLog(17),
        pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        cbs_level: DecompositionLevelCount(2),
        cbs_base_log: DecompositionBaseLog(9),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(128),
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
pub const LEGACY_WOPBS_ONLY_8_BLOCKS_PARAM_MESSAGE_2_CARRY_0_KS_PBS: WopbsParameters =
    WopbsParameters {
        lwe_dimension: LweDimension(637),
        glwe_dimension: GlweDimension(4),
        polynomial_size: PolynomialSize(512),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            6.27510880527384e-05,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        pbs_base_log: DecompositionBaseLog(16),
        pbs_level: DecompositionLevelCount(2),
        ks_level: DecompositionLevelCount(6),
        ks_base_log: DecompositionBaseLog(2),
        pfks_level: DecompositionLevelCount(2),
        pfks_base_log: DecompositionBaseLog(17),
        pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        cbs_level: DecompositionLevelCount(1),
        cbs_base_log: DecompositionBaseLog(11),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(1),
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
pub const LEGACY_WOPBS_ONLY_4_BLOCKS_PARAM_MESSAGE_2_CARRY_1_KS_PBS: WopbsParameters =
    WopbsParameters {
        lwe_dimension: LweDimension(589),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(1024),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            0.00015133150634020836,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        pbs_base_log: DecompositionBaseLog(15),
        pbs_level: DecompositionLevelCount(2),
        ks_level: DecompositionLevelCount(5),
        ks_base_log: DecompositionBaseLog(2),
        pfks_level: DecompositionLevelCount(1),
        pfks_base_log: DecompositionBaseLog(25),
        pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        cbs_level: DecompositionLevelCount(2),
        cbs_base_log: DecompositionBaseLog(7),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(2),
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
pub const LEGACY_WOPBS_ONLY_4_BLOCKS_PARAM_MESSAGE_2_CARRY_2_KS_PBS: WopbsParameters =
    WopbsParameters {
        lwe_dimension: LweDimension(589),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(1024),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            0.00015133150634020836,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        pbs_base_log: DecompositionBaseLog(15),
        pbs_level: DecompositionLevelCount(2),
        ks_level: DecompositionLevelCount(5),
        ks_base_log: DecompositionBaseLog(2),
        pfks_level: DecompositionLevelCount(1),
        pfks_base_log: DecompositionBaseLog(25),
        pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        cbs_level: DecompositionLevelCount(2),
        cbs_base_log: DecompositionBaseLog(7),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(4),
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
pub const LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_2_CARRY_3_KS_PBS: WopbsParameters =
    WopbsParameters {
        lwe_dimension: LweDimension(568),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(1024),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            0.00022310338140366212,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        pbs_base_log: DecompositionBaseLog(9),
        pbs_level: DecompositionLevelCount(4),
        ks_level: DecompositionLevelCount(5),
        ks_base_log: DecompositionBaseLog(2),
        pfks_level: DecompositionLevelCount(2),
        pfks_base_log: DecompositionBaseLog(17),
        pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        cbs_level: DecompositionLevelCount(2),
        cbs_base_log: DecompositionBaseLog(9),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(8),
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
pub const LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_2_CARRY_4_KS_PBS: WopbsParameters =
    WopbsParameters {
        lwe_dimension: LweDimension(568),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(1024),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            0.00022310338140366212,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        pbs_base_log: DecompositionBaseLog(9),
        pbs_level: DecompositionLevelCount(4),
        ks_level: DecompositionLevelCount(5),
        ks_base_log: DecompositionBaseLog(2),
        pfks_level: DecompositionLevelCount(2),
        pfks_base_log: DecompositionBaseLog(17),
        pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        cbs_level: DecompositionLevelCount(2),
        cbs_base_log: DecompositionBaseLog(9),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(16),
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
pub const LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_2_CARRY_5_KS_PBS: WopbsParameters =
    WopbsParameters {
        lwe_dimension: LweDimension(568),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(1024),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            0.00022310338140366212,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        pbs_base_log: DecompositionBaseLog(9),
        pbs_level: DecompositionLevelCount(4),
        ks_level: DecompositionLevelCount(5),
        ks_base_log: DecompositionBaseLog(2),
        pfks_level: DecompositionLevelCount(2),
        pfks_base_log: DecompositionBaseLog(17),
        pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        cbs_level: DecompositionLevelCount(2),
        cbs_base_log: DecompositionBaseLog(9),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(32),
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
pub const LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_2_CARRY_6_KS_PBS: WopbsParameters =
    WopbsParameters {
        lwe_dimension: LweDimension(568),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(1024),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            0.00022310338140366212,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        pbs_base_log: DecompositionBaseLog(9),
        pbs_level: DecompositionLevelCount(4),
        ks_level: DecompositionLevelCount(5),
        ks_base_log: DecompositionBaseLog(2),
        pfks_level: DecompositionLevelCount(2),
        pfks_base_log: DecompositionBaseLog(17),
        pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        cbs_level: DecompositionLevelCount(2),
        cbs_base_log: DecompositionBaseLog(9),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(64),
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
pub const LEGACY_WOPBS_ONLY_4_BLOCKS_PARAM_MESSAGE_3_CARRY_0_KS_PBS: WopbsParameters =
    WopbsParameters {
        lwe_dimension: LweDimension(589),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(1024),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            0.00015133150634020836,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        pbs_base_log: DecompositionBaseLog(15),
        pbs_level: DecompositionLevelCount(2),
        ks_level: DecompositionLevelCount(5),
        ks_base_log: DecompositionBaseLog(2),
        pfks_level: DecompositionLevelCount(1),
        pfks_base_log: DecompositionBaseLog(25),
        pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        cbs_level: DecompositionLevelCount(2),
        cbs_base_log: DecompositionBaseLog(7),
        message_modulus: MessageModulus(8),
        carry_modulus: CarryModulus(1),
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
pub const LEGACY_WOPBS_ONLY_4_BLOCKS_PARAM_MESSAGE_3_CARRY_1_KS_PBS: WopbsParameters =
    WopbsParameters {
        lwe_dimension: LweDimension(589),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(1024),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            0.00015133150634020836,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        pbs_base_log: DecompositionBaseLog(15),
        pbs_level: DecompositionLevelCount(2),
        ks_level: DecompositionLevelCount(5),
        ks_base_log: DecompositionBaseLog(2),
        pfks_level: DecompositionLevelCount(1),
        pfks_base_log: DecompositionBaseLog(25),
        pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        cbs_level: DecompositionLevelCount(2),
        cbs_base_log: DecompositionBaseLog(7),
        message_modulus: MessageModulus(8),
        carry_modulus: CarryModulus(2),
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
pub const LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_3_CARRY_2_KS_PBS: WopbsParameters =
    WopbsParameters {
        lwe_dimension: LweDimension(568),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(1024),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            0.00022310338140366212,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        pbs_base_log: DecompositionBaseLog(9),
        pbs_level: DecompositionLevelCount(4),
        ks_level: DecompositionLevelCount(5),
        ks_base_log: DecompositionBaseLog(2),
        pfks_level: DecompositionLevelCount(2),
        pfks_base_log: DecompositionBaseLog(17),
        pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        cbs_level: DecompositionLevelCount(2),
        cbs_base_log: DecompositionBaseLog(9),
        message_modulus: MessageModulus(8),
        carry_modulus: CarryModulus(4),
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
pub const LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_3_CARRY_3_KS_PBS: WopbsParameters =
    WopbsParameters {
        lwe_dimension: LweDimension(568),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(1024),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            0.00022310338140366212,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        pbs_base_log: DecompositionBaseLog(9),
        pbs_level: DecompositionLevelCount(4),
        ks_level: DecompositionLevelCount(5),
        ks_base_log: DecompositionBaseLog(2),
        pfks_level: DecompositionLevelCount(2),
        pfks_base_log: DecompositionBaseLog(17),
        pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        cbs_level: DecompositionLevelCount(2),
        cbs_base_log: DecompositionBaseLog(9),
        message_modulus: MessageModulus(8),
        carry_modulus: CarryModulus(8),
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
pub const LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_3_CARRY_4_KS_PBS: WopbsParameters =
    WopbsParameters {
        lwe_dimension: LweDimension(568),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(1024),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            0.00022310338140366212,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        pbs_base_log: DecompositionBaseLog(9),
        pbs_level: DecompositionLevelCount(4),
        ks_level: DecompositionLevelCount(5),
        ks_base_log: DecompositionBaseLog(2),
        pfks_level: DecompositionLevelCount(2),
        pfks_base_log: DecompositionBaseLog(17),
        pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        cbs_level: DecompositionLevelCount(2),
        cbs_base_log: DecompositionBaseLog(9),
        message_modulus: MessageModulus(8),
        carry_modulus: CarryModulus(16),
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
pub const LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_3_CARRY_5_KS_PBS: WopbsParameters =
    WopbsParameters {
        lwe_dimension: LweDimension(568),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(1024),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            0.00022310338140366212,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        pbs_base_log: DecompositionBaseLog(9),
        pbs_level: DecompositionLevelCount(4),
        ks_level: DecompositionLevelCount(5),
        ks_base_log: DecompositionBaseLog(2),
        pfks_level: DecompositionLevelCount(2),
        pfks_base_log: DecompositionBaseLog(17),
        pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        cbs_level: DecompositionLevelCount(2),
        cbs_base_log: DecompositionBaseLog(9),
        message_modulus: MessageModulus(8),
        carry_modulus: CarryModulus(32),
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
pub const LEGACY_WOPBS_ONLY_4_BLOCKS_PARAM_MESSAGE_4_CARRY_0_KS_PBS: WopbsParameters =
    WopbsParameters {
        lwe_dimension: LweDimension(589),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(1024),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            0.00015133150634020836,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        pbs_base_log: DecompositionBaseLog(15),
        pbs_level: DecompositionLevelCount(2),
        ks_level: DecompositionLevelCount(5),
        ks_base_log: DecompositionBaseLog(2),
        pfks_level: DecompositionLevelCount(1),
        pfks_base_log: DecompositionBaseLog(25),
        pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        cbs_level: DecompositionLevelCount(2),
        cbs_base_log: DecompositionBaseLog(7),
        message_modulus: MessageModulus(16),
        carry_modulus: CarryModulus(1),
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
pub const LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_4_CARRY_1_KS_PBS: WopbsParameters =
    WopbsParameters {
        lwe_dimension: LweDimension(568),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(1024),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            0.00022310338140366212,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        pbs_base_log: DecompositionBaseLog(9),
        pbs_level: DecompositionLevelCount(4),
        ks_level: DecompositionLevelCount(5),
        ks_base_log: DecompositionBaseLog(2),
        pfks_level: DecompositionLevelCount(2),
        pfks_base_log: DecompositionBaseLog(17),
        pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        cbs_level: DecompositionLevelCount(2),
        cbs_base_log: DecompositionBaseLog(9),
        message_modulus: MessageModulus(16),
        carry_modulus: CarryModulus(2),
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
pub const LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_4_CARRY_2_KS_PBS: WopbsParameters =
    WopbsParameters {
        lwe_dimension: LweDimension(568),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(1024),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            0.00022310338140366212,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        pbs_base_log: DecompositionBaseLog(9),
        pbs_level: DecompositionLevelCount(4),
        ks_level: DecompositionLevelCount(5),
        ks_base_log: DecompositionBaseLog(2),
        pfks_level: DecompositionLevelCount(2),
        pfks_base_log: DecompositionBaseLog(17),
        pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        cbs_level: DecompositionLevelCount(2),
        cbs_base_log: DecompositionBaseLog(9),
        message_modulus: MessageModulus(16),
        carry_modulus: CarryModulus(4),
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
pub const LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_4_CARRY_3_KS_PBS: WopbsParameters =
    WopbsParameters {
        lwe_dimension: LweDimension(568),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(1024),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            0.00022310338140366212,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        pbs_base_log: DecompositionBaseLog(9),
        pbs_level: DecompositionLevelCount(4),
        ks_level: DecompositionLevelCount(5),
        ks_base_log: DecompositionBaseLog(2),
        pfks_level: DecompositionLevelCount(2),
        pfks_base_log: DecompositionBaseLog(17),
        pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        cbs_level: DecompositionLevelCount(2),
        cbs_base_log: DecompositionBaseLog(9),
        message_modulus: MessageModulus(16),
        carry_modulus: CarryModulus(8),
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
pub const LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_4_CARRY_4_KS_PBS: WopbsParameters =
    WopbsParameters {
        lwe_dimension: LweDimension(568),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(1024),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            0.00022310338140366212,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        pbs_base_log: DecompositionBaseLog(9),
        pbs_level: DecompositionLevelCount(4),
        ks_level: DecompositionLevelCount(5),
        ks_base_log: DecompositionBaseLog(2),
        pfks_level: DecompositionLevelCount(2),
        pfks_base_log: DecompositionBaseLog(17),
        pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        cbs_level: DecompositionLevelCount(2),
        cbs_base_log: DecompositionBaseLog(9),
        message_modulus: MessageModulus(16),
        carry_modulus: CarryModulus(16),
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
pub const LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_5_CARRY_0_KS_PBS: WopbsParameters =
    WopbsParameters {
        lwe_dimension: LweDimension(568),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(1024),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            0.00022310338140366212,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        pbs_base_log: DecompositionBaseLog(9),
        pbs_level: DecompositionLevelCount(4),
        ks_level: DecompositionLevelCount(5),
        ks_base_log: DecompositionBaseLog(2),
        pfks_level: DecompositionLevelCount(2),
        pfks_base_log: DecompositionBaseLog(17),
        pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        cbs_level: DecompositionLevelCount(2),
        cbs_base_log: DecompositionBaseLog(9),
        message_modulus: MessageModulus(32),
        carry_modulus: CarryModulus(1),
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
pub const LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_5_CARRY_1_KS_PBS: WopbsParameters =
    WopbsParameters {
        lwe_dimension: LweDimension(568),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(1024),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            0.00022310338140366212,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        pbs_base_log: DecompositionBaseLog(9),
        pbs_level: DecompositionLevelCount(4),
        ks_level: DecompositionLevelCount(5),
        ks_base_log: DecompositionBaseLog(2),
        pfks_level: DecompositionLevelCount(2),
        pfks_base_log: DecompositionBaseLog(17),
        pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        cbs_level: DecompositionLevelCount(2),
        cbs_base_log: DecompositionBaseLog(9),
        message_modulus: MessageModulus(32),
        carry_modulus: CarryModulus(2),
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
pub const LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_5_CARRY_2_KS_PBS: WopbsParameters =
    WopbsParameters {
        lwe_dimension: LweDimension(568),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(1024),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            0.00022310338140366212,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        pbs_base_log: DecompositionBaseLog(9),
        pbs_level: DecompositionLevelCount(4),
        ks_level: DecompositionLevelCount(5),
        ks_base_log: DecompositionBaseLog(2),
        pfks_level: DecompositionLevelCount(2),
        pfks_base_log: DecompositionBaseLog(17),
        pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        cbs_level: DecompositionLevelCount(2),
        cbs_base_log: DecompositionBaseLog(9),
        message_modulus: MessageModulus(32),
        carry_modulus: CarryModulus(4),
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
pub const LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_5_CARRY_3_KS_PBS: WopbsParameters =
    WopbsParameters {
        lwe_dimension: LweDimension(568),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(1024),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            0.00022310338140366212,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        pbs_base_log: DecompositionBaseLog(9),
        pbs_level: DecompositionLevelCount(4),
        ks_level: DecompositionLevelCount(5),
        ks_base_log: DecompositionBaseLog(2),
        pfks_level: DecompositionLevelCount(2),
        pfks_base_log: DecompositionBaseLog(17),
        pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        cbs_level: DecompositionLevelCount(2),
        cbs_base_log: DecompositionBaseLog(9),
        message_modulus: MessageModulus(32),
        carry_modulus: CarryModulus(8),
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
pub const LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_6_CARRY_0_KS_PBS: WopbsParameters =
    WopbsParameters {
        lwe_dimension: LweDimension(568),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(1024),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            0.00022310338140366212,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        pbs_base_log: DecompositionBaseLog(9),
        pbs_level: DecompositionLevelCount(4),
        ks_level: DecompositionLevelCount(5),
        ks_base_log: DecompositionBaseLog(2),
        pfks_level: DecompositionLevelCount(2),
        pfks_base_log: DecompositionBaseLog(17),
        pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        cbs_level: DecompositionLevelCount(2),
        cbs_base_log: DecompositionBaseLog(9),
        message_modulus: MessageModulus(64),
        carry_modulus: CarryModulus(1),
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
pub const LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_6_CARRY_1_KS_PBS: WopbsParameters =
    WopbsParameters {
        lwe_dimension: LweDimension(568),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(1024),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            0.00022310338140366212,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        pbs_base_log: DecompositionBaseLog(9),
        pbs_level: DecompositionLevelCount(4),
        ks_level: DecompositionLevelCount(5),
        ks_base_log: DecompositionBaseLog(2),
        pfks_level: DecompositionLevelCount(2),
        pfks_base_log: DecompositionBaseLog(17),
        pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        cbs_level: DecompositionLevelCount(2),
        cbs_base_log: DecompositionBaseLog(9),
        message_modulus: MessageModulus(64),
        carry_modulus: CarryModulus(2),
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
pub const LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_6_CARRY_2_KS_PBS: WopbsParameters =
    WopbsParameters {
        lwe_dimension: LweDimension(568),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(1024),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            0.00022310338140366212,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        pbs_base_log: DecompositionBaseLog(9),
        pbs_level: DecompositionLevelCount(4),
        ks_level: DecompositionLevelCount(5),
        ks_base_log: DecompositionBaseLog(2),
        pfks_level: DecompositionLevelCount(2),
        pfks_base_log: DecompositionBaseLog(17),
        pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        cbs_level: DecompositionLevelCount(2),
        cbs_base_log: DecompositionBaseLog(9),
        message_modulus: MessageModulus(64),
        carry_modulus: CarryModulus(4),
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
pub const LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_7_CARRY_0_KS_PBS: WopbsParameters =
    WopbsParameters {
        lwe_dimension: LweDimension(568),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(1024),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            0.00022310338140366212,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        pbs_base_log: DecompositionBaseLog(9),
        pbs_level: DecompositionLevelCount(4),
        ks_level: DecompositionLevelCount(5),
        ks_base_log: DecompositionBaseLog(2),
        pfks_level: DecompositionLevelCount(2),
        pfks_base_log: DecompositionBaseLog(17),
        pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        cbs_level: DecompositionLevelCount(2),
        cbs_base_log: DecompositionBaseLog(9),
        message_modulus: MessageModulus(128),
        carry_modulus: CarryModulus(1),
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
pub const LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_7_CARRY_1_KS_PBS: WopbsParameters =
    WopbsParameters {
        lwe_dimension: LweDimension(568),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(1024),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            0.00022310338140366212,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        pbs_base_log: DecompositionBaseLog(9),
        pbs_level: DecompositionLevelCount(4),
        ks_level: DecompositionLevelCount(5),
        ks_base_log: DecompositionBaseLog(2),
        pfks_level: DecompositionLevelCount(2),
        pfks_base_log: DecompositionBaseLog(17),
        pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        cbs_level: DecompositionLevelCount(2),
        cbs_base_log: DecompositionBaseLog(9),
        message_modulus: MessageModulus(128),
        carry_modulus: CarryModulus(2),
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
pub const LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_8_CARRY_0_KS_PBS: WopbsParameters =
    WopbsParameters {
        lwe_dimension: LweDimension(568),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(1024),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            0.00022310338140366212,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        pbs_base_log: DecompositionBaseLog(9),
        pbs_level: DecompositionLevelCount(4),
        ks_level: DecompositionLevelCount(5),
        ks_base_log: DecompositionBaseLog(2),
        pfks_level: DecompositionLevelCount(2),
        pfks_base_log: DecompositionBaseLog(17),
        pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        cbs_level: DecompositionLevelCount(2),
        cbs_base_log: DecompositionBaseLog(9),
        message_modulus: MessageModulus(256),
        carry_modulus: CarryModulus(1),
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
