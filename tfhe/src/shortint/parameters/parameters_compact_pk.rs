//! #Warning experimental

pub use crate::core_crypto::commons::dispersion::StandardDev;
pub use crate::core_crypto::commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, DynamicDistribution, GlweDimension,
    LweDimension, PolynomialSize,
};
use crate::shortint::parameters::{
    CarryModulus, CiphertextModulus, EncryptionKeyChoice, MessageModulus,
};
use crate::shortint::ClassicPBSParameters;

pub const ALL_PARAMETER_VEC_COMPACT_PK: [ClassicPBSParameters; 56] = [
    PARAM_MESSAGE_1_CARRY_1_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_1_CARRY_2_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_1_CARRY_3_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_1_CARRY_4_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_1_CARRY_5_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_1_CARRY_6_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_1_CARRY_7_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_2_CARRY_1_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_2_CARRY_3_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_2_CARRY_4_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_2_CARRY_5_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_2_CARRY_6_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_3_CARRY_1_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_3_CARRY_2_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_3_CARRY_3_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_3_CARRY_4_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_3_CARRY_5_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_4_CARRY_1_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_4_CARRY_2_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_4_CARRY_3_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_4_CARRY_4_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_5_CARRY_1_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_5_CARRY_2_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_5_CARRY_3_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_6_CARRY_1_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_6_CARRY_2_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_7_CARRY_1_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_1_CARRY_1_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_1_CARRY_2_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_1_CARRY_3_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_1_CARRY_4_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_1_CARRY_5_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_1_CARRY_6_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_1_CARRY_7_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_2_CARRY_1_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_2_CARRY_3_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_2_CARRY_4_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_2_CARRY_5_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_2_CARRY_6_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_3_CARRY_1_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_3_CARRY_2_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_3_CARRY_3_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_3_CARRY_4_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_3_CARRY_5_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_4_CARRY_1_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_4_CARRY_2_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_4_CARRY_3_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_4_CARRY_4_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_5_CARRY_1_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_5_CARRY_2_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_5_CARRY_3_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_6_CARRY_1_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_6_CARRY_2_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_7_CARRY_1_COMPACT_PK_PBS_KS,
];

pub const PARAM_MESSAGE_1_CARRY_1_COMPACT_PK_KS_PBS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(638),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        6.150656787521441e-05,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        4.9902938117294516e-08,
    )),
    pbs_base_log: DecompositionBaseLog(6),
    pbs_level: DecompositionLevelCount(3),
    ks_level: DecompositionLevelCount(6),
    ks_base_log: DecompositionBaseLog(2),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
pub const PARAM_MESSAGE_1_CARRY_2_COMPACT_PK_KS_PBS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(710),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.6307554775887557e-05,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.152834667799722e-16,
    )),
    pbs_base_log: DecompositionBaseLog(21),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(4),
    ks_base_log: DecompositionBaseLog(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
pub const PARAM_MESSAGE_1_CARRY_3_COMPACT_PK_KS_PBS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(756),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        6.983104533665408e-06,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.152834667799722e-16,
    )),
    pbs_base_log: DecompositionBaseLog(21),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(5),
    ks_base_log: DecompositionBaseLog(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(8),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
pub const PARAM_MESSAGE_1_CARRY_4_COMPACT_PK_KS_PBS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(821),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.1066761751849058e-06,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(5),
    ks_base_log: DecompositionBaseLog(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(16),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
pub const PARAM_MESSAGE_1_CARRY_5_COMPACT_PK_KS_PBS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(888),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        6.12494404462554e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(6),
    ks_base_log: DecompositionBaseLog(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(32),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
pub const PARAM_MESSAGE_1_CARRY_6_COMPACT_PK_KS_PBS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(942),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.2630942423569665e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(6),
    ks_base_log: DecompositionBaseLog(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(64),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
pub const PARAM_MESSAGE_1_CARRY_7_COMPACT_PK_KS_PBS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1029),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        4.5508144326041556e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(5),
    ks_base_log: DecompositionBaseLog(4),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(128),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
pub const PARAM_MESSAGE_2_CARRY_1_COMPACT_PK_KS_PBS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(710),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.6307554775887557e-05,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.152834667799722e-16,
    )),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(4),
    ks_base_log: DecompositionBaseLog(3),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(2),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
pub const PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(756),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
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
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
pub const PARAM_MESSAGE_2_CARRY_3_COMPACT_PK_KS_PBS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(850),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.2341934723690542e-06,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(4),
    ks_base_log: DecompositionBaseLog(4),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(8),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
pub const PARAM_MESSAGE_2_CARRY_4_COMPACT_PK_KS_PBS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(877),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        7.502111286917793e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(6),
    ks_base_log: DecompositionBaseLog(3),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(16),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
pub const PARAM_MESSAGE_2_CARRY_5_COMPACT_PK_KS_PBS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(942),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.2630942423569665e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(6),
    ks_base_log: DecompositionBaseLog(3),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(32),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
pub const PARAM_MESSAGE_2_CARRY_6_COMPACT_PK_KS_PBS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1030),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        4.46767660406645e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(5),
    ks_base_log: DecompositionBaseLog(4),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(64),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
pub const PARAM_MESSAGE_3_CARRY_1_COMPACT_PK_KS_PBS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(759),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        6.607793351104514e-06,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.152834667799722e-16,
    )),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(5),
    ks_base_log: DecompositionBaseLog(3),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(2),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
pub const PARAM_MESSAGE_3_CARRY_2_COMPACT_PK_KS_PBS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(862),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        9.892236038140916e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(6),
    ks_base_log: DecompositionBaseLog(3),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
pub const PARAM_MESSAGE_3_CARRY_3_COMPACT_PK_KS_PBS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(877),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        7.502111286917793e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(6),
    ks_base_log: DecompositionBaseLog(3),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
pub const PARAM_MESSAGE_3_CARRY_4_COMPACT_PK_KS_PBS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(942),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.2630942423569665e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(6),
    ks_base_log: DecompositionBaseLog(3),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(16),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
pub const PARAM_MESSAGE_3_CARRY_5_COMPACT_PK_KS_PBS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1032),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        4.305929680023812e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(5),
    ks_base_log: DecompositionBaseLog(4),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(32),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
pub const PARAM_MESSAGE_4_CARRY_1_COMPACT_PK_KS_PBS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(820),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.145878762605306e-06,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(5),
    ks_base_log: DecompositionBaseLog(3),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(2),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
pub const PARAM_MESSAGE_4_CARRY_2_COMPACT_PK_KS_PBS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(877),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        7.502111286917793e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(6),
    ks_base_log: DecompositionBaseLog(3),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
pub const PARAM_MESSAGE_4_CARRY_3_COMPACT_PK_KS_PBS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(943),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.2219042764335445e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(6),
    ks_base_log: DecompositionBaseLog(3),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(8),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
pub const PARAM_MESSAGE_4_CARRY_4_COMPACT_PK_KS_PBS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1044),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.4512638181977925e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(5),
    ks_base_log: DecompositionBaseLog(4),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
pub const PARAM_MESSAGE_5_CARRY_1_COMPACT_PK_KS_PBS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(877),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        7.502111286917793e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(6),
    ks_base_log: DecompositionBaseLog(3),
    message_modulus: MessageModulus(32),
    carry_modulus: CarryModulus(2),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
pub const PARAM_MESSAGE_5_CARRY_2_COMPACT_PK_KS_PBS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(947),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.0639337523302752e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(6),
    ks_base_log: DecompositionBaseLog(3),
    message_modulus: MessageModulus(32),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
pub const PARAM_MESSAGE_5_CARRY_3_COMPACT_PK_KS_PBS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(997),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        8.20967300015962e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_level: DecompositionLevelCount(7),
    ks_base_log: DecompositionBaseLog(3),
    message_modulus: MessageModulus(32),
    carry_modulus: CarryModulus(8),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
pub const PARAM_MESSAGE_6_CARRY_1_COMPACT_PK_KS_PBS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(942),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.2630942423569665e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_level: DecompositionLevelCount(6),
    ks_base_log: DecompositionBaseLog(3),
    message_modulus: MessageModulus(64),
    carry_modulus: CarryModulus(2),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
pub const PARAM_MESSAGE_6_CARRY_2_COMPACT_PK_KS_PBS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(998),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        8.05969228871865e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_level: DecompositionLevelCount(7),
    ks_base_log: DecompositionBaseLog(3),
    message_modulus: MessageModulus(64),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
pub const PARAM_MESSAGE_7_CARRY_1_COMPACT_PK_KS_PBS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1017),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        5.6777713805325606e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_level: DecompositionLevelCount(7),
    ks_base_log: DecompositionBaseLog(3),
    message_modulus: MessageModulus(128),
    carry_modulus: CarryModulus(2),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

// Parameter set for small
pub const PARAM_MESSAGE_1_CARRY_1_COMPACT_PK_PBS_KS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(3),
    polynomial_size: PolynomialSize(512),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        4.99029381172945e-8,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.96669408172410e-12,
    )),
    pbs_base_log: DecompositionBaseLog(18),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(8),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};
pub const PARAM_MESSAGE_1_CARRY_2_COMPACT_PK_PBS_KS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        4.99029381172945e-8,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.15283466779972e-16,
    )),
    pbs_base_log: DecompositionBaseLog(18),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(8),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};
pub const PARAM_MESSAGE_1_CARRY_3_COMPACT_PK_PBS_KS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
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
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(8),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};
pub const PARAM_MESSAGE_1_CARRY_4_COMPACT_PK_PBS_KS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        4.99029381172945e-8,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.16840434497101e-19,
    )),
    pbs_base_log: DecompositionBaseLog(21),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(6),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(16),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};
pub const PARAM_MESSAGE_1_CARRY_5_COMPACT_PK_PBS_KS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        4.99029381172945e-8,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.16840434497101e-19,
    )),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(4),
    ks_base_log: DecompositionBaseLog(5),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(32),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};
pub const PARAM_MESSAGE_1_CARRY_6_COMPACT_PK_PBS_KS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        4.99029381172945e-8,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.16840434497101e-19,
    )),
    pbs_base_log: DecompositionBaseLog(12),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(5),
    ks_base_log: DecompositionBaseLog(4),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(64),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};
pub const PARAM_MESSAGE_1_CARRY_7_COMPACT_PK_PBS_KS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        4.99029381172945e-8,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.16840434497101e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(11),
    ks_base_log: DecompositionBaseLog(2),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(128),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};
pub const PARAM_MESSAGE_2_CARRY_1_COMPACT_PK_PBS_KS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
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
    carry_modulus: CarryModulus(2),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};
pub const PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_PBS_KS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
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
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};
pub const PARAM_MESSAGE_2_CARRY_3_COMPACT_PK_PBS_KS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        4.99029381172945e-8,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.16840434497101e-19,
    )),
    pbs_base_log: DecompositionBaseLog(21),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(6),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(8),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};
pub const PARAM_MESSAGE_2_CARRY_4_COMPACT_PK_PBS_KS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        4.99029381172945e-8,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.16840434497101e-19,
    )),
    pbs_base_log: DecompositionBaseLog(12),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(4),
    ks_base_log: DecompositionBaseLog(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(16),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};
pub const PARAM_MESSAGE_2_CARRY_5_COMPACT_PK_PBS_KS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        4.99029381172945e-8,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.16840434497101e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(7),
    ks_base_log: DecompositionBaseLog(3),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(32),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};
pub const PARAM_MESSAGE_2_CARRY_6_COMPACT_PK_PBS_KS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(2048),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.15283466779972e-16,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.16840434497101e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(25),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(64),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};
pub const PARAM_MESSAGE_3_CARRY_1_COMPACT_PK_PBS_KS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        4.99029381172945e-8,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.15283466779972e-16,
    )),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(2),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};
pub const PARAM_MESSAGE_3_CARRY_2_COMPACT_PK_PBS_KS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        4.99029381172945e-8,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.16840434497101e-19,
    )),
    pbs_base_log: DecompositionBaseLog(12),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(4),
    ks_base_log: DecompositionBaseLog(5),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};
pub const PARAM_MESSAGE_3_CARRY_3_COMPACT_PK_PBS_KS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        4.99029381172945e-8,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.16840434497101e-19,
    )),
    pbs_base_log: DecompositionBaseLog(12),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(7),
    ks_base_log: DecompositionBaseLog(3),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};
pub const PARAM_MESSAGE_3_CARRY_4_COMPACT_PK_PBS_KS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        4.99029381172945e-8,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.16840434497101e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(22),
    ks_base_log: DecompositionBaseLog(1),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(16),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};
pub const PARAM_MESSAGE_3_CARRY_5_COMPACT_PK_PBS_KS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(2048),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.15283466779972e-16,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.16840434497101e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(25),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(32),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};
pub const PARAM_MESSAGE_4_CARRY_1_COMPACT_PK_PBS_KS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        4.99029381172945e-8,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.16840434497101e-19,
    )),
    pbs_base_log: DecompositionBaseLog(12),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(11),
    ks_base_log: DecompositionBaseLog(2),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(2),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};
pub const PARAM_MESSAGE_4_CARRY_2_COMPACT_PK_PBS_KS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        4.99029381172945e-8,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.16840434497101e-19,
    )),
    pbs_base_log: DecompositionBaseLog(9),
    pbs_level: DecompositionLevelCount(3),
    ks_level: DecompositionLevelCount(21),
    ks_base_log: DecompositionBaseLog(1),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};
pub const PARAM_MESSAGE_4_CARRY_3_COMPACT_PK_PBS_KS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(2048),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.15283466779972e-16,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.16840434497101e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(25),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(8),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};
pub const PARAM_MESSAGE_4_CARRY_4_COMPACT_PK_PBS_KS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(2048),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.15283466779972e-16,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.16840434497101e-19,
    )),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(25),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};
pub const PARAM_MESSAGE_5_CARRY_1_COMPACT_PK_PBS_KS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(2048),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.15283466779972e-16,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.16840434497101e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(25),
    message_modulus: MessageModulus(32),
    carry_modulus: CarryModulus(2),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};
pub const PARAM_MESSAGE_5_CARRY_2_COMPACT_PK_PBS_KS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(2048),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.15283466779972e-16,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.16840434497101e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(25),
    message_modulus: MessageModulus(32),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};
pub const PARAM_MESSAGE_5_CARRY_3_COMPACT_PK_PBS_KS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(2048),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.15283466779972e-16,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.16840434497101e-19,
    )),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(25),
    message_modulus: MessageModulus(32),
    carry_modulus: CarryModulus(8),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};
pub const PARAM_MESSAGE_6_CARRY_1_COMPACT_PK_PBS_KS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(2048),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.15283466779972e-16,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.16840434497101e-19,
    )),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(25),
    message_modulus: MessageModulus(64),
    carry_modulus: CarryModulus(2),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};
pub const PARAM_MESSAGE_6_CARRY_2_COMPACT_PK_PBS_KS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(2048),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.15283466779972e-16,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.16840434497101e-19,
    )),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(17),
    message_modulus: MessageModulus(64),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};
pub const PARAM_MESSAGE_7_CARRY_1_COMPACT_PK_PBS_KS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(2048),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.15283466779972e-16,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.16840434497101e-19,
    )),
    pbs_base_log: DecompositionBaseLog(9),
    pbs_level: DecompositionLevelCount(4),
    ks_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(17),
    message_modulus: MessageModulus(128),
    carry_modulus: CarryModulus(2),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

// Convenience aliases
pub const DEFAULT_COMPACT_PK: ClassicPBSParameters = PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS;
