//! #Warning experimental

pub use crate::core_crypto::commons::dispersion::{DispersionParameter, StandardDev};
pub use crate::core_crypto::commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
};
use crate::shortint::parameters::{
    CarryModulus, CiphertextModulus, EncryptionKeyChoice, LweBskGroupingFactor, MessageModulus,
};
use serde::{Deserialize, Serialize};

/// A structure defining the set of cryptographic parameters for homomorphic integer circuit
/// evaluation. This structure contains information to run the so-called multi-bit PBS with improved
/// latency provided enough threads are available on the machine performing the FHE computations
#[derive(Serialize, Copy, Clone, Deserialize, Debug, PartialEq)]
pub struct MultiBitPBSParameters {
    pub lwe_dimension: LweDimension,
    pub glwe_dimension: GlweDimension,
    pub polynomial_size: PolynomialSize,
    pub lwe_modular_std_dev: StandardDev,
    pub glwe_modular_std_dev: StandardDev,
    pub pbs_base_log: DecompositionBaseLog,
    pub pbs_level: DecompositionLevelCount,
    pub ks_base_log: DecompositionBaseLog,
    pub ks_level: DecompositionLevelCount,
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
    pub ciphertext_modulus: CiphertextModulus,
    pub encryption_key_choice: EncryptionKeyChoice,
    pub grouping_factor: LweBskGroupingFactor,
    pub deterministic_execution: bool,
}

impl MultiBitPBSParameters {
    pub const fn with_deterministic_execution(self) -> Self {
        Self {
            deterministic_execution: true,
            ..self
        }
    }

    pub const fn with_non_deterministic_execution(self) -> Self {
        Self {
            deterministic_execution: false,
            ..self
        }
    }
}

/// Vector containing all [`MultiBitPBSParameters`] parameter sets
pub const ALL_MULTI_BIT_PARAMETER_VEC: [MultiBitPBSParameters; 6] = [
    PARAM_MULTI_BIT_MESSAGE_1_CARRY_1_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_1_CARRY_1_GROUP_3_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS,
];

// Group 2
pub const PARAM_MULTI_BIT_MESSAGE_1_CARRY_1_GROUP_2_KS_PBS: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(764),
        glwe_dimension: GlweDimension(3),
        polynomial_size: PolynomialSize(512),
        lwe_modular_std_dev: StandardDev(0.000006025673585415336),
        glwe_modular_std_dev: StandardDev(0.0000000000039666089171633006),
        pbs_base_log: DecompositionBaseLog(18),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(6),
        ks_level: DecompositionLevelCount(2),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(2),
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(2),
        deterministic_execution: false,
    };

pub const PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(818),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(2048),
        lwe_modular_std_dev: StandardDev(0.000002226459789930014),
        glwe_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
        pbs_base_log: DecompositionBaseLog(22),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(5),
        ks_level: DecompositionLevelCount(3),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(4),
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(2),
        deterministic_execution: false,
    };

pub const PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(922),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(8192),
        lwe_modular_std_dev: StandardDev(0.0000003272369292345697),
        glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
        pbs_base_log: DecompositionBaseLog(14),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(4),
        message_modulus: MessageModulus(8),
        carry_modulus: CarryModulus(8),
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(2),
        deterministic_execution: false,
    };

// Group 3
pub const PARAM_MULTI_BIT_MESSAGE_1_CARRY_1_GROUP_3_KS_PBS: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(765),
        glwe_dimension: GlweDimension(3),
        polynomial_size: PolynomialSize(512),
        lwe_modular_std_dev: StandardDev(0.000005915594083804978),
        glwe_modular_std_dev: StandardDev(0.0000000000039666089171633006),
        pbs_base_log: DecompositionBaseLog(18),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(6),
        ks_level: DecompositionLevelCount(2),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(2),
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(3),
        deterministic_execution: false,
    };

pub const PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(888),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(2048),
        lwe_modular_std_dev: StandardDev(0.0000006125031601933181),
        glwe_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
        pbs_base_log: DecompositionBaseLog(21),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(7),
        ks_level: DecompositionLevelCount(2),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(4),
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(3),
        deterministic_execution: false,
    };

pub const PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(972),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(8192),
        lwe_modular_std_dev: StandardDev(0.00000013016688349592805),
        glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
        pbs_base_log: DecompositionBaseLog(14),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(6),
        ks_level: DecompositionLevelCount(3),
        message_modulus: MessageModulus(8),
        carry_modulus: CarryModulus(8),
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(3),
        deterministic_execution: false,
    };

// Convenience aliases
pub const DEFAULT_MULTI_BIT_GROUP_2: MultiBitPBSParameters =
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS;
pub const DEFAULT_MULTI_BIT_GROUP_3: MultiBitPBSParameters =
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS;
