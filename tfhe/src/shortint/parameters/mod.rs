//! Module with the definition of parameters for short-integers.
//!
//! This module provides the structure containing the cryptographic parameters required for the
//! homomorphic evaluation of integer circuits as well as a list of secure cryptographic parameter
//! sets.

pub use crate::core_crypto::prelude::{
    DecompositionBaseLog, DecompositionLevelCount, DispersionParameter, GlweDimension,
    LweDimension, PolynomialSize, StandardDev,
};
use serde::{Deserialize, Serialize};

pub mod parameters_wopbs;
pub mod parameters_wopbs_message_carry;
pub(crate) mod parameters_wopbs_prime_moduli;

/// The number of bits on which the message will be encoded.
#[derive(Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize)]
pub struct MessageModulus(pub usize);

/// The number of bits on which the carry will be encoded.
#[derive(Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize)]
pub struct CarryModulus(pub usize);

/// A structure defining the set of cryptographic parameters for homomorphic integer circuit
/// evaluation.
#[derive(Serialize, Copy, Clone, Deserialize, Debug, PartialEq)]
pub struct Parameters {
    pub lwe_dimension: LweDimension,
    pub glwe_dimension: GlweDimension,
    pub polynomial_size: PolynomialSize,
    pub lwe_modular_std_dev: StandardDev,
    pub glwe_modular_std_dev: StandardDev,
    pub pbs_base_log: DecompositionBaseLog,
    pub pbs_level: DecompositionLevelCount,
    pub ks_base_log: DecompositionBaseLog,
    pub ks_level: DecompositionLevelCount,
    pub pfks_level: DecompositionLevelCount,
    pub pfks_base_log: DecompositionBaseLog,
    pub pfks_modular_std_dev: StandardDev,
    pub cbs_level: DecompositionLevelCount,
    pub cbs_base_log: DecompositionBaseLog,
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
}

impl Parameters {
    /// Constructs a new set of parameters for integer circuit evaluation.
    ///
    /// # Safety
    ///
    /// This function is unsafe, as failing to fix the parameters properly would yield incorrect
    /// and unsecure computation. Unless you are a cryptographer who really knows the impact of each
    /// of those parameters, you __must__ stick with the provided parameters.
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn new_unsecure(
        lwe_dimension: LweDimension,
        glwe_dimension: GlweDimension,
        polynomial_size: PolynomialSize,
        lwe_modular_std_dev: StandardDev,
        glwe_modular_std_dev: StandardDev,
        pbs_base_log: DecompositionBaseLog,
        pbs_level: DecompositionLevelCount,
        ks_base_log: DecompositionBaseLog,
        ks_level: DecompositionLevelCount,
        pfks_level: DecompositionLevelCount,
        pfks_base_log: DecompositionBaseLog,
        pfks_modular_std_dev: StandardDev,
        cbs_level: DecompositionLevelCount,
        cbs_base_log: DecompositionBaseLog,
        message_modulus: MessageModulus,
        carry_modulus: CarryModulus,
    ) -> Parameters {
        Parameters {
            lwe_dimension,
            glwe_dimension,
            polynomial_size,
            lwe_modular_std_dev,
            glwe_modular_std_dev,
            pbs_base_log,
            pbs_level,
            ks_level,
            ks_base_log,
            pfks_level,
            pfks_base_log,
            pfks_modular_std_dev,
            cbs_level,
            cbs_base_log,
            message_modulus,
            carry_modulus,
        }
    }
}

impl Default for Parameters {
    fn default() -> Self {
        DEFAULT_PARAMETERS
    }
}

/// Vector containing all parameter sets
pub const ALL_PARAMETER_VEC: [Parameters; 28] = WITH_CARRY_PARAMETERS_VEC;

/// Vector containing all parameter sets where the carry space is strictly greater than one
pub const WITH_CARRY_PARAMETERS_VEC: [Parameters; 28] = [
    PARAM_MESSAGE_1_CARRY_1,
    PARAM_MESSAGE_1_CARRY_2,
    PARAM_MESSAGE_1_CARRY_3,
    PARAM_MESSAGE_1_CARRY_4,
    PARAM_MESSAGE_1_CARRY_5,
    PARAM_MESSAGE_1_CARRY_6,
    PARAM_MESSAGE_1_CARRY_7,
    PARAM_MESSAGE_2_CARRY_1,
    PARAM_MESSAGE_2_CARRY_2,
    PARAM_MESSAGE_2_CARRY_3,
    PARAM_MESSAGE_2_CARRY_4,
    PARAM_MESSAGE_2_CARRY_5,
    PARAM_MESSAGE_2_CARRY_6,
    PARAM_MESSAGE_3_CARRY_1,
    PARAM_MESSAGE_3_CARRY_2,
    PARAM_MESSAGE_3_CARRY_3,
    PARAM_MESSAGE_3_CARRY_4,
    PARAM_MESSAGE_3_CARRY_5,
    PARAM_MESSAGE_4_CARRY_1,
    PARAM_MESSAGE_4_CARRY_2,
    PARAM_MESSAGE_4_CARRY_3,
    PARAM_MESSAGE_4_CARRY_4,
    PARAM_MESSAGE_5_CARRY_1,
    PARAM_MESSAGE_5_CARRY_2,
    PARAM_MESSAGE_5_CARRY_3,
    PARAM_MESSAGE_6_CARRY_1,
    PARAM_MESSAGE_6_CARRY_2,
    PARAM_MESSAGE_7_CARRY_1,
];

/// Vector containing all parameter sets where the carry space is strictly greater than one
pub const BIVARIATE_PBS_COMPLIANT_PARAMETER_SET_VEC: [Parameters; 16] = [
    PARAM_MESSAGE_1_CARRY_1,
    PARAM_MESSAGE_1_CARRY_2,
    PARAM_MESSAGE_1_CARRY_3,
    PARAM_MESSAGE_1_CARRY_4,
    PARAM_MESSAGE_1_CARRY_5,
    PARAM_MESSAGE_1_CARRY_6,
    PARAM_MESSAGE_1_CARRY_7,
    PARAM_MESSAGE_2_CARRY_2,
    PARAM_MESSAGE_2_CARRY_3,
    PARAM_MESSAGE_2_CARRY_4,
    PARAM_MESSAGE_2_CARRY_5,
    PARAM_MESSAGE_2_CARRY_6,
    PARAM_MESSAGE_3_CARRY_3,
    PARAM_MESSAGE_3_CARRY_4,
    PARAM_MESSAGE_3_CARRY_5,
    PARAM_MESSAGE_4_CARRY_4,
];

/// Default parameter set
pub const DEFAULT_PARAMETERS: Parameters = PARAM_MESSAGE_2_CARRY_2;

/// Nomenclature: PARAM_MESSAGE_X_CARRY_Y: the message (respectively carry) modulus is
/// encoded over X (reps. Y) bits, i.e., message_modulus = 2^{X} (resp. carry_modulus = 2^{Y}).
pub const PARAM_MESSAGE_1_CARRY_0: Parameters = Parameters {
    lwe_dimension: LweDimension(567),
    glwe_dimension: GlweDimension(5),
    polynomial_size: PolynomialSize(256),
    lwe_modular_std_dev: StandardDev(0.00017395369678340785),
    glwe_modular_std_dev: StandardDev(0.00000000037411618952047216),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    pfks_level: DecompositionLevelCount(1),
    pfks_base_log: DecompositionBaseLog(15),
    pfks_modular_std_dev: StandardDev(0.00000000037411618952047216),
    cbs_level: DecompositionLevelCount(0),
    cbs_base_log: DecompositionBaseLog(0),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(1),
};
pub const PARAM_MESSAGE_1_CARRY_1: Parameters = Parameters {
    lwe_dimension: LweDimension(653),
    glwe_dimension: GlweDimension(6),
    polynomial_size: PolynomialSize(256),
    lwe_modular_std_dev: StandardDev(0.00003604499526942373),
    glwe_modular_std_dev: StandardDev(0.0000000000034525330484572114),
    pbs_base_log: DecompositionBaseLog(18),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(4),
    pfks_level: DecompositionLevelCount(1),
    pfks_base_log: DecompositionBaseLog(18),
    pfks_modular_std_dev: StandardDev(0.0000000000034525330484572114),
    cbs_level: DecompositionLevelCount(0),
    cbs_base_log: DecompositionBaseLog(0),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
};
pub const PARAM_MESSAGE_2_CARRY_0: Parameters = Parameters {
    lwe_dimension: LweDimension(653),
    glwe_dimension: GlweDimension(5),
    polynomial_size: PolynomialSize(256),
    lwe_modular_std_dev: StandardDev(0.00003604499526942373),
    glwe_modular_std_dev: StandardDev(0.00000000037411618952047216),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(4),
    pfks_level: DecompositionLevelCount(1),
    pfks_base_log: DecompositionBaseLog(15),
    pfks_modular_std_dev: StandardDev(0.00000000037411618952047216),
    cbs_level: DecompositionLevelCount(0),
    cbs_base_log: DecompositionBaseLog(0),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(1),
};
pub const PARAM_MESSAGE_1_CARRY_2: Parameters = Parameters {
    lwe_dimension: LweDimension(698),
    glwe_dimension: GlweDimension(3),
    polynomial_size: PolynomialSize(512),
    lwe_modular_std_dev: StandardDev(0.000015818059929193196),
    glwe_modular_std_dev: StandardDev(0.0000000000034525330484572114),
    pbs_base_log: DecompositionBaseLog(18),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(4),
    ks_base_log: DecompositionBaseLog(3),
    pfks_level: DecompositionLevelCount(1),
    pfks_base_log: DecompositionBaseLog(18),
    pfks_modular_std_dev: StandardDev(0.0000000000034525330484572114),
    cbs_level: DecompositionLevelCount(0),
    cbs_base_log: DecompositionBaseLog(0),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(4),
};
pub const PARAM_MESSAGE_2_CARRY_1: Parameters = Parameters {
    lwe_dimension: LweDimension(696),
    glwe_dimension: GlweDimension(3),
    polynomial_size: PolynomialSize(512),
    lwe_modular_std_dev: StandardDev(0.00001640781036519474),
    glwe_modular_std_dev: StandardDev(0.0000000000034525330484572114),
    pbs_base_log: DecompositionBaseLog(18),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(4),
    pfks_level: DecompositionLevelCount(1),
    pfks_base_log: DecompositionBaseLog(18),
    pfks_modular_std_dev: StandardDev(0.0000000000034525330484572114),
    cbs_level: DecompositionLevelCount(0),
    cbs_base_log: DecompositionBaseLog(0),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(2),
};
pub const PARAM_MESSAGE_3_CARRY_0: Parameters = Parameters {
    lwe_dimension: LweDimension(694),
    glwe_dimension: GlweDimension(3),
    polynomial_size: PolynomialSize(512),
    lwe_modular_std_dev: StandardDev(0.00001701954867950249),
    glwe_modular_std_dev: StandardDev(0.0000000000034525330484572114),
    pbs_base_log: DecompositionBaseLog(18),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(4),
    pfks_level: DecompositionLevelCount(1),
    pfks_base_log: DecompositionBaseLog(18),
    pfks_modular_std_dev: StandardDev(0.0000000000034525330484572114),
    cbs_level: DecompositionLevelCount(0),
    cbs_base_log: DecompositionBaseLog(0),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(1),
};
pub const PARAM_MESSAGE_1_CARRY_3: Parameters = Parameters {
    lwe_dimension: LweDimension(771),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_modular_std_dev: StandardDev(0.000004158126532841584),
    glwe_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(4),
    pfks_level: DecompositionLevelCount(1),
    pfks_base_log: DecompositionBaseLog(23),
    pfks_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
    cbs_level: DecompositionLevelCount(0),
    cbs_base_log: DecompositionBaseLog(0),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(8),
};
pub const PARAM_MESSAGE_2_CARRY_2: Parameters = Parameters {
    lwe_dimension: LweDimension(769),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_modular_std_dev: StandardDev(0.0000043131554647504185),
    glwe_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(4),
    pfks_level: DecompositionLevelCount(1),
    pfks_base_log: DecompositionBaseLog(23),
    pfks_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
    cbs_level: DecompositionLevelCount(0),
    cbs_base_log: DecompositionBaseLog(0),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
};
pub const PARAM_MESSAGE_3_CARRY_1: Parameters = Parameters {
    lwe_dimension: LweDimension(769),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_modular_std_dev: StandardDev(0.0000043131554647504185),
    glwe_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(4),
    pfks_level: DecompositionLevelCount(1),
    pfks_base_log: DecompositionBaseLog(23),
    pfks_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
    cbs_level: DecompositionLevelCount(0),
    cbs_base_log: DecompositionBaseLog(0),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(2),
};
pub const PARAM_MESSAGE_4_CARRY_0: Parameters = Parameters {
    lwe_dimension: LweDimension(769),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_modular_std_dev: StandardDev(0.0000043131554647504185),
    glwe_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(4),
    pfks_level: DecompositionLevelCount(1),
    pfks_base_log: DecompositionBaseLog(23),
    pfks_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
    cbs_level: DecompositionLevelCount(0),
    cbs_base_log: DecompositionBaseLog(0),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(1),
};
pub const PARAM_MESSAGE_1_CARRY_4: Parameters = Parameters {
    lwe_dimension: LweDimension(769),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_modular_std_dev: StandardDev(0.0000043131554647504185),
    glwe_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(5),
    ks_base_log: DecompositionBaseLog(3),
    pfks_level: DecompositionLevelCount(1),
    pfks_base_log: DecompositionBaseLog(23),
    pfks_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
    cbs_level: DecompositionLevelCount(0),
    cbs_base_log: DecompositionBaseLog(0),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(16),
};
pub const PARAM_MESSAGE_2_CARRY_3: Parameters = Parameters {
    lwe_dimension: LweDimension(755),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_modular_std_dev: StandardDev(0.000005572845359330198),
    glwe_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(5),
    ks_base_log: DecompositionBaseLog(3),
    pfks_level: DecompositionLevelCount(1),
    pfks_base_log: DecompositionBaseLog(23),
    pfks_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
    cbs_level: DecompositionLevelCount(0),
    cbs_base_log: DecompositionBaseLog(0),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(8),
};
pub const PARAM_MESSAGE_3_CARRY_2: Parameters = Parameters {
    lwe_dimension: LweDimension(754),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_modular_std_dev: StandardDev(0.0000056757818866051225),
    glwe_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(5),
    ks_base_log: DecompositionBaseLog(3),
    pfks_level: DecompositionLevelCount(1),
    pfks_base_log: DecompositionBaseLog(23),
    pfks_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
    cbs_level: DecompositionLevelCount(0),
    cbs_base_log: DecompositionBaseLog(0),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(4),
};
pub const PARAM_MESSAGE_4_CARRY_1: Parameters = Parameters {
    lwe_dimension: LweDimension(754),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_modular_std_dev: StandardDev(0.0000056757818866051225),
    glwe_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(5),
    ks_base_log: DecompositionBaseLog(3),
    pfks_level: DecompositionLevelCount(1),
    pfks_base_log: DecompositionBaseLog(23),
    pfks_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
    cbs_level: DecompositionLevelCount(0),
    cbs_base_log: DecompositionBaseLog(0),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(2),
};
pub const PARAM_MESSAGE_5_CARRY_0: Parameters = Parameters {
    lwe_dimension: LweDimension(754),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_modular_std_dev: StandardDev(0.0000056757818866051225),
    glwe_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(5),
    ks_base_log: DecompositionBaseLog(3),
    pfks_level: DecompositionLevelCount(1),
    pfks_base_log: DecompositionBaseLog(23),
    pfks_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
    cbs_level: DecompositionLevelCount(0),
    cbs_base_log: DecompositionBaseLog(0),
    message_modulus: MessageModulus(32),
    carry_modulus: CarryModulus(1),
};
pub const PARAM_MESSAGE_1_CARRY_5: Parameters = Parameters {
    lwe_dimension: LweDimension(824),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_modular_std_dev: StandardDev(0.0000015762180593038625),
    glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(5),
    ks_base_log: DecompositionBaseLog(3),
    pfks_level: DecompositionLevelCount(2),
    pfks_base_log: DecompositionBaseLog(15),
    pfks_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    cbs_level: DecompositionLevelCount(0),
    cbs_base_log: DecompositionBaseLog(0),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(32),
};
pub const PARAM_MESSAGE_2_CARRY_4: Parameters = Parameters {
    lwe_dimension: LweDimension(824),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_modular_std_dev: StandardDev(0.0000015762180593038625),
    glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(5),
    ks_base_log: DecompositionBaseLog(3),
    pfks_level: DecompositionLevelCount(2),
    pfks_base_log: DecompositionBaseLog(15),
    pfks_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    cbs_level: DecompositionLevelCount(0),
    cbs_base_log: DecompositionBaseLog(0),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(16),
};
pub const PARAM_MESSAGE_3_CARRY_3: Parameters = Parameters {
    lwe_dimension: LweDimension(873),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_modular_std_dev: StandardDev(0.0000006428797112843789),
    glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(4),
    ks_base_log: DecompositionBaseLog(4),
    pfks_level: DecompositionLevelCount(1),
    pfks_base_log: DecompositionBaseLog(23),
    pfks_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    cbs_level: DecompositionLevelCount(0),
    cbs_base_log: DecompositionBaseLog(0),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
};
pub const PARAM_MESSAGE_4_CARRY_2: Parameters = Parameters {
    lwe_dimension: LweDimension(850),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_modular_std_dev: StandardDev(0.0000009793771134612522),
    glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(4),
    ks_base_log: DecompositionBaseLog(4),
    pfks_level: DecompositionLevelCount(1),
    pfks_base_log: DecompositionBaseLog(23),
    pfks_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    cbs_level: DecompositionLevelCount(0),
    cbs_base_log: DecompositionBaseLog(0),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(4),
};
pub const PARAM_MESSAGE_5_CARRY_1: Parameters = Parameters {
    lwe_dimension: LweDimension(848),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_modular_std_dev: StandardDev(0.0000010158915837729808),
    glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(4),
    ks_base_log: DecompositionBaseLog(4),
    pfks_level: DecompositionLevelCount(1),
    pfks_base_log: DecompositionBaseLog(23),
    pfks_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    cbs_level: DecompositionLevelCount(0),
    cbs_base_log: DecompositionBaseLog(0),
    message_modulus: MessageModulus(32),
    carry_modulus: CarryModulus(2),
};
pub const PARAM_MESSAGE_6_CARRY_0: Parameters = Parameters {
    lwe_dimension: LweDimension(847),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_modular_std_dev: StandardDev(0.0000010346562084806),
    glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(4),
    ks_base_log: DecompositionBaseLog(4),
    pfks_level: DecompositionLevelCount(1),
    pfks_base_log: DecompositionBaseLog(23),
    pfks_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    cbs_level: DecompositionLevelCount(0),
    cbs_base_log: DecompositionBaseLog(0),
    message_modulus: MessageModulus(64),
    carry_modulus: CarryModulus(1),
};
pub const PARAM_MESSAGE_1_CARRY_6: Parameters = Parameters {
    lwe_dimension: LweDimension(879),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_modular_std_dev: StandardDev(0.0000005760198979100338),
    glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(6),
    ks_base_log: DecompositionBaseLog(3),
    pfks_level: DecompositionLevelCount(2),
    pfks_base_log: DecompositionBaseLog(15),
    pfks_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    cbs_level: DecompositionLevelCount(0),
    cbs_base_log: DecompositionBaseLog(0),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(64),
};
pub const PARAM_MESSAGE_2_CARRY_5: Parameters = Parameters {
    lwe_dimension: LweDimension(878),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_modular_std_dev: StandardDev(0.0000005866596131917157),
    glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(6),
    ks_base_log: DecompositionBaseLog(3),
    pfks_level: DecompositionLevelCount(2),
    pfks_base_log: DecompositionBaseLog(15),
    pfks_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    cbs_level: DecompositionLevelCount(0),
    cbs_base_log: DecompositionBaseLog(0),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(32),
};
pub const PARAM_MESSAGE_3_CARRY_4: Parameters = Parameters {
    lwe_dimension: LweDimension(877),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_modular_std_dev: StandardDev(0.0000005974958556101962),
    glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(6),
    ks_base_log: DecompositionBaseLog(3),
    pfks_level: DecompositionLevelCount(2),
    pfks_base_log: DecompositionBaseLog(15),
    pfks_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    cbs_level: DecompositionLevelCount(0),
    cbs_base_log: DecompositionBaseLog(0),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(16),
};
pub const PARAM_MESSAGE_4_CARRY_3: Parameters = Parameters {
    lwe_dimension: LweDimension(877),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_modular_std_dev: StandardDev(0.0000005974958556101962),
    glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(6),
    ks_base_log: DecompositionBaseLog(3),
    pfks_level: DecompositionLevelCount(2),
    pfks_base_log: DecompositionBaseLog(15),
    pfks_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    cbs_level: DecompositionLevelCount(0),
    cbs_base_log: DecompositionBaseLog(0),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(8),
};
pub const PARAM_MESSAGE_5_CARRY_2: Parameters = Parameters {
    lwe_dimension: LweDimension(877),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_modular_std_dev: StandardDev(0.0000005974958556101962),
    glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(6),
    ks_base_log: DecompositionBaseLog(3),
    pfks_level: DecompositionLevelCount(2),
    pfks_base_log: DecompositionBaseLog(15),
    pfks_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    cbs_level: DecompositionLevelCount(0),
    cbs_base_log: DecompositionBaseLog(0),
    message_modulus: MessageModulus(32),
    carry_modulus: CarryModulus(4),
};
pub const PARAM_MESSAGE_6_CARRY_1: Parameters = Parameters {
    lwe_dimension: LweDimension(893),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_modular_std_dev: StandardDev(0.0000004458159540199854),
    glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(6),
    ks_base_log: DecompositionBaseLog(3),
    pfks_level: DecompositionLevelCount(1),
    pfks_base_log: DecompositionBaseLog(23),
    pfks_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    cbs_level: DecompositionLevelCount(0),
    cbs_base_log: DecompositionBaseLog(0),
    message_modulus: MessageModulus(64),
    carry_modulus: CarryModulus(2),
};
pub const PARAM_MESSAGE_7_CARRY_0: Parameters = Parameters {
    lwe_dimension: LweDimension(880),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_modular_std_dev: StandardDev(0.0000005655731455300567),
    glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(6),
    ks_base_log: DecompositionBaseLog(3),
    pfks_level: DecompositionLevelCount(1),
    pfks_base_log: DecompositionBaseLog(23),
    pfks_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    cbs_level: DecompositionLevelCount(0),
    cbs_base_log: DecompositionBaseLog(0),
    message_modulus: MessageModulus(128),
    carry_modulus: CarryModulus(1),
};
pub const PARAM_MESSAGE_1_CARRY_7: Parameters = Parameters {
    lwe_dimension: LweDimension(954),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_modular_std_dev: StandardDev(0.00000014597704188641654),
    glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_level: DecompositionLevelCount(6),
    ks_base_log: DecompositionBaseLog(3),
    pfks_level: DecompositionLevelCount(3),
    pfks_base_log: DecompositionBaseLog(11),
    pfks_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    cbs_level: DecompositionLevelCount(0),
    cbs_base_log: DecompositionBaseLog(0),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(128),
};
pub const PARAM_MESSAGE_2_CARRY_6: Parameters = Parameters {
    lwe_dimension: LweDimension(991),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_modular_std_dev: StandardDev(0.00000007416217327637463),
    glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(5),
    ks_base_log: DecompositionBaseLog(4),
    pfks_level: DecompositionLevelCount(2),
    pfks_base_log: DecompositionBaseLog(15),
    pfks_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    cbs_level: DecompositionLevelCount(0),
    cbs_base_log: DecompositionBaseLog(0),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(64),
};
pub const PARAM_MESSAGE_3_CARRY_5: Parameters = Parameters {
    lwe_dimension: LweDimension(973),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_modular_std_dev: StandardDev(0.00000010310011520238092),
    glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(5),
    ks_base_log: DecompositionBaseLog(4),
    pfks_level: DecompositionLevelCount(2),
    pfks_base_log: DecompositionBaseLog(15),
    pfks_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    cbs_level: DecompositionLevelCount(0),
    cbs_base_log: DecompositionBaseLog(0),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(32),
};
pub const PARAM_MESSAGE_4_CARRY_4: Parameters = Parameters {
    lwe_dimension: LweDimension(953),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_modular_std_dev: StandardDev(0.0000001486733969411098),
    glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(6),
    ks_base_log: DecompositionBaseLog(3),
    pfks_level: DecompositionLevelCount(2),
    pfks_base_log: DecompositionBaseLog(15),
    pfks_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    cbs_level: DecompositionLevelCount(0),
    cbs_base_log: DecompositionBaseLog(0),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
};
pub const PARAM_MESSAGE_5_CARRY_3: Parameters = Parameters {
    lwe_dimension: LweDimension(952),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_modular_std_dev: StandardDev(0.00000015141955661224835),
    glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(6),
    ks_base_log: DecompositionBaseLog(3),
    pfks_level: DecompositionLevelCount(2),
    pfks_base_log: DecompositionBaseLog(15),
    pfks_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    cbs_level: DecompositionLevelCount(0),
    cbs_base_log: DecompositionBaseLog(0),
    message_modulus: MessageModulus(32),
    carry_modulus: CarryModulus(8),
};
pub const PARAM_MESSAGE_6_CARRY_2: Parameters = Parameters {
    lwe_dimension: LweDimension(952),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_modular_std_dev: StandardDev(0.00000015141955661224835),
    glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(6),
    ks_base_log: DecompositionBaseLog(3),
    pfks_level: DecompositionLevelCount(2),
    pfks_base_log: DecompositionBaseLog(15),
    pfks_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    cbs_level: DecompositionLevelCount(0),
    cbs_base_log: DecompositionBaseLog(0),
    message_modulus: MessageModulus(64),
    carry_modulus: CarryModulus(4),
};
pub const PARAM_MESSAGE_7_CARRY_1: Parameters = Parameters {
    lwe_dimension: LweDimension(952),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_modular_std_dev: StandardDev(0.00000015141955661224835),
    glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(6),
    ks_base_log: DecompositionBaseLog(3),
    pfks_level: DecompositionLevelCount(2),
    pfks_base_log: DecompositionBaseLog(15),
    pfks_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    cbs_level: DecompositionLevelCount(0),
    cbs_base_log: DecompositionBaseLog(0),
    message_modulus: MessageModulus(128),
    carry_modulus: CarryModulus(2),
};
pub const PARAM_MESSAGE_8_CARRY_0: Parameters = Parameters {
    lwe_dimension: LweDimension(952),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_modular_std_dev: StandardDev(0.00000015141955661224835),
    glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(6),
    ks_base_log: DecompositionBaseLog(3),
    pfks_level: DecompositionLevelCount(2),
    pfks_base_log: DecompositionBaseLog(15),
    pfks_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    cbs_level: DecompositionLevelCount(0),
    cbs_base_log: DecompositionBaseLog(0),
    message_modulus: MessageModulus(256),
    carry_modulus: CarryModulus(1),
};

/// Return a parameter set from a message and carry moduli.
///
/// # Example
///
/// ```rust
/// use tfhe::shortint::parameters::{
///     get_parameters_from_message_and_carry, PARAM_MESSAGE_3_CARRY_1,
/// };
/// let message_space = 7;
/// let carry_space = 2;
/// let param = get_parameters_from_message_and_carry(message_space, carry_space);
/// assert_eq!(param, PARAM_MESSAGE_3_CARRY_1);
/// ```
pub fn get_parameters_from_message_and_carry(msg_space: usize, carry_space: usize) -> Parameters {
    let mut out = Parameters::default();
    let mut flag: bool = false;
    let mut rescaled_message_space = f64::ceil(f64::log2(msg_space as f64)) as usize;
    rescaled_message_space = 1 << rescaled_message_space;
    let mut rescaled_carry_space = f64::ceil(f64::log2(carry_space as f64)) as usize;
    rescaled_carry_space = 1 << rescaled_carry_space;

    for param in ALL_PARAMETER_VEC {
        if param.message_modulus.0 == rescaled_message_space
            && param.carry_modulus.0 == rescaled_carry_space
        {
            out = param;
            flag = true;
            break;
        }
    }
    if !flag {
        println!(
            "### WARNING: NO PARAMETERS FOUND for msg_space = {} and carry_space = {} ### ",
            rescaled_message_space, rescaled_carry_space
        );
    }
    out
}
