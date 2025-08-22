#![allow(clippy::excessive_precision)]
//! Module with the definition of cryptographic parameters.
//!
//! This module provides the structure containing the cryptographic parameters required for the
//! homomorphic evaluation of integer circuits as well as a list of secure cryptographic parameter
//! sets.

pub use crate::core_crypto::commons::dispersion::{DispersionParameter, StandardDev};
pub use crate::core_crypto::commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
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
    pub unsafe fn new(
        lwe_dimension: LweDimension,
        glwe_dimension: GlweDimension,
        polynomial_size: PolynomialSize,
        lwe_modular_std_dev: StandardDev,
        glwe_modular_std_dev: StandardDev,
        pbs_base_log: DecompositionBaseLog,
        pbs_level: DecompositionLevelCount,
        ks_base_log: DecompositionBaseLog,
        ks_level: DecompositionLevelCount,
        pfks_modular_std_dev: StandardDev,
        pfks_base_log: DecompositionBaseLog,
        pfks_level: DecompositionLevelCount,
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
/// All parameter sets guarantee 128-bits of security and an error probability smaller than
/// 2^{-40} for a PBS.
pub const PARAM_MESSAGE_1_CARRY_0: Parameters = Parameters {
    lwe_dimension: LweDimension(678),
    glwe_dimension: GlweDimension(5),
    polynomial_size: PolynomialSize(256),
    lwe_modular_std_dev: StandardDev(0.000022810107419132102),
    glwe_modular_std_dev: StandardDev(0.00000000037411618952047216),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(5),
    pfks_level: DecompositionLevelCount(1),
    pfks_base_log: DecompositionBaseLog(15),
    pfks_modular_std_dev: StandardDev(0.00000000037411618952047216),
    cbs_level: DecompositionLevelCount(0),
    cbs_base_log: DecompositionBaseLog(0),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(1),
};
pub const PARAM_MESSAGE_1_CARRY_1: Parameters = Parameters {
    lwe_dimension: LweDimension(684),
    glwe_dimension: GlweDimension(3),
    polynomial_size: PolynomialSize(512),
    lwe_modular_std_dev: StandardDev(0.00002043784477291318),
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
    lwe_dimension: LweDimension(656),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(512),
    lwe_modular_std_dev: StandardDev(0.000034119201269311964),
    glwe_modular_std_dev: StandardDev(0.00000004053919869756513),
    pbs_base_log: DecompositionBaseLog(8),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(4),
    ks_base_log: DecompositionBaseLog(3),
    pfks_level: DecompositionLevelCount(1),
    pfks_base_log: DecompositionBaseLog(15),
    pfks_modular_std_dev: StandardDev(0.00000000037411618952047216),
    cbs_level: DecompositionLevelCount(0),
    cbs_base_log: DecompositionBaseLog(0),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(1),
};
pub const PARAM_MESSAGE_1_CARRY_2: Parameters = Parameters {
    lwe_dimension: LweDimension(742),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_modular_std_dev: StandardDev(0.000007069849454709433),
    glwe_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(4),
    pfks_level: DecompositionLevelCount(1),
    pfks_base_log: DecompositionBaseLog(18),
    pfks_modular_std_dev: StandardDev(0.0000000000034525330484572114),
    cbs_level: DecompositionLevelCount(0),
    cbs_base_log: DecompositionBaseLog(0),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(4),
};
pub const PARAM_MESSAGE_2_CARRY_1: Parameters = Parameters {
    lwe_dimension: LweDimension(742),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_modular_std_dev: StandardDev(0.000007069849454709433),
    glwe_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
    pbs_base_log: DecompositionBaseLog(23),
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
    lwe_dimension: LweDimension(742),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_modular_std_dev: StandardDev(0.000007069849454709433),
    glwe_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
    pbs_base_log: DecompositionBaseLog(23),
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
    lwe_dimension: LweDimension(745),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_modular_std_dev: StandardDev(0.000006692125069956277),
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
    carry_modulus: CarryModulus(8),
};
pub const PARAM_MESSAGE_2_CARRY_2: Parameters = Parameters {
    lwe_dimension: LweDimension(742),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_modular_std_dev: StandardDev(0.000007069849454709433),
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
    carry_modulus: CarryModulus(4),
};
pub const PARAM_MESSAGE_3_CARRY_1: Parameters = Parameters {
    lwe_dimension: LweDimension(742),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_modular_std_dev: StandardDev(0.000007069849454709433),
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
    carry_modulus: CarryModulus(2),
};
pub const PARAM_MESSAGE_4_CARRY_0: Parameters = Parameters {
    lwe_dimension: LweDimension(742),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_modular_std_dev: StandardDev(0.000007069849454709433),
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
    carry_modulus: CarryModulus(1),
};
pub const PARAM_MESSAGE_1_CARRY_4: Parameters = Parameters {
    lwe_dimension: LweDimension(807),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_modular_std_dev: StandardDev(0.0000021515145918907506),
    glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
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
    lwe_dimension: LweDimension(856),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_modular_std_dev: StandardDev(0.0000008775214009854235),
    glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(6),
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
    lwe_dimension: LweDimension(812),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_modular_std_dev: StandardDev(0.0000019633637461248447),
    glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    pbs_base_log: DecompositionBaseLog(22),
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
    lwe_dimension: LweDimension(808),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_modular_std_dev: StandardDev(0.0000021124945159091033),
    glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    pbs_base_log: DecompositionBaseLog(22),
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
    lwe_dimension: LweDimension(807),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_modular_std_dev: StandardDev(0.0000021515145918907506),
    glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    pbs_base_log: DecompositionBaseLog(22),
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
    lwe_dimension: LweDimension(864),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_modular_std_dev: StandardDev(0.000000757998020150446),
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
    carry_modulus: CarryModulus(32),
};
pub const PARAM_MESSAGE_2_CARRY_4: Parameters = Parameters {
    lwe_dimension: LweDimension(864),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_modular_std_dev: StandardDev(0.000000757998020150446),
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
    carry_modulus: CarryModulus(16),
};
pub const PARAM_MESSAGE_3_CARRY_3: Parameters = Parameters {
    lwe_dimension: LweDimension(864),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_modular_std_dev: StandardDev(0.000000757998020150446),
    glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(6),
    ks_base_log: DecompositionBaseLog(3),
    pfks_level: DecompositionLevelCount(1),
    pfks_base_log: DecompositionBaseLog(23),
    pfks_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    cbs_level: DecompositionLevelCount(0),
    cbs_base_log: DecompositionBaseLog(0),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
};
pub const PARAM_MESSAGE_4_CARRY_2: Parameters = Parameters {
    lwe_dimension: LweDimension(864),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_modular_std_dev: StandardDev(0.000000757998020150446),
    glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(6),
    ks_base_log: DecompositionBaseLog(3),
    pfks_level: DecompositionLevelCount(1),
    pfks_base_log: DecompositionBaseLog(23),
    pfks_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    cbs_level: DecompositionLevelCount(0),
    cbs_base_log: DecompositionBaseLog(0),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(4),
};
pub const PARAM_MESSAGE_5_CARRY_1: Parameters = Parameters {
    lwe_dimension: LweDimension(875),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_modular_std_dev: StandardDev(0.0000006197725091905067),
    glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(6),
    ks_base_log: DecompositionBaseLog(3),
    pfks_level: DecompositionLevelCount(1),
    pfks_base_log: DecompositionBaseLog(23),
    pfks_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    cbs_level: DecompositionLevelCount(0),
    cbs_base_log: DecompositionBaseLog(0),
    message_modulus: MessageModulus(32),
    carry_modulus: CarryModulus(2),
};
pub const PARAM_MESSAGE_6_CARRY_0: Parameters = Parameters {
    lwe_dimension: LweDimension(915),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_modular_std_dev: StandardDev(0.00000029804653749339636),
    glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    pbs_base_log: DecompositionBaseLog(22),
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
    lwe_dimension: LweDimension(930),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_modular_std_dev: StandardDev(0.00000022649232786295453),
    glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
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
    lwe_dimension: LweDimension(934),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_modular_std_dev: StandardDev(0.00000021050318566634375),
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
    lwe_dimension: LweDimension(930),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_modular_std_dev: StandardDev(0.00000022649232786295453),
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
    lwe_dimension: LweDimension(930),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_modular_std_dev: StandardDev(0.00000022649232786295453),
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
    lwe_dimension: LweDimension(930),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_modular_std_dev: StandardDev(0.00000022649232786295453),
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
    lwe_dimension: LweDimension(930),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_modular_std_dev: StandardDev(0.00000022649232786295453),
    glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
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
    lwe_dimension: LweDimension(930),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_modular_std_dev: StandardDev(0.00000022649232786295453),
    glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
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
    lwe_dimension: LweDimension(1004),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_modular_std_dev: StandardDev(0.00000005845871624688967),
    glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_level: DecompositionLevelCount(7),
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
    lwe_dimension: LweDimension(987),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_modular_std_dev: StandardDev(0.00000007979529246348835),
    glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_level: DecompositionLevelCount(7),
    ks_base_log: DecompositionBaseLog(3),
    pfks_level: DecompositionLevelCount(2),
    pfks_base_log: DecompositionBaseLog(15),
    pfks_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    cbs_level: DecompositionLevelCount(0),
    cbs_base_log: DecompositionBaseLog(0),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(64),
};
pub const PARAM_MESSAGE_3_CARRY_5: Parameters = Parameters {
    lwe_dimension: LweDimension(985),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_modular_std_dev: StandardDev(0.00000008277032914509569),
    glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_level: DecompositionLevelCount(7),
    ks_base_log: DecompositionBaseLog(3),
    pfks_level: DecompositionLevelCount(2),
    pfks_base_log: DecompositionBaseLog(15),
    pfks_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    cbs_level: DecompositionLevelCount(0),
    cbs_base_log: DecompositionBaseLog(0),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(32),
};
pub const PARAM_MESSAGE_4_CARRY_4: Parameters = Parameters {
    lwe_dimension: LweDimension(996),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_modular_std_dev: StandardDev(0.00000006767666038309478),
    glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(7),
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
    lwe_dimension: LweDimension(1020),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_modular_std_dev: StandardDev(0.000000043618425315728666),
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
    message_modulus: MessageModulus(32),
    carry_modulus: CarryModulus(8),
};
pub const PARAM_MESSAGE_6_CARRY_2: Parameters = Parameters {
    lwe_dimension: LweDimension(1018),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_modular_std_dev: StandardDev(0.000000045244666805696514),
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
    message_modulus: MessageModulus(64),
    carry_modulus: CarryModulus(4),
};
pub const PARAM_MESSAGE_7_CARRY_1: Parameters = Parameters {
    lwe_dimension: LweDimension(1017),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_modular_std_dev: StandardDev(0.0000000460803851108693),
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
    message_modulus: MessageModulus(128),
    carry_modulus: CarryModulus(2),
};
pub const PARAM_MESSAGE_8_CARRY_0: Parameters = Parameters {
    lwe_dimension: LweDimension(1017),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_modular_std_dev: StandardDev(0.0000000460803851108693),
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
    message_modulus: MessageModulus(256),
    carry_modulus: CarryModulus(1),
};

pub const PARAM_SMALL_MESSAGE_1_CARRY_1: Parameters = Parameters {
    lwe_dimension: LweDimension(783),
    glwe_dimension: GlweDimension(3),
    polynomial_size: PolynomialSize(512),
    lwe_modular_std_dev: StandardDev(0.0000033382067621812462),
    glwe_modular_std_dev: StandardDev(0.0000000000034525330484572114),
    pbs_base_log: DecompositionBaseLog(18),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(5),
    pfks_level: DecompositionLevelCount(0),
    pfks_base_log: DecompositionBaseLog(0),
    pfks_modular_std_dev: StandardDev(0.0000000000034525330484572114),
    cbs_level: DecompositionLevelCount(0),
    cbs_base_log: DecompositionBaseLog(0),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
};

pub const PARAM_SMALL_MESSAGE_2_CARRY_2: Parameters = Parameters {
    lwe_dimension: LweDimension(870),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_modular_std_dev: StandardDev(0.0000006791658447437413),
    glwe_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(4),
    ks_base_log: DecompositionBaseLog(4),
    pfks_level: DecompositionLevelCount(0),
    pfks_base_log: DecompositionBaseLog(0),
    pfks_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
    cbs_level: DecompositionLevelCount(0),
    cbs_base_log: DecompositionBaseLog(0),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
};

pub const PARAM_SMALL_MESSAGE_3_CARRY_3: Parameters = Parameters {
    lwe_dimension: LweDimension(1025),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_modular_std_dev: StandardDev(0.00000003980397588319241),
    glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(5),
    ks_base_log: DecompositionBaseLog(4),
    pfks_level: DecompositionLevelCount(0),
    pfks_base_log: DecompositionBaseLog(0),
    pfks_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    cbs_level: DecompositionLevelCount(0),
    cbs_base_log: DecompositionBaseLog(0),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
};

pub const PARAM_SMALL_MESSAGE_4_CARRY_4: Parameters = Parameters {
    lwe_dimension: LweDimension(1214),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_modular_std_dev: StandardDev(0.0000000012520482863081104),
    glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(6),
    ks_base_log: DecompositionBaseLog(4),
    pfks_level: DecompositionLevelCount(0),
    pfks_base_log: DecompositionBaseLog(0),
    pfks_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    cbs_level: DecompositionLevelCount(0),
    cbs_base_log: DecompositionBaseLog(0),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
};

pub const PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64: Parameters =
    Parameters {
        lwe_dimension: LweDimension(879),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(4096),
        lwe_modular_std_dev: StandardDev(0.0000006791658447437413),
        glwe_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
        pbs_base_log: DecompositionBaseLog(23),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(5),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(4),
        pfks_level: DecompositionLevelCount(0),
        pfks_base_log: DecompositionBaseLog(0),
        pfks_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
        cbs_level: DecompositionLevelCount(0),
        cbs_base_log: DecompositionBaseLog(0),
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
            "### WARNING: NO PARAMETERS FOUND for msg_space = {rescaled_message_space} and \
            carry_space = {rescaled_carry_space} ### "
        );
    }
    out
}
