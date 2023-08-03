//! The cryptographic parameter set.
//!
//! This module provides the structure containing the cryptographic parameters required for the
//! homomorphic evaluation of Boolean circuit as well as a list of secure cryptographic parameter
//! sets.
//!
//! Two parameter sets are provided:
//!  * `tfhe::boolean::parameters::DEFAULT_PARAMETERS`
//!  * `tfhe::boolean::parameters::TFHE_LIB_PARAMETERS`
//!
//! They ensure the correctness of the Boolean circuit evaluation result (up to a certain
//! probability) along with 128-bits of security.
//!
//! The two parameter sets offer a trade-off in terms of execution time versus error probability.
//! The `DEFAULT_PARAMETERS` set offers better performances on homomorphic circuit evaluation
//! with an higher probability error in comparison with the `TFHE_LIB_PARAMETERS`.
//! Note that if you desire, you can also create your own set of parameters.
//! Failing to properly fix the parameters will potentially result with an incorrect and/or insecure
//! computation.

pub use crate::core_crypto::commons::dispersion::StandardDev;
pub use crate::core_crypto::commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
};
use serde::{Deserialize, Serialize};

/// A set of cryptographic parameters for homomorphic Boolean circuit evaluation.
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BooleanParameters {
    pub lwe_dimension: LweDimension,
    pub glwe_dimension: GlweDimension,
    pub polynomial_size: PolynomialSize,
    pub lwe_modular_std_dev: StandardDev,
    pub glwe_modular_std_dev: StandardDev,
    pub pbs_base_log: DecompositionBaseLog,
    pub pbs_level: DecompositionLevelCount,
    pub ks_base_log: DecompositionBaseLog,
    pub ks_level: DecompositionLevelCount,
}

impl BooleanParameters {
    /// Constructs a new set of parameters for boolean circuit evaluation.
    ///
    /// # Warning
    ///
    /// Failing to fix the parameters properly would yield incorrect and insecure computation.
    /// Unless you are a cryptographer who really knows the impact of each of those parameters, you
    /// __must__ stick with the provided parameters [`DEFAULT_PARAMETERS`] and
    /// [`TFHE_LIB_PARAMETERS`], which both offer correct results with 128 bits of security.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lwe_dimension: LweDimension,
        glwe_dimension: GlweDimension,
        polynomial_size: PolynomialSize,
        lwe_modular_std_dev: StandardDev,
        glwe_modular_std_dev: StandardDev,
        pbs_base_log: DecompositionBaseLog,
        pbs_level: DecompositionLevelCount,
        ks_base_log: DecompositionBaseLog,
        ks_level: DecompositionLevelCount,
    ) -> BooleanParameters {
        BooleanParameters {
            lwe_dimension,
            glwe_dimension,
            polynomial_size,
            lwe_modular_std_dev,
            glwe_modular_std_dev,
            pbs_base_log,
            pbs_level,
            ks_level,
            ks_base_log,
        }
    }
}

/// A set of cryptographic parameters for homomorphic Boolean key switching.
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BooleanKeySwitchingParameters {
    pub ks_base_log: DecompositionBaseLog,
    pub ks_level: DecompositionLevelCount,
}
impl BooleanKeySwitchingParameters {
    /// Constructs a new set of parameters for boolean circuit evaluation.
    ///
    /// # Warning
    ///
    /// Failing to fix the parameters properly would yield incorrect and insecure computation.
    /// Unless you are a cryptographer who really knows the impact of each of those parameters,
    /// you __must__ stick with the provided parameters (if any), which both offer correct
    /// results with 128 bits of security.
    pub fn new(
        ks_base_log: DecompositionBaseLog,
        ks_level: DecompositionLevelCount,
    ) -> BooleanKeySwitchingParameters {
        BooleanKeySwitchingParameters {
            ks_level,
            ks_base_log,
        }
    }
}

/// Default parameter set.
///
/// This parameter set ensures 128-bits of security, and a probability of error is upper-bounded by
/// $2^{-40}$. The secret keys generated with this parameter set are uniform binary.
/// This parameter set allows to evaluate faster Boolean circuits than the `TFHE_LIB_PARAMETERS`
/// one.
pub const DEFAULT_PARAMETERS: BooleanParameters = BooleanParameters {
    lwe_dimension: LweDimension(722),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(512),
    lwe_modular_std_dev: StandardDev(0.000013071021089943935),
    glwe_modular_std_dev: StandardDev(0.00000004990272175010415),
    pbs_base_log: DecompositionBaseLog(6),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(4),
};

/// The secret keys generated with this parameter set are uniform binary.
/// This parameter set ensures a probability of error upper-bounded by $2^{-165}$ as the ones
/// proposed into [TFHE library](https://tfhe.github.io/tfhe/) for for 128-bits of security.
/// They are updated to the last security standards, so they differ from the original
/// publication.
pub const TFHE_LIB_PARAMETERS: BooleanParameters = BooleanParameters {
    lwe_dimension: LweDimension(767),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_modular_std_dev: StandardDev(0.000005104350373791501),
    glwe_modular_std_dev: StandardDev(0.0000000009313225746154785),
    pbs_base_log: DecompositionBaseLog(10),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
};
