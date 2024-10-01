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

pub mod params;

pub use crate::core_crypto::commons::dispersion::StandardDev;
pub use crate::core_crypto::commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, DynamicDistribution, EncryptionKeyChoice,
    GlweDimension, LweDimension, PolynomialSize,
};
pub use params::*;

use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

use super::backward_compatibility::parameters::{
    BooleanKeySwitchingParametersVersions, BooleanParametersVersions,
};

/// A set of cryptographic parameters for homomorphic Boolean circuit evaluation.
/// The choice of encryption key for (`boolean ciphertext`)[`super::ciphertext::Ciphertext`].
///
/// * The `Big` choice means the big LWE key derived from the GLWE key is used to encrypt the input
///   ciphertext. This offers better performance but the (`public
///   key`)[`super::public_key::PublicKey`] can be extremely large and in some cases may not fit in
///   memory. When refreshing a ciphertext and/or evaluating a table lookup the PBS is computed
///   first followed by a keyswitch.
/// * The `Small` choice means the small LWE key is used to encrypt the input ciphertext.
///   Performance is not as good as in the `Big` case but (`public
///   key`)[`super::public_key::PublicKey`] sizes are much more manageable and should always fit in
///   memory. When refreshing a ciphertext and/or evaluating a table lookup the keyswitch is
///   computed first followed by a PBS.
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(BooleanParametersVersions)]
pub struct BooleanParameters {
    pub lwe_dimension: LweDimension,
    pub glwe_dimension: GlweDimension,
    pub polynomial_size: PolynomialSize,
    pub lwe_noise_distribution: DynamicDistribution<u32>,
    pub glwe_noise_distribution: DynamicDistribution<u32>,
    pub pbs_base_log: DecompositionBaseLog,
    pub pbs_level: DecompositionLevelCount,
    pub ks_base_log: DecompositionBaseLog,
    pub ks_level: DecompositionLevelCount,
    pub encryption_key_choice: EncryptionKeyChoice,
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
        lwe_noise_distribution: DynamicDistribution<u32>,
        glwe_noise_distribution: DynamicDistribution<u32>,
        pbs_base_log: DecompositionBaseLog,
        pbs_level: DecompositionLevelCount,
        ks_base_log: DecompositionBaseLog,
        ks_level: DecompositionLevelCount,
        encryption_key_choice: EncryptionKeyChoice,
    ) -> Self {
        Self {
            lwe_dimension,
            glwe_dimension,
            polynomial_size,
            lwe_noise_distribution,
            glwe_noise_distribution,
            pbs_base_log,
            pbs_level,
            ks_base_log,
            ks_level,
            encryption_key_choice,
        }
    }
}

/// A set of cryptographic parameters for homomorphic Boolean key switching.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Versionize)]
#[versionize(BooleanKeySwitchingParametersVersions)]
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
    pub fn new(ks_base_log: DecompositionBaseLog, ks_level: DecompositionLevelCount) -> Self {
        Self {
            ks_base_log,
            ks_level,
        }
    }
}

/// Parameter sets given in TFHE-lib:
/// <https://github.com/tfhe/tfhe/blob/bc71bfae7ad9d5f8ce5f29bdfd691189bfe207f3/src/libtfhe/tfhe_gate_bootstrapping.cpp#L51>
///
/// Original security in 2020 was 129-bits, while it is currently around 120 bits.
pub const TFHE_LIB_PARAMETERS: BooleanParameters = BooleanParameters {
    lwe_dimension: LweDimension(630),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.000030517578125,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.00000002980232238769531,
    )),
    pbs_base_log: DecompositionBaseLog(7),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(2),
    ks_level: DecompositionLevelCount(8),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const VEC_BOOLEAN_PARAM: [BooleanParameters; 5] = [
    DEFAULT_PARAMETERS,
    DEFAULT_PARAMETERS_KS_PBS,
    PARAMETERS_ERROR_PROB_2_POW_MINUS_165,
    PARAMETERS_ERROR_PROB_2_POW_MINUS_165_KS_PBS,
    TFHE_LIB_PARAMETERS,
];
