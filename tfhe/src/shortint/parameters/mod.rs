#![allow(clippy::excessive_precision)]
//! Module with the definition of cryptographic parameters.
//!
//! This module provides the structure containing the cryptographic parameters required for the
//! homomorphic evaluation of integer circuits as well as a list of secure cryptographic parameter
//! sets.

use crate::conformance::ListSizeConstraint;
pub use crate::core_crypto::commons::dispersion::StandardDev;
pub use crate::core_crypto::commons::parameters::{
    CiphertextModulus as CoreCiphertextModulus, DecompositionBaseLog, DecompositionLevelCount,
    DynamicDistribution, GlweDimension, LweBskGroupingFactor, LweDimension, PolynomialSize,
};
use crate::core_crypto::prelude::{LweCiphertextListParameters, LweCiphertextParameters};
use crate::shortint::backward_compatibility::parameters::*;
use serde::{Deserialize, Serialize};

use tfhe_versionable::Versionize;

pub mod classic;
#[cfg(tarpaulin)]
pub mod coverage_parameters;
pub mod key_switching;
pub mod multi_bit;
pub mod parameters_wopbs;
pub mod parameters_wopbs_message_carry;
pub mod parameters_wopbs_only;
pub use super::ciphertext::{Degree, MaxNoiseLevel, NoiseLevel};
pub use super::PBSOrder;
pub use crate::core_crypto::commons::parameters::EncryptionKeyChoice;
pub use crate::shortint::parameters::classic::compact_pk::*;
use crate::shortint::parameters::classic::p_fail_2_minus_40::{ks_pbs, pbs_ks};
pub use key_switching::ShortintKeySwitchingParameters;
pub use multi_bit::*;
pub use parameters_wopbs::*;

/// The modulus of the message space. For a given plaintext $p$ we have the message $m$ defined as
/// $m = p\bmod{MessageModulus}$ and so $0 <= m < MessageModulus$.
///
/// # Note
///
/// The total plaintext modulus is given by $MessageModulus \times CarryModulus$
#[derive(Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize, Versionize)]
#[versionize(MessageModulusVersions)]
pub struct MessageModulus(pub usize);

/// The modulus of the carry space. For a given plaintext $p$ we have the carry $c$ defined as
/// $c = \frac{p}{MessageModulus}$ and so $0 <= c < CarryModulus$ as the total plaintext modulus is
/// given by $MessageModulus \times CarryModulus$
///
/// # Note
///
/// The total plaintext modulus is given by $MessageModulus \times CarryModulus$
#[derive(Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize, Versionize)]
#[versionize(CarryModulusVersions)]
pub struct CarryModulus(pub usize);

/// Determines in what ring computations are made
pub type CiphertextModulus = CoreCiphertextModulus<u64>;

/// A structure defining the set of cryptographic parameters for homomorphic integer circuit
/// evaluation.
///
/// The choice of encryption key for (`shortint ciphertext`)[`super::ciphertext::Ciphertext`].
///
/// * The `Big` choice means the big LWE key derived from the GLWE key is used to encrypt the input
///   ciphertext. This offers better performance but the (`public
///   key`)[`super::public_key::PublicKey`] can be extremely large and in some cases may not fit in
///   memory. When refreshing a ciphertext and/or evaluating a table lookup the keyswitch is
///   computed first followed by a PBS, the keyswitch goes from the large key to the small key and
///   the PBS goes from the small key to the large key.
/// * The `Small` choice means the small LWE key is used to encrypt the input ciphertext.
///   Performance is not as good as in the `Big` case but (`public
///   key`)[`super::public_key::PublicKey`] sizes are much more manageable and should always fit in
///   memory. When refreshing a ciphertext and/or evaluating a table lookup the PBS is computed
///   first followed by a keyswitch, the PBS goes from the small key to the large key and the
///   keyswitch goes from the large key to the small key.
#[derive(Serialize, Copy, Clone, Deserialize, Debug, PartialEq, Versionize)]
#[versionize(ClassicPBSParametersVersions)]
pub struct ClassicPBSParameters {
    pub lwe_dimension: LweDimension,
    pub glwe_dimension: GlweDimension,
    pub polynomial_size: PolynomialSize,
    pub lwe_noise_distribution: DynamicDistribution<u64>,
    pub glwe_noise_distribution: DynamicDistribution<u64>,
    pub pbs_base_log: DecompositionBaseLog,
    pub pbs_level: DecompositionLevelCount,
    pub ks_base_log: DecompositionBaseLog,
    pub ks_level: DecompositionLevelCount,
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
    pub max_noise_level: MaxNoiseLevel,
    pub log2_p_fail: f64,
    pub ciphertext_modulus: CiphertextModulus,
    pub encryption_key_choice: EncryptionKeyChoice,
}

impl ClassicPBSParameters {
    /// Constructs a new set of parameters for integer circuit evaluation.
    ///
    /// # Warning
    ///
    /// Failing to fix the parameters properly would yield incorrect and unsecure computation.
    /// Unless you are a cryptographer who really knows the impact of each of those parameters, you
    /// __must__ stick with the provided parameters.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lwe_dimension: LweDimension,
        glwe_dimension: GlweDimension,
        polynomial_size: PolynomialSize,
        lwe_noise_distribution: DynamicDistribution<u64>,
        glwe_noise_distribution: DynamicDistribution<u64>,
        pbs_base_log: DecompositionBaseLog,
        pbs_level: DecompositionLevelCount,
        ks_base_log: DecompositionBaseLog,
        ks_level: DecompositionLevelCount,
        message_modulus: MessageModulus,
        carry_modulus: CarryModulus,
        max_noise_level: MaxNoiseLevel,
        log2_p_fail: f64,
        ciphertext_modulus: CiphertextModulus,
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
            message_modulus,
            carry_modulus,
            max_noise_level,
            log2_p_fail,
            ciphertext_modulus,
            encryption_key_choice,
        }
    }

    pub fn to_shortint_conformance_param(&self) -> CiphertextConformanceParams {
        let (pbs_order, expected_dim) = match self.encryption_key_choice {
            EncryptionKeyChoice::Big => (
                PBSOrder::KeyswitchBootstrap,
                self.glwe_dimension
                    .to_equivalent_lwe_dimension(self.polynomial_size),
            ),
            EncryptionKeyChoice::Small => (PBSOrder::BootstrapKeyswitch, self.lwe_dimension),
        };

        let message_modulus = self.message_modulus;
        let ciphertext_modulus = self.ciphertext_modulus;
        let carry_modulus = self.carry_modulus;

        let degree = Degree::new(message_modulus.0 - 1);

        let noise_level = NoiseLevel::NOMINAL;

        CiphertextConformanceParams {
            ct_params: LweCiphertextParameters {
                lwe_dim: expected_dim,
                ct_modulus: ciphertext_modulus,
            },
            message_modulus,
            carry_modulus,
            pbs_order,
            degree,
            noise_level,
        }
    }
}

#[derive(Serialize, Copy, Clone, Deserialize, Debug, PartialEq, Versionize)]
#[versionize(PBSParametersVersions)]
pub enum PBSParameters {
    PBS(ClassicPBSParameters),
    MultiBitPBS(MultiBitPBSParameters),
}

/// Structure to store the expected properties of a ciphertext
/// Can be used on a server to check if client inputs are well formed
/// before running a computation on them
#[derive(Copy, Clone)]
pub struct CiphertextConformanceParams {
    pub ct_params: LweCiphertextParameters<u64>,
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
    pub degree: Degree,
    pub noise_level: NoiseLevel,
    pub pbs_order: PBSOrder,
}

/// Structure to store the expected properties of a ciphertext list
/// Can be used on a server to check if client inputs are well formed
/// before running a computation on them
pub struct CiphertextListConformanceParams {
    pub ct_list_params: LweCiphertextListParameters<u64>,
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
    pub degree: Degree,
    pub noise_level: NoiseLevel,
    pub pbs_order: PBSOrder,
}

impl CiphertextConformanceParams {
    pub fn to_ct_list_conformance_parameters(
        &self,
        list_constraint: ListSizeConstraint,
    ) -> CiphertextListConformanceParams {
        CiphertextListConformanceParams {
            ct_list_params: LweCiphertextListParameters {
                lwe_dim: self.ct_params.lwe_dim,
                ct_modulus: self.ct_params.ct_modulus,
                lwe_ciphertext_count_constraint: list_constraint,
            },
            message_modulus: self.message_modulus,
            carry_modulus: self.carry_modulus,
            degree: self.degree,
            pbs_order: self.pbs_order,
            noise_level: self.noise_level,
        }
    }
}

impl From<ClassicPBSParameters> for PBSParameters {
    fn from(value: ClassicPBSParameters) -> Self {
        Self::PBS(value)
    }
}

impl From<MultiBitPBSParameters> for PBSParameters {
    fn from(value: MultiBitPBSParameters) -> Self {
        Self::MultiBitPBS(value)
    }
}

impl PBSParameters {
    pub const fn lwe_dimension(&self) -> LweDimension {
        match self {
            Self::PBS(params) => params.lwe_dimension,
            Self::MultiBitPBS(params) => params.lwe_dimension,
        }
    }
    pub const fn glwe_dimension(&self) -> GlweDimension {
        match self {
            Self::PBS(params) => params.glwe_dimension,
            Self::MultiBitPBS(params) => params.glwe_dimension,
        }
    }
    pub const fn polynomial_size(&self) -> PolynomialSize {
        match self {
            Self::PBS(params) => params.polynomial_size,
            Self::MultiBitPBS(params) => params.polynomial_size,
        }
    }
    pub const fn lwe_noise_distribution(&self) -> DynamicDistribution<u64> {
        match self {
            Self::PBS(params) => params.lwe_noise_distribution,
            Self::MultiBitPBS(params) => params.lwe_noise_distribution,
        }
    }
    pub const fn glwe_noise_distribution(&self) -> DynamicDistribution<u64> {
        match self {
            Self::PBS(params) => params.glwe_noise_distribution,
            Self::MultiBitPBS(params) => params.glwe_noise_distribution,
        }
    }
    pub const fn pbs_base_log(&self) -> DecompositionBaseLog {
        match self {
            Self::PBS(params) => params.pbs_base_log,
            Self::MultiBitPBS(params) => params.pbs_base_log,
        }
    }
    pub const fn pbs_level(&self) -> DecompositionLevelCount {
        match self {
            Self::PBS(params) => params.pbs_level,
            Self::MultiBitPBS(params) => params.pbs_level,
        }
    }
    pub const fn ks_base_log(&self) -> DecompositionBaseLog {
        match self {
            Self::PBS(params) => params.ks_base_log,
            Self::MultiBitPBS(params) => params.ks_base_log,
        }
    }
    pub const fn ks_level(&self) -> DecompositionLevelCount {
        match self {
            Self::PBS(params) => params.ks_level,
            Self::MultiBitPBS(params) => params.ks_level,
        }
    }
    pub const fn message_modulus(&self) -> MessageModulus {
        match self {
            Self::PBS(params) => params.message_modulus,
            Self::MultiBitPBS(params) => params.message_modulus,
        }
    }
    pub const fn carry_modulus(&self) -> CarryModulus {
        match self {
            Self::PBS(params) => params.carry_modulus,
            Self::MultiBitPBS(params) => params.carry_modulus,
        }
    }
    pub const fn max_noise_level(&self) -> MaxNoiseLevel {
        match self {
            Self::PBS(params) => params.max_noise_level,
            Self::MultiBitPBS(params) => params.max_noise_level,
        }
    }
    pub const fn ciphertext_modulus(&self) -> CiphertextModulus {
        match self {
            Self::PBS(params) => params.ciphertext_modulus,
            Self::MultiBitPBS(params) => params.ciphertext_modulus,
        }
    }
    pub const fn encryption_key_choice(&self) -> EncryptionKeyChoice {
        match self {
            Self::PBS(params) => params.encryption_key_choice,
            Self::MultiBitPBS(params) => params.encryption_key_choice,
        }
    }
    pub const fn grouping_factor(&self) -> LweBskGroupingFactor {
        match self {
            Self::PBS(_) => {
                panic!("PBSParameters::PBS does not have an LweBskGroupingFactor")
            }
            Self::MultiBitPBS(params) => params.grouping_factor,
        }
    }

    pub const fn is_pbs(&self) -> bool {
        matches!(self, Self::PBS(_))
    }

    pub const fn is_multi_bit_pbs(&self) -> bool {
        matches!(self, Self::MultiBitPBS(_))
    }

    pub fn to_shortint_conformance_param(&self) -> CiphertextConformanceParams {
        match self {
            Self::PBS(param) => param.to_shortint_conformance_param(),
            Self::MultiBitPBS(param) => param.to_shortint_conformance_param(),
        }
    }
}

#[derive(Serialize, Copy, Clone, Deserialize, Debug, PartialEq, Versionize)]
#[versionize(ShortintParameterSetInnerVersions)]
pub(crate) enum ShortintParameterSetInner {
    PBSOnly(PBSParameters),
    WopbsOnly(WopbsParameters),
    PBSAndWopbs(PBSParameters, WopbsParameters),
}

impl ShortintParameterSetInner {
    pub const fn is_pbs_only(&self) -> bool {
        matches!(self, Self::PBSOnly(_))
    }

    pub const fn is_wopbs_only(&self) -> bool {
        matches!(self, Self::WopbsOnly(_))
    }

    pub const fn is_pbs_and_wopbs(&self) -> bool {
        matches!(self, Self::PBSAndWopbs(_, _))
    }
}

#[derive(Serialize, Copy, Clone, Deserialize, Debug, PartialEq, Versionize)]
#[versionize(ShortintParameterSetVersions)]
pub struct ShortintParameterSet {
    inner: ShortintParameterSetInner,
}

impl ShortintParameterSet {
    pub const fn new_pbs_param_set(params: PBSParameters) -> Self {
        Self {
            inner: ShortintParameterSetInner::PBSOnly(params),
        }
    }

    pub const fn new_wopbs_param_set(params: WopbsParameters) -> Self {
        Self {
            inner: ShortintParameterSetInner::WopbsOnly(params),
        }
    }

    pub fn try_new_pbs_and_wopbs_param_set<P>(
        (pbs_params, wopbs_params): (P, WopbsParameters),
    ) -> Result<Self, &'static str>
    where
        P: Into<PBSParameters>,
    {
        let pbs_params: PBSParameters = pbs_params.into();

        if pbs_params.carry_modulus() != wopbs_params.carry_modulus
            || pbs_params.message_modulus() != wopbs_params.message_modulus
            || pbs_params.ciphertext_modulus() != wopbs_params.ciphertext_modulus
            || pbs_params.encryption_key_choice() != wopbs_params.encryption_key_choice
        {
            return Err(
                "Incompatible ClassicPBSParameters and WopbsParameters, this may be due to mismatched \
                carry moduli, message moduli, ciphertext moduli or encryption key choices",
            );
        }
        Ok(Self {
            inner: ShortintParameterSetInner::PBSAndWopbs(pbs_params, wopbs_params),
        })
    }

    pub const fn pbs_parameters(&self) -> Option<PBSParameters> {
        match self.inner {
            ShortintParameterSetInner::PBSOnly(params) => Some(params),
            ShortintParameterSetInner::WopbsOnly(_) => None,
            ShortintParameterSetInner::PBSAndWopbs(params, _) => Some(params),
        }
    }

    pub const fn wopbs_parameters(&self) -> Option<WopbsParameters> {
        match self.inner {
            ShortintParameterSetInner::PBSOnly(_) => None,
            ShortintParameterSetInner::WopbsOnly(params) => Some(params),
            ShortintParameterSetInner::PBSAndWopbs(_, params) => Some(params),
        }
    }

    pub const fn lwe_dimension(&self) -> LweDimension {
        match self.inner {
            ShortintParameterSetInner::PBSOnly(params) => params.lwe_dimension(),
            ShortintParameterSetInner::WopbsOnly(params) => params.lwe_dimension,
            ShortintParameterSetInner::PBSAndWopbs(params, _) => params.lwe_dimension(),
        }
    }

    pub const fn glwe_dimension(&self) -> GlweDimension {
        match self.inner {
            ShortintParameterSetInner::PBSOnly(params) => params.glwe_dimension(),
            ShortintParameterSetInner::WopbsOnly(params) => params.glwe_dimension,
            ShortintParameterSetInner::PBSAndWopbs(params, _) => params.glwe_dimension(),
        }
    }

    pub const fn polynomial_size(&self) -> PolynomialSize {
        match self.inner {
            ShortintParameterSetInner::PBSOnly(params) => params.polynomial_size(),
            ShortintParameterSetInner::WopbsOnly(params) => params.polynomial_size,
            ShortintParameterSetInner::PBSAndWopbs(params, _) => params.polynomial_size(),
        }
    }

    pub const fn lwe_noise_distribution(&self) -> DynamicDistribution<u64> {
        match self.inner {
            ShortintParameterSetInner::PBSOnly(params) => params.lwe_noise_distribution(),
            ShortintParameterSetInner::WopbsOnly(params) => params.lwe_noise_distribution,
            ShortintParameterSetInner::PBSAndWopbs(params, _) => params.lwe_noise_distribution(),
        }
    }

    pub const fn glwe_noise_distribution(&self) -> DynamicDistribution<u64> {
        match self.inner {
            ShortintParameterSetInner::PBSOnly(params) => params.glwe_noise_distribution(),
            ShortintParameterSetInner::WopbsOnly(params) => params.glwe_noise_distribution,
            ShortintParameterSetInner::PBSAndWopbs(params, _) => params.glwe_noise_distribution(),
        }
    }

    pub const fn pbs_base_log(&self) -> DecompositionBaseLog {
        match self.inner {
            ShortintParameterSetInner::PBSOnly(params) => params.pbs_base_log(),
            ShortintParameterSetInner::WopbsOnly(params) => params.pbs_base_log,
            ShortintParameterSetInner::PBSAndWopbs(params, _) => params.pbs_base_log(),
        }
    }

    pub const fn pbs_level(&self) -> DecompositionLevelCount {
        match self.inner {
            ShortintParameterSetInner::PBSOnly(params) => params.pbs_level(),
            ShortintParameterSetInner::WopbsOnly(params) => params.pbs_level,
            ShortintParameterSetInner::PBSAndWopbs(params, _) => params.pbs_level(),
        }
    }

    pub const fn ks_base_log(&self) -> DecompositionBaseLog {
        match self.inner {
            ShortintParameterSetInner::PBSOnly(params) => params.ks_base_log(),
            ShortintParameterSetInner::WopbsOnly(params) => params.ks_base_log,
            ShortintParameterSetInner::PBSAndWopbs(params, _) => params.ks_base_log(),
        }
    }

    pub const fn ks_level(&self) -> DecompositionLevelCount {
        match self.inner {
            ShortintParameterSetInner::PBSOnly(params) => params.ks_level(),
            ShortintParameterSetInner::WopbsOnly(params) => params.ks_level,
            ShortintParameterSetInner::PBSAndWopbs(params, _) => params.ks_level(),
        }
    }

    pub const fn message_modulus(&self) -> MessageModulus {
        match self.inner {
            ShortintParameterSetInner::PBSOnly(params) => params.message_modulus(),
            ShortintParameterSetInner::WopbsOnly(params) => params.message_modulus,
            ShortintParameterSetInner::PBSAndWopbs(params, _) => params.message_modulus(),
        }
    }

    pub const fn carry_modulus(&self) -> CarryModulus {
        match self.inner {
            ShortintParameterSetInner::PBSOnly(params) => params.carry_modulus(),
            ShortintParameterSetInner::WopbsOnly(params) => params.carry_modulus,
            ShortintParameterSetInner::PBSAndWopbs(params, _) => params.carry_modulus(),
        }
    }

    pub const fn max_noise_level(&self) -> MaxNoiseLevel {
        match self.inner {
            ShortintParameterSetInner::PBSOnly(params) => params.max_noise_level(),
            ShortintParameterSetInner::WopbsOnly(_) => {
                panic!("WopbsOnly parameters do not have a MaxNoiseLevel information")
            }
            ShortintParameterSetInner::PBSAndWopbs(params, _) => params.max_noise_level(),
        }
    }

    pub const fn ciphertext_modulus(&self) -> CiphertextModulus {
        match self.inner {
            ShortintParameterSetInner::PBSOnly(params) => params.ciphertext_modulus(),
            ShortintParameterSetInner::WopbsOnly(params) => params.ciphertext_modulus,
            ShortintParameterSetInner::PBSAndWopbs(params, _) => params.ciphertext_modulus(),
        }
    }

    pub const fn encryption_key_choice(&self) -> EncryptionKeyChoice {
        match self.inner {
            ShortintParameterSetInner::PBSOnly(params) => params.encryption_key_choice(),
            ShortintParameterSetInner::WopbsOnly(params) => params.encryption_key_choice,
            ShortintParameterSetInner::PBSAndWopbs(params, _) => params.encryption_key_choice(),
        }
    }

    pub const fn pbs_only(&self) -> bool {
        self.inner.is_pbs_only()
    }

    pub const fn wopbs_only(&self) -> bool {
        self.inner.is_wopbs_only()
    }

    pub const fn pbs_and_wopbs(&self) -> bool {
        self.inner.is_pbs_and_wopbs()
    }
}

impl<P> From<P> for ShortintParameterSet
where
    P: Into<PBSParameters>,
{
    fn from(value: P) -> Self {
        Self::new_pbs_param_set(value.into())
    }
}

impl From<WopbsParameters> for ShortintParameterSet {
    fn from(value: WopbsParameters) -> Self {
        Self::new_wopbs_param_set(value)
    }
}

impl<P> TryFrom<(P, WopbsParameters)> for ShortintParameterSet
where
    P: Into<PBSParameters>,
{
    type Error = &'static str;

    fn try_from(value: (P, WopbsParameters)) -> Result<Self, Self::Error> {
        Self::try_new_pbs_and_wopbs_param_set(value)
    }
}

/// Vector containing all [`ClassicPBSParameters`] parameter sets
pub const ALL_PARAMETER_VEC: [ClassicPBSParameters; 28] = WITH_CARRY_PARAMETERS_VEC;

/// Vector containing all parameter sets where the carry space is strictly greater than one
pub const WITH_CARRY_PARAMETERS_VEC: [ClassicPBSParameters; 28] = [
    PARAM_MESSAGE_1_CARRY_1_KS_PBS,
    PARAM_MESSAGE_1_CARRY_2_KS_PBS,
    PARAM_MESSAGE_1_CARRY_3_KS_PBS,
    PARAM_MESSAGE_1_CARRY_4_KS_PBS,
    PARAM_MESSAGE_1_CARRY_5_KS_PBS,
    PARAM_MESSAGE_1_CARRY_6_KS_PBS,
    PARAM_MESSAGE_1_CARRY_7_KS_PBS,
    PARAM_MESSAGE_2_CARRY_1_KS_PBS,
    PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    PARAM_MESSAGE_2_CARRY_3_KS_PBS,
    PARAM_MESSAGE_2_CARRY_4_KS_PBS,
    PARAM_MESSAGE_2_CARRY_5_KS_PBS,
    PARAM_MESSAGE_2_CARRY_6_KS_PBS,
    PARAM_MESSAGE_3_CARRY_1_KS_PBS,
    PARAM_MESSAGE_3_CARRY_2_KS_PBS,
    PARAM_MESSAGE_3_CARRY_3_KS_PBS,
    PARAM_MESSAGE_3_CARRY_4_KS_PBS,
    PARAM_MESSAGE_3_CARRY_5_KS_PBS,
    PARAM_MESSAGE_4_CARRY_1_KS_PBS,
    PARAM_MESSAGE_4_CARRY_2_KS_PBS,
    PARAM_MESSAGE_4_CARRY_3_KS_PBS,
    PARAM_MESSAGE_4_CARRY_4_KS_PBS,
    PARAM_MESSAGE_5_CARRY_1_KS_PBS,
    PARAM_MESSAGE_5_CARRY_2_KS_PBS,
    PARAM_MESSAGE_5_CARRY_3_KS_PBS,
    PARAM_MESSAGE_6_CARRY_1_KS_PBS,
    PARAM_MESSAGE_6_CARRY_2_KS_PBS,
    PARAM_MESSAGE_7_CARRY_1_KS_PBS,
];

/// Vector containing all parameter sets where the carry space is strictly greater than one
pub const BIVARIATE_PBS_COMPLIANT_PARAMETER_SET_VEC: [ClassicPBSParameters; 16] = [
    PARAM_MESSAGE_1_CARRY_1_KS_PBS,
    PARAM_MESSAGE_1_CARRY_2_KS_PBS,
    PARAM_MESSAGE_1_CARRY_3_KS_PBS,
    PARAM_MESSAGE_1_CARRY_4_KS_PBS,
    PARAM_MESSAGE_1_CARRY_5_KS_PBS,
    PARAM_MESSAGE_1_CARRY_6_KS_PBS,
    PARAM_MESSAGE_1_CARRY_7_KS_PBS,
    PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    PARAM_MESSAGE_2_CARRY_3_KS_PBS,
    PARAM_MESSAGE_2_CARRY_4_KS_PBS,
    PARAM_MESSAGE_2_CARRY_5_KS_PBS,
    PARAM_MESSAGE_2_CARRY_6_KS_PBS,
    PARAM_MESSAGE_3_CARRY_3_KS_PBS,
    PARAM_MESSAGE_3_CARRY_4_KS_PBS,
    PARAM_MESSAGE_3_CARRY_5_KS_PBS,
    PARAM_MESSAGE_4_CARRY_4_KS_PBS,
];

/// Nomenclature: PARAM_MESSAGE_X_CARRY_Y: the message (respectively carry) modulus is
/// encoded over X (reps. Y) bits, i.e., message_modulus = 2^{X} (resp. carry_modulus = 2^{Y}).
/// All parameter sets guarantee 128-bits of security and an error probability smaller than
/// 2^{-40} for a PBS.

/// Return a parameter set from a message and carry moduli.
///
/// # Example
///
/// ```rust
/// use tfhe::shortint::parameters::{
///     get_parameters_from_message_and_carry, PARAM_MESSAGE_3_CARRY_1_KS_PBS,
/// };
/// let message_space = 7;
/// let carry_space = 2;
/// let param = get_parameters_from_message_and_carry(message_space, carry_space);
/// assert_eq!(param, PARAM_MESSAGE_3_CARRY_1_KS_PBS);
/// ```
pub fn get_parameters_from_message_and_carry(
    msg_space: usize,
    carry_space: usize,
) -> ClassicPBSParameters {
    let mut out = PARAM_MESSAGE_2_CARRY_2_KS_PBS;
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

// Aliases, to be deprecated in subsequent versions once we e.g. have the "parameter builder"
pub const PARAM_MESSAGE_1_CARRY_0_KS_PBS: ClassicPBSParameters =
    ks_pbs::PARAM_MESSAGE_1_CARRY_0_KS_PBS_GAUSSIAN_2M40;
pub const PARAM_MESSAGE_1_CARRY_1_KS_PBS: ClassicPBSParameters =
    ks_pbs::PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M40;
pub const PARAM_MESSAGE_1_CARRY_2_KS_PBS: ClassicPBSParameters =
    ks_pbs::PARAM_MESSAGE_1_CARRY_2_KS_PBS_GAUSSIAN_2M40;
pub const PARAM_MESSAGE_1_CARRY_3_KS_PBS: ClassicPBSParameters =
    ks_pbs::PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M40;
pub const PARAM_MESSAGE_1_CARRY_4_KS_PBS: ClassicPBSParameters =
    ks_pbs::PARAM_MESSAGE_1_CARRY_4_KS_PBS_GAUSSIAN_2M40;
pub const PARAM_MESSAGE_1_CARRY_5_KS_PBS: ClassicPBSParameters =
    ks_pbs::PARAM_MESSAGE_1_CARRY_5_KS_PBS_GAUSSIAN_2M40;
pub const PARAM_MESSAGE_1_CARRY_6_KS_PBS: ClassicPBSParameters =
    ks_pbs::PARAM_MESSAGE_1_CARRY_6_KS_PBS_GAUSSIAN_2M40;
pub const PARAM_MESSAGE_1_CARRY_7_KS_PBS: ClassicPBSParameters =
    ks_pbs::PARAM_MESSAGE_1_CARRY_7_KS_PBS_GAUSSIAN_2M40;
pub const PARAM_MESSAGE_2_CARRY_0_KS_PBS: ClassicPBSParameters =
    ks_pbs::PARAM_MESSAGE_2_CARRY_0_KS_PBS_GAUSSIAN_2M40;
pub const PARAM_MESSAGE_2_CARRY_1_KS_PBS: ClassicPBSParameters =
    ks_pbs::PARAM_MESSAGE_2_CARRY_1_KS_PBS_GAUSSIAN_2M40;
pub const PARAM_MESSAGE_2_CARRY_2_KS_PBS: ClassicPBSParameters =
    ks_pbs::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M40;
pub const PARAM_MESSAGE_2_CARRY_3_KS_PBS: ClassicPBSParameters =
    ks_pbs::PARAM_MESSAGE_2_CARRY_3_KS_PBS_GAUSSIAN_2M40;
pub const PARAM_MESSAGE_2_CARRY_4_KS_PBS: ClassicPBSParameters =
    ks_pbs::PARAM_MESSAGE_2_CARRY_4_KS_PBS_GAUSSIAN_2M40;
pub const PARAM_MESSAGE_2_CARRY_5_KS_PBS: ClassicPBSParameters =
    ks_pbs::PARAM_MESSAGE_2_CARRY_5_KS_PBS_GAUSSIAN_2M40;
pub const PARAM_MESSAGE_2_CARRY_6_KS_PBS: ClassicPBSParameters =
    ks_pbs::PARAM_MESSAGE_2_CARRY_6_KS_PBS_GAUSSIAN_2M40;
pub const PARAM_MESSAGE_3_CARRY_0_KS_PBS: ClassicPBSParameters =
    ks_pbs::PARAM_MESSAGE_3_CARRY_0_KS_PBS_GAUSSIAN_2M40;
pub const PARAM_MESSAGE_3_CARRY_1_KS_PBS: ClassicPBSParameters =
    ks_pbs::PARAM_MESSAGE_3_CARRY_1_KS_PBS_GAUSSIAN_2M40;
pub const PARAM_MESSAGE_3_CARRY_2_KS_PBS: ClassicPBSParameters =
    ks_pbs::PARAM_MESSAGE_3_CARRY_2_KS_PBS_GAUSSIAN_2M40;
pub const PARAM_MESSAGE_3_CARRY_3_KS_PBS: ClassicPBSParameters =
    ks_pbs::PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M40;
pub const PARAM_MESSAGE_3_CARRY_4_KS_PBS: ClassicPBSParameters =
    ks_pbs::PARAM_MESSAGE_3_CARRY_4_KS_PBS_GAUSSIAN_2M40;
pub const PARAM_MESSAGE_3_CARRY_5_KS_PBS: ClassicPBSParameters =
    ks_pbs::PARAM_MESSAGE_3_CARRY_5_KS_PBS_GAUSSIAN_2M40;
pub const PARAM_MESSAGE_4_CARRY_0_KS_PBS: ClassicPBSParameters =
    ks_pbs::PARAM_MESSAGE_4_CARRY_0_KS_PBS_GAUSSIAN_2M40;
pub const PARAM_MESSAGE_4_CARRY_1_KS_PBS: ClassicPBSParameters =
    ks_pbs::PARAM_MESSAGE_4_CARRY_1_KS_PBS_GAUSSIAN_2M40;
pub const PARAM_MESSAGE_4_CARRY_2_KS_PBS: ClassicPBSParameters =
    ks_pbs::PARAM_MESSAGE_4_CARRY_2_KS_PBS_GAUSSIAN_2M40;
pub const PARAM_MESSAGE_4_CARRY_3_KS_PBS: ClassicPBSParameters =
    ks_pbs::PARAM_MESSAGE_4_CARRY_3_KS_PBS_GAUSSIAN_2M40;
pub const PARAM_MESSAGE_4_CARRY_4_KS_PBS: ClassicPBSParameters =
    ks_pbs::PARAM_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M40;
pub const PARAM_MESSAGE_5_CARRY_0_KS_PBS: ClassicPBSParameters =
    ks_pbs::PARAM_MESSAGE_5_CARRY_0_KS_PBS_GAUSSIAN_2M40;
pub const PARAM_MESSAGE_5_CARRY_1_KS_PBS: ClassicPBSParameters =
    ks_pbs::PARAM_MESSAGE_5_CARRY_1_KS_PBS_GAUSSIAN_2M40;
pub const PARAM_MESSAGE_5_CARRY_2_KS_PBS: ClassicPBSParameters =
    ks_pbs::PARAM_MESSAGE_5_CARRY_2_KS_PBS_GAUSSIAN_2M40;
pub const PARAM_MESSAGE_5_CARRY_3_KS_PBS: ClassicPBSParameters =
    ks_pbs::PARAM_MESSAGE_5_CARRY_3_KS_PBS_GAUSSIAN_2M40;
pub const PARAM_MESSAGE_6_CARRY_0_KS_PBS: ClassicPBSParameters =
    ks_pbs::PARAM_MESSAGE_6_CARRY_0_KS_PBS_GAUSSIAN_2M40;
pub const PARAM_MESSAGE_6_CARRY_1_KS_PBS: ClassicPBSParameters =
    ks_pbs::PARAM_MESSAGE_6_CARRY_1_KS_PBS_GAUSSIAN_2M40;
pub const PARAM_MESSAGE_6_CARRY_2_KS_PBS: ClassicPBSParameters =
    ks_pbs::PARAM_MESSAGE_6_CARRY_2_KS_PBS_GAUSSIAN_2M40;
pub const PARAM_MESSAGE_7_CARRY_0_KS_PBS: ClassicPBSParameters =
    ks_pbs::PARAM_MESSAGE_7_CARRY_0_KS_PBS_GAUSSIAN_2M40;
pub const PARAM_MESSAGE_7_CARRY_1_KS_PBS: ClassicPBSParameters =
    ks_pbs::PARAM_MESSAGE_7_CARRY_1_KS_PBS_GAUSSIAN_2M40;
pub const PARAM_MESSAGE_8_CARRY_0_KS_PBS: ClassicPBSParameters =
    ks_pbs::PARAM_MESSAGE_8_CARRY_0_KS_PBS_GAUSSIAN_2M40;
pub const PARAM_MESSAGE_1_CARRY_1_PBS_KS: ClassicPBSParameters =
    pbs_ks::PARAM_MESSAGE_1_CARRY_1_PBS_KS_GAUSSIAN_2M40;
pub const PARAM_MESSAGE_2_CARRY_2_PBS_KS: ClassicPBSParameters =
    pbs_ks::PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M40;
pub const PARAM_MESSAGE_3_CARRY_3_PBS_KS: ClassicPBSParameters =
    pbs_ks::PARAM_MESSAGE_3_CARRY_3_PBS_KS_GAUSSIAN_2M40;
pub const PARAM_MESSAGE_4_CARRY_4_PBS_KS: ClassicPBSParameters =
    pbs_ks::PARAM_MESSAGE_4_CARRY_4_PBS_KS_GAUSSIAN_2M40;

pub const PARAM_MESSAGE_1_CARRY_0: ClassicPBSParameters = PARAM_MESSAGE_1_CARRY_0_KS_PBS;
pub const PARAM_MESSAGE_1_CARRY_1: ClassicPBSParameters = PARAM_MESSAGE_1_CARRY_1_KS_PBS;
pub const PARAM_MESSAGE_1_CARRY_2: ClassicPBSParameters = PARAM_MESSAGE_1_CARRY_2_KS_PBS;
pub const PARAM_MESSAGE_1_CARRY_3: ClassicPBSParameters = PARAM_MESSAGE_1_CARRY_3_KS_PBS;
pub const PARAM_MESSAGE_1_CARRY_4: ClassicPBSParameters = PARAM_MESSAGE_1_CARRY_4_KS_PBS;
pub const PARAM_MESSAGE_1_CARRY_5: ClassicPBSParameters = PARAM_MESSAGE_1_CARRY_5_KS_PBS;
pub const PARAM_MESSAGE_1_CARRY_6: ClassicPBSParameters = PARAM_MESSAGE_1_CARRY_6_KS_PBS;
pub const PARAM_MESSAGE_1_CARRY_7: ClassicPBSParameters = PARAM_MESSAGE_1_CARRY_7_KS_PBS;
pub const PARAM_MESSAGE_2_CARRY_0: ClassicPBSParameters = PARAM_MESSAGE_2_CARRY_0_KS_PBS;
pub const PARAM_MESSAGE_2_CARRY_1: ClassicPBSParameters = PARAM_MESSAGE_2_CARRY_1_KS_PBS;
pub const PARAM_MESSAGE_2_CARRY_2: ClassicPBSParameters = PARAM_MESSAGE_2_CARRY_2_KS_PBS;
pub const PARAM_MESSAGE_2_CARRY_3: ClassicPBSParameters = PARAM_MESSAGE_2_CARRY_3_KS_PBS;
pub const PARAM_MESSAGE_2_CARRY_4: ClassicPBSParameters = PARAM_MESSAGE_2_CARRY_4_KS_PBS;
pub const PARAM_MESSAGE_2_CARRY_5: ClassicPBSParameters = PARAM_MESSAGE_2_CARRY_5_KS_PBS;
pub const PARAM_MESSAGE_2_CARRY_6: ClassicPBSParameters = PARAM_MESSAGE_2_CARRY_6_KS_PBS;
pub const PARAM_MESSAGE_3_CARRY_0: ClassicPBSParameters = PARAM_MESSAGE_3_CARRY_0_KS_PBS;
pub const PARAM_MESSAGE_3_CARRY_1: ClassicPBSParameters = PARAM_MESSAGE_3_CARRY_1_KS_PBS;
pub const PARAM_MESSAGE_3_CARRY_2: ClassicPBSParameters = PARAM_MESSAGE_3_CARRY_2_KS_PBS;
pub const PARAM_MESSAGE_3_CARRY_3: ClassicPBSParameters = PARAM_MESSAGE_3_CARRY_3_KS_PBS;
pub const PARAM_MESSAGE_3_CARRY_4: ClassicPBSParameters = PARAM_MESSAGE_3_CARRY_4_KS_PBS;
pub const PARAM_MESSAGE_3_CARRY_5: ClassicPBSParameters = PARAM_MESSAGE_3_CARRY_5_KS_PBS;
pub const PARAM_MESSAGE_4_CARRY_0: ClassicPBSParameters = PARAM_MESSAGE_4_CARRY_0_KS_PBS;
pub const PARAM_MESSAGE_4_CARRY_1: ClassicPBSParameters = PARAM_MESSAGE_4_CARRY_1_KS_PBS;
pub const PARAM_MESSAGE_4_CARRY_2: ClassicPBSParameters = PARAM_MESSAGE_4_CARRY_2_KS_PBS;
pub const PARAM_MESSAGE_4_CARRY_3: ClassicPBSParameters = PARAM_MESSAGE_4_CARRY_3_KS_PBS;
pub const PARAM_MESSAGE_4_CARRY_4: ClassicPBSParameters = PARAM_MESSAGE_4_CARRY_4_KS_PBS;
pub const PARAM_MESSAGE_5_CARRY_0: ClassicPBSParameters = PARAM_MESSAGE_5_CARRY_0_KS_PBS;
pub const PARAM_MESSAGE_5_CARRY_1: ClassicPBSParameters = PARAM_MESSAGE_5_CARRY_1_KS_PBS;
pub const PARAM_MESSAGE_5_CARRY_2: ClassicPBSParameters = PARAM_MESSAGE_5_CARRY_2_KS_PBS;
pub const PARAM_MESSAGE_5_CARRY_3: ClassicPBSParameters = PARAM_MESSAGE_5_CARRY_3_KS_PBS;
pub const PARAM_MESSAGE_6_CARRY_0: ClassicPBSParameters = PARAM_MESSAGE_6_CARRY_0_KS_PBS;
pub const PARAM_MESSAGE_6_CARRY_1: ClassicPBSParameters = PARAM_MESSAGE_6_CARRY_1_KS_PBS;
pub const PARAM_MESSAGE_6_CARRY_2: ClassicPBSParameters = PARAM_MESSAGE_6_CARRY_2_KS_PBS;
pub const PARAM_MESSAGE_7_CARRY_0: ClassicPBSParameters = PARAM_MESSAGE_7_CARRY_0_KS_PBS;
pub const PARAM_MESSAGE_7_CARRY_1: ClassicPBSParameters = PARAM_MESSAGE_7_CARRY_1_KS_PBS;
pub const PARAM_MESSAGE_8_CARRY_0: ClassicPBSParameters = PARAM_MESSAGE_8_CARRY_0_KS_PBS;
pub const PARAM_SMALL_MESSAGE_1_CARRY_1: ClassicPBSParameters = PARAM_MESSAGE_1_CARRY_1_PBS_KS;
pub const PARAM_SMALL_MESSAGE_2_CARRY_2: ClassicPBSParameters = PARAM_MESSAGE_2_CARRY_2_PBS_KS;
pub const PARAM_SMALL_MESSAGE_3_CARRY_3: ClassicPBSParameters = PARAM_MESSAGE_3_CARRY_3_PBS_KS;
pub const PARAM_SMALL_MESSAGE_4_CARRY_4: ClassicPBSParameters = PARAM_MESSAGE_4_CARRY_4_PBS_KS;
