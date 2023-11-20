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
use crate::core_crypto::prelude::{
    GlweCiphertextConformanceParameters, LweCiphertextCount, LweCiphertextListParameters,
    LweCiphertextParameters, MsDecompressionType,
};
use crate::shortint::backward_compatibility::parameters::*;
use serde::{Deserialize, Serialize};

use tfhe_versionable::Versionize;

pub mod classic;
pub mod compact_public_key_only;
#[cfg(tarpaulin)]
pub mod coverage_parameters;
pub mod key_switching;
pub mod list_compression;
pub mod multi_bit;
pub mod parameters_wopbs;
pub mod parameters_wopbs_message_carry;
pub mod parameters_wopbs_only;

pub use super::ciphertext::{Degree, MaxNoiseLevel, NoiseLevel};
pub use super::PBSOrder;
pub use crate::core_crypto::commons::parameters::EncryptionKeyChoice;
use crate::shortint::ciphertext::MaxDegree;
pub use crate::shortint::parameters::classic::compact_pk::*;
pub use crate::shortint::parameters::classic::gaussian::p_fail_2_minus_64::ks_pbs::*;
pub use crate::shortint::parameters::classic::gaussian::p_fail_2_minus_64::pbs_ks::*;
pub use crate::shortint::parameters::classic::tuniform::p_fail_2_minus_64::ks_pbs::*;
pub use crate::shortint::parameters::classic::tuniform::p_fail_2_minus_64::pbs_ks::*;
pub use crate::shortint::parameters::list_compression::CompressionParameters;
pub use compact_public_key_only::{
    CompactCiphertextListExpansionKind, CompactPublicKeyEncryptionParameters,
    ShortintCompactCiphertextListCastingMode,
};
#[cfg(tarpaulin)]
pub use coverage_parameters::*;
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

impl MessageModulus {
    pub fn corresponding_max_degree(&self) -> MaxDegree {
        MaxDegree::new(self.0 - 1)
    }
}

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
                ms_decompression_method: MsDecompressionType::ClassicPbs,
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

/// Structure to store the expected properties of a compressed ciphertext
/// Can be used on a server to check if client inputs are well formed
/// before running a computation on them
#[derive(Copy, Clone)]
pub struct CompressedCiphertextConformanceParams {
    pub ct_params: GlweCiphertextConformanceParameters<u64>,
    pub lwe_per_glwe: LweCiphertextCount,
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
    pub expansion_kind: CompactCiphertextListExpansionKind,
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
            expansion_kind: self.pbs_order.into(),
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

    pub const fn encryption_noise_distribution(&self) -> DynamicDistribution<u64> {
        match self.encryption_key_choice() {
            EncryptionKeyChoice::Big => self.glwe_noise_distribution(),
            EncryptionKeyChoice::Small => self.lwe_noise_distribution(),
        }
    }

    pub const fn encryption_lwe_dimension(&self) -> LweDimension {
        match self.encryption_key_choice() {
            EncryptionKeyChoice::Big => self
                .glwe_dimension()
                .to_equivalent_lwe_dimension(self.polynomial_size()),
            EncryptionKeyChoice::Small => self.lwe_dimension(),
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
    PARAM_MESSAGE_1_CARRY_0_KS_PBS_GAUSSIAN_2M64;
pub const PARAM_MESSAGE_1_CARRY_1_KS_PBS: ClassicPBSParameters =
    PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64;
pub const PARAM_MESSAGE_1_CARRY_2_KS_PBS: ClassicPBSParameters =
    PARAM_MESSAGE_1_CARRY_2_KS_PBS_GAUSSIAN_2M64;
pub const PARAM_MESSAGE_1_CARRY_3_KS_PBS: ClassicPBSParameters =
    PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64;
pub const PARAM_MESSAGE_1_CARRY_4_KS_PBS: ClassicPBSParameters =
    PARAM_MESSAGE_1_CARRY_4_KS_PBS_GAUSSIAN_2M64;
pub const PARAM_MESSAGE_1_CARRY_5_KS_PBS: ClassicPBSParameters =
    PARAM_MESSAGE_1_CARRY_5_KS_PBS_GAUSSIAN_2M64;
pub const PARAM_MESSAGE_1_CARRY_6_KS_PBS: ClassicPBSParameters =
    PARAM_MESSAGE_1_CARRY_6_KS_PBS_GAUSSIAN_2M64;
pub const PARAM_MESSAGE_1_CARRY_7_KS_PBS: ClassicPBSParameters =
    PARAM_MESSAGE_1_CARRY_7_KS_PBS_GAUSSIAN_2M64;
pub const PARAM_MESSAGE_2_CARRY_0_KS_PBS: ClassicPBSParameters =
    PARAM_MESSAGE_2_CARRY_0_KS_PBS_GAUSSIAN_2M64;
pub const PARAM_MESSAGE_2_CARRY_1_KS_PBS: ClassicPBSParameters =
    PARAM_MESSAGE_2_CARRY_1_KS_PBS_GAUSSIAN_2M64;
pub const PARAM_MESSAGE_2_CARRY_2_KS_PBS: ClassicPBSParameters =
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64;
pub const PARAM_MESSAGE_2_CARRY_3_KS_PBS: ClassicPBSParameters =
    PARAM_MESSAGE_2_CARRY_3_KS_PBS_GAUSSIAN_2M64;
pub const PARAM_MESSAGE_2_CARRY_4_KS_PBS: ClassicPBSParameters =
    PARAM_MESSAGE_2_CARRY_4_KS_PBS_GAUSSIAN_2M64;
pub const PARAM_MESSAGE_2_CARRY_5_KS_PBS: ClassicPBSParameters =
    PARAM_MESSAGE_2_CARRY_5_KS_PBS_GAUSSIAN_2M64;
pub const PARAM_MESSAGE_2_CARRY_6_KS_PBS: ClassicPBSParameters =
    PARAM_MESSAGE_2_CARRY_6_KS_PBS_GAUSSIAN_2M64;
pub const PARAM_MESSAGE_3_CARRY_0_KS_PBS: ClassicPBSParameters =
    PARAM_MESSAGE_3_CARRY_0_KS_PBS_GAUSSIAN_2M64;
pub const PARAM_MESSAGE_3_CARRY_1_KS_PBS: ClassicPBSParameters =
    PARAM_MESSAGE_3_CARRY_1_KS_PBS_GAUSSIAN_2M64;
pub const PARAM_MESSAGE_3_CARRY_2_KS_PBS: ClassicPBSParameters =
    PARAM_MESSAGE_3_CARRY_2_KS_PBS_GAUSSIAN_2M64;
pub const PARAM_MESSAGE_3_CARRY_3_KS_PBS: ClassicPBSParameters =
    PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64;
pub const PARAM_MESSAGE_3_CARRY_4_KS_PBS: ClassicPBSParameters =
    PARAM_MESSAGE_3_CARRY_4_KS_PBS_GAUSSIAN_2M64;
pub const PARAM_MESSAGE_3_CARRY_5_KS_PBS: ClassicPBSParameters =
    PARAM_MESSAGE_3_CARRY_5_KS_PBS_GAUSSIAN_2M64;
pub const PARAM_MESSAGE_4_CARRY_0_KS_PBS: ClassicPBSParameters =
    PARAM_MESSAGE_4_CARRY_0_KS_PBS_GAUSSIAN_2M64;
pub const PARAM_MESSAGE_4_CARRY_1_KS_PBS: ClassicPBSParameters =
    PARAM_MESSAGE_4_CARRY_1_KS_PBS_GAUSSIAN_2M64;
pub const PARAM_MESSAGE_4_CARRY_2_KS_PBS: ClassicPBSParameters =
    PARAM_MESSAGE_4_CARRY_2_KS_PBS_GAUSSIAN_2M64;
pub const PARAM_MESSAGE_4_CARRY_3_KS_PBS: ClassicPBSParameters =
    PARAM_MESSAGE_4_CARRY_3_KS_PBS_GAUSSIAN_2M64;
pub const PARAM_MESSAGE_4_CARRY_4_KS_PBS: ClassicPBSParameters =
    PARAM_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M64;
pub const PARAM_MESSAGE_5_CARRY_0_KS_PBS: ClassicPBSParameters =
    PARAM_MESSAGE_5_CARRY_0_KS_PBS_GAUSSIAN_2M64;
pub const PARAM_MESSAGE_5_CARRY_1_KS_PBS: ClassicPBSParameters =
    PARAM_MESSAGE_5_CARRY_1_KS_PBS_GAUSSIAN_2M64;
pub const PARAM_MESSAGE_5_CARRY_2_KS_PBS: ClassicPBSParameters =
    PARAM_MESSAGE_5_CARRY_2_KS_PBS_GAUSSIAN_2M64;
pub const PARAM_MESSAGE_5_CARRY_3_KS_PBS: ClassicPBSParameters =
    PARAM_MESSAGE_5_CARRY_3_KS_PBS_GAUSSIAN_2M64;
pub const PARAM_MESSAGE_6_CARRY_0_KS_PBS: ClassicPBSParameters =
    PARAM_MESSAGE_6_CARRY_0_KS_PBS_GAUSSIAN_2M64;
pub const PARAM_MESSAGE_6_CARRY_1_KS_PBS: ClassicPBSParameters =
    PARAM_MESSAGE_6_CARRY_1_KS_PBS_GAUSSIAN_2M64;
pub const PARAM_MESSAGE_6_CARRY_2_KS_PBS: ClassicPBSParameters =
    PARAM_MESSAGE_6_CARRY_2_KS_PBS_GAUSSIAN_2M64;
pub const PARAM_MESSAGE_7_CARRY_0_KS_PBS: ClassicPBSParameters =
    PARAM_MESSAGE_7_CARRY_0_KS_PBS_GAUSSIAN_2M64;
pub const PARAM_MESSAGE_7_CARRY_1_KS_PBS: ClassicPBSParameters =
    PARAM_MESSAGE_7_CARRY_1_KS_PBS_GAUSSIAN_2M64;
pub const PARAM_MESSAGE_8_CARRY_0_KS_PBS: ClassicPBSParameters =
    PARAM_MESSAGE_8_CARRY_0_KS_PBS_GAUSSIAN_2M64;
pub const PARAM_MESSAGE_1_CARRY_1_PBS_KS: ClassicPBSParameters =
    PARAM_MESSAGE_1_CARRY_1_PBS_KS_GAUSSIAN_2M64;
pub const PARAM_MESSAGE_2_CARRY_2_PBS_KS: ClassicPBSParameters =
    PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64;
pub const PARAM_MESSAGE_3_CARRY_3_PBS_KS: ClassicPBSParameters =
    PARAM_MESSAGE_3_CARRY_3_PBS_KS_GAUSSIAN_2M64;
pub const PARAM_MESSAGE_4_CARRY_4_PBS_KS: ClassicPBSParameters =
    PARAM_MESSAGE_4_CARRY_4_PBS_KS_GAUSSIAN_2M64;

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

pub const COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS: CompressionParameters =
    list_compression::COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64;

pub const COMP_PARAM_MESSAGE_2_CARRY_2: CompressionParameters = COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS;

///////////////////////
////////////////////////
////////////////////////
////////////////////////
////////////////////////
////////////////////////
////////////////////////
////////////////////////
////////////////////////
////////////////////////
////////////////////////
////////////////////////
////////////////////////
////////////////////////

////////////////////
 // 2^-40 CJP
////////////////////
pub const PARAM_MESSAGE_2_PBS_MS_0_EF_0_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(750),
    glwe_dimension: GlweDimension(3),
    polynomial_size: PolynomialSize(512),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(1.5140301927925663e-05)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(1.9524392655548086e-11)),
    pbs_base_log: DecompositionBaseLog(17),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(3),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
// p-fail = 2^-40.166, algorithmic cost ~ 71020771, 2-norm = 7, extention factor = 1,
pub const PARAM_MESSAGE_3_PBS_MS_0_EF_0_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(797),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(6.729146877775986e-06)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.845267479601915e-15)),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(7),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
// p-fail = 2^-40.339, algorithmic cost ~ 101102820, 2-norm = 5, extention factor = 1,
pub const PARAM_MESSAGE_4_PBS_MS_0_EF_0_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(796),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(6.8462551852215656e-06)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.845267479601915e-15)),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(5),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
// p-fail = 2^-40.012, algorithmic cost ~ 270175365, 2-norm = 10, extention factor = 1,
pub const PARAM_MESSAGE_5_PBS_MS_0_EF_0_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(891),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(1.3292631075564801e-06)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.168404344971009e-19)),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(2),
    ks_level: DecompositionLevelCount(9),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(10),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
// p-fail = 2^-40.294, algorithmic cost ~ 788216931, 2-norm = 9, extention factor = 1,
pub const PARAM_MESSAGE_6_PBS_MS_0_EF_0_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(925),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(7.393437385253331e-07)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.168404344971009e-19)),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(9),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
// p-fail = 2^-40.278, algorithmic cost ~ 1797127195, 2-norm = 18, extention factor = 1,
pub const PARAM_MESSAGE_7_PBS_MS_0_EF_0_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(997),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.134740032189177e-07)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.168404344971009e-19)),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(18),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
// p-fail = 2^-40.14, algorithmic cost ~ 4134108115, 2-norm = 17, extention factor = 1,
pub const PARAM_MESSAGE_8_PBS_MS_0_EF_0_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1069),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(6.163729761369871e-08)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.168404344971009e-19)),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(17),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
// p-fail = 2^-40.195, algorithmic cost ~ 12062096272, 2-norm = 34, extention factor = 1,
pub const PARAM_MESSAGE_9_PBS_MS_0_EF_0_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1136),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(1.9400260433432435e-08)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.168404344971009e-19)),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(32),
    max_noise_level: MaxNoiseLevel::new(34),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

////////////////////
// 2^-40 LY & Sorted
////////////////////
// p-fail = 2^-40.198, algorithmic cost ~ 153220270, 2-norm = 10, extention factor = 2,
pub const PARAM_MESSAGE_5_SORTED_PBS_MS_0_EF_1_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(850),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.6966651909950986e-06)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.845267479601915e-15)),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(10),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
// p-fail = 2^-40.166, algorithmic cost ~ 394375947, 2-norm = 9, extention factor = 8,
pub const PARAM_MESSAGE_6_SORTED_PBS_MS_0_EF_3_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(885),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(1.4742441118914234e-06)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.845267479601915e-15)),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(2),
    ks_level: DecompositionLevelCount(8),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(9),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
// p-fail = 2^-40.098, algorithmic cost ~ 823972990, 2-norm = 18, extention factor = 8,
pub const PARAM_MESSAGE_7_SORTED_PBS_MS_0_EF_3_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(898),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(1.178038342566844e-06)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.845267479601915e-15)),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(2),
    ks_level: DecompositionLevelCount(9),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(18),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
// p-fail = 2^-40.275, algorithmic cost ~ 1686047825, 2-norm = 17, extention factor = 16,
pub const PARAM_MESSAGE_8_SORTED_PBS_MS_0_EF_4_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(943),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(5.419647594102004e-07)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.845267479601915e-15)),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(2),
    ks_level: DecompositionLevelCount(9),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(17),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
// p-fail = 2^-40.026, algorithmic cost ~ 3482372147, 2-norm = 34, extention factor = 32,
pub const PARAM_MESSAGE_9_SORTED_PBS_MS_0_EF_5_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(973),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(3.229823543641909e-07)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.845267479601915e-15)),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(20),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(32),
    max_noise_level: MaxNoiseLevel::new(34),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

////////////////////
//2^-40 Sorted + new MS
////////////////////

// p-fail = 2^-40.012, algorithmic cost ~ 152881661, 2-norm = 10, extention factor = 2,
pub const PARAM_MESSAGE_5_BEST_PBS_MS_20_EF_1_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(856),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.431468115021058e-06)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.845267479601915e-15)),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(10),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
// p-fail = 2^-40.032, algorithmic cost ~ 394171147, 2-norm = 9, extention factor = 8,
pub const PARAM_MESSAGE_6_BEST_PBS_MS_1_EF_3_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(885),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(1.4742441118914234e-06)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.845267479601915e-15)),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(2),
    ks_level: DecompositionLevelCount(8),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(9),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
// p-fail = 2^-40.011, algorithmic cost ~ 806758841, 2-norm = 18, extention factor = 8,
pub const PARAM_MESSAGE_7_BEST_PBS_MS_94_EF_3_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(924),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(7.522106435597801e-07)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.845267479601915e-15)),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(2),
    ks_level: DecompositionLevelCount(9),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(18),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
// p-fail = 2^-40.009, algorithmic cost ~ 1654281273, 2-norm = 17, extention factor = 16,
pub const PARAM_MESSAGE_8_BEST_PBS_MS_90_EF_4_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(967),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(3.582096211498188e-07)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.845267479601915e-15)),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(2),
    ks_level: DecompositionLevelCount(10),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(17),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
// p-fail = 2^-40.002, algorithmic cost ~ 3431866737, 2-norm = 34, extention factor = 32,
pub const PARAM_MESSAGE_9_BEST_PBS_MS_76_EF_5_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(996),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.1718912188918548e-07)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.845267479601915e-15)),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(20),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(32),
    max_noise_level: MaxNoiseLevel::new(34),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

////////////////////
////////////////////
////////////////////

////////////////////
// 2^-64 CJP
////////////////////

// p-fail = 2^-64.01, algorithmic cost ~ 59598579, 2-norm = 3, extention factor = 1,
pub const PARAM_MESSAGE_2_PBS_MS_0_EF_0_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(781),
    glwe_dimension: GlweDimension(4),
    polynomial_size: PolynomialSize(512),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(8.868480365938865e-06)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.845267479601915e-15)),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(3),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
// p-fail = 2^-64.415, algorithmic cost ~ 76455078, 2-norm = 7, extention factor = 1,
pub const PARAM_MESSAGE_3_PBS_MS_0_EF_0_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(858),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.348996819227123e-06)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.845267479601915e-15)),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(5),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(7),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
// p-fail = 2^-64.074, algorithmic cost ~ 105927870, 2-norm = 5, extention factor = 1,
pub const PARAM_MESSAGE_4_PBS_MS_0_EF_0_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(834),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(3.5539902359442825e-06)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.845267479601915e-15)),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(5),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
// p-fail = 2^-64.084, algorithmic cost ~ 362142842, 2-norm = 10, extention factor = 1,
pub const PARAM_MESSAGE_5_PBS_MS_0_EF_0_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(902),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(1.0994794733558207e-06)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.168404344971009e-19)),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(10),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
// p-fail = 2^-64.122, algorithmic cost ~ 832519215, 2-norm = 9, extention factor = 1,
pub const PARAM_MESSAGE_6_PBS_MS_0_EF_0_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(977),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(3.0144389706858286e-07)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.168404344971009e-19)),
    pbs_base_log: DecompositionBaseLog(16),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(9),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
// p-fail = 2^-64.037, algorithmic cost ~ 1947286491, 2-norm = 18, extention factor = 1,
pub const PARAM_MESSAGE_7_PBS_MS_0_EF_0_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1061),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(7.07600596055958e-08)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.168404344971009e-19)),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(18),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
// p-fail = 2^-64.033, algorithmic cost ~ 5904038824, 2-norm = 17, extention factor = 1,
pub const PARAM_MESSAGE_8_PBS_MS_0_EF_0_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1112),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.935224755982453e-08)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.168404344971009e-19)),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(2),
    ks_level: DecompositionLevelCount(11),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(17),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
// p-fail = 2^-64.29, algorithmic cost ~ 26222263157, 2-norm = 34, extention factor = 1,
pub const PARAM_MESSAGE_9_PBS_MS_0_EF_0_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1163),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(131072),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(1.2175716662978789e-08)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.168404344971009e-19)),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(8),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(32),
    max_noise_level: MaxNoiseLevel::new(34),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

////////////////////
// 2^-64 LY & Sorted
////////////////////

// p-fail = 2^-64.01, algorithmic cost ~ 216691848, 2-norm = 10, extention factor = 4,
pub const PARAM_MESSAGE_5_SORTED_PBS_MS_0_EF_2_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(888),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(1.3998779623487315e-06)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.845267479601915e-15)),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(2),
    ks_level: DecompositionLevelCount(8),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(10),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
// p-fail = 2^-64.1, algorithmic cost ~ 436786304, 2-norm = 9, extention factor = 4,
pub const PARAM_MESSAGE_6_SORTED_PBS_MS_0_EF_2_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(896),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(1.2193982745221312e-06)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.845267479601915e-15)),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(2),
    ks_level: DecompositionLevelCount(9),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(9),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
// p-fail = 2^-64.182, algorithmic cost ~ 868013134, 2-norm = 18, extention factor = 8,
pub const PARAM_MESSAGE_7_SORTED_PBS_MS_0_EF_3_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(946),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(5.146261171730886e-07)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.845267479601915e-15)),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(2),
    ks_level: DecompositionLevelCount(9),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(18),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
// p-fail = 2^-64.093, algorithmic cost ~ 1779516447, 2-norm = 17, extention factor = 16,
pub const PARAM_MESSAGE_8_SORTED_PBS_MS_0_EF_4_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(993),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.287269267206566e-07)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.845267479601915e-15)),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(2),
    ks_level: DecompositionLevelCount(10),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(17),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
// p-fail = 2^-64.04, algorithmic cost ~ 3744337899, 2-norm = 34, extention factor = 32,
pub const PARAM_MESSAGE_9_SORTED_PBS_MS_0_EF_5_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1045),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(9.325613048771689e-08)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.845267479601915e-15)),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(21),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(32),
    max_noise_level: MaxNoiseLevel::new(34),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

////////////////////
//2^-64 Sorted + new MS
//////////////////// (No parameters found by RO)

////////////////////
////////////////////
////////////////////

////////////////////
// 2^-80 CJP
////////////////////

// p-fail = 2^-80.073, algorithmic cost ~ 65248508, 2-norm = 3, extention factor = 1,
pub const PARAM_MESSAGE_2_PBS_MS_0_EF_0_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(772),
    glwe_dimension: GlweDimension(4),
    polynomial_size: PolynomialSize(512),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(1.0358261825601776e-05)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.845267479601915e-15)),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(3),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
// p-fail = 2^-80.029, algorithmic cost ~ 80675011, 2-norm = 7, extention factor = 1,
pub const PARAM_MESSAGE_3_PBS_MS_0_EF_0_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(829),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(3.874196153925216e-06)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.845267479601915e-15)),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(7),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
// p-fail = 2^-80.006, algorithmic cost ~ 125637780, 2-norm = 5, extention factor = 1,
pub const PARAM_MESSAGE_4_PBS_MS_0_EF_0_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(876),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(1.7218966356934023e-06)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.845267479601915e-15)),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(2),
    ks_level: DecompositionLevelCount(9),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(5),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
// p-fail = 2^-80.797, algorithmic cost ~ 760314976, 2-norm = 10, extention factor = 1,
pub const PARAM_MESSAGE_5_PBS_MS_0_EF_0_81: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(928),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(7.020485941329387e-07)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.168404344971009e-19)),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(10),
    log2_p_fail: -81.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
// p-fail = 2^-81.092, algorithmic cost ~ 1726839874, 2-norm = 9, extention factor = 1,
pub const PARAM_MESSAGE_6_PBS_MS_0_EF_0_81: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(958),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(4.1838385960350906e-07)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.168404344971009e-19)),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(9),
    log2_p_fail: -81.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
// p-fail = 2^-80.299, algorithmic cost ~ 3945233376, 2-norm = 18, extention factor = 1,
pub const PARAM_MESSAGE_7_PBS_MS_0_EF_0_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1056),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(7.713536970443607e-08)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.168404344971009e-19)),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(18),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
// p-fail = 2^-81.43, algorithmic cost ~ 11520637891, 2-norm = 17, extention factor = 1,
pub const PARAM_MESSAGE_8_PBS_MS_0_EF_0_81: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1085),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(4.676860202394557e-08)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.168404344971009e-19)),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(17),
    log2_p_fail: -81.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
// p-fail = 2^-80.046, algorithmic cost ~ 27146582860, 2-norm = 34, extention factor = 1,
pub const PARAM_MESSAGE_9_PBS_MS_0_EF_0_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1204),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(131072),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(6.001757660611216e-09)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.168404344971009e-19)),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(8),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(32),
    max_noise_level: MaxNoiseLevel::new(34),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

////////////////////
// 2^-64 LY & Sorted
////////////////////

// p-fail = 2^-80.021, algorithmic cost ~ 273579159, 2-norm = 10, extention factor = 4,
pub const PARAM_MESSAGE_5_SORTED_PBS_MS_0_EF_2_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(873),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(1.8133694827208593e-06)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.845267479601915e-15)),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(10),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
// p-fail = 2^-80.021, algorithmic cost ~ 790820582, 2-norm = 9, extention factor = 16,
pub const PARAM_MESSAGE_6_SORTED_PBS_MS_0_EF_4_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(922),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(7.786201243971259e-07)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.845267479601915e-15)),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(2),
    ks_level: DecompositionLevelCount(9),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(9),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
// p-fail = 2^-81.286, algorithmic cost ~ 1627047026, 2-norm = 18, extention factor = 16,
pub const PARAM_MESSAGE_7_SORTED_PBS_MS_0_EF_4_81: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(910),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(9.577287511785255e-07)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.845267479601915e-15)),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(2),
    ks_level: DecompositionLevelCount(9),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(18),
    log2_p_fail: -81.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
// p-fail = 2^-80.528, algorithmic cost ~ 3360412756, 2-norm = 17, extention factor = 32,
pub const PARAM_MESSAGE_8_SORTED_PBS_MS_0_EF_5_81: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(940),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(5.707557207862519e-07)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.845267479601915e-15)),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(19),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(17),
    log2_p_fail: -81.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
// p-fail = 2^-80.891, algorithmic cost ~ 6960229416, 2-norm = 34, extention factor = 64,
pub const PARAM_MESSAGE_9_SORTED_PBS_MS_0_EF_6_81: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(984),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.671498718807819e-07)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.845267479601915e-15)),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(20),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(32),
    max_noise_level: MaxNoiseLevel::new(34),
    log2_p_fail: -81.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

////////////////////
//2^-64 Sorted + new MS
////////////////////

// p-fail = 2^-80.014, algorithmic cost ~ 262883820, 2-norm = 10, extention factor = 4,
pub const PARAM_MESSAGE_5_BEST_PBS_MS_151_EF_2_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(873),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(1.8133694827208593e-06)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.845267479601915e-15)),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(2),
    ks_level: DecompositionLevelCount(8),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(10),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
// p-fail = 2^-80.036, algorithmic cost ~ 706139269, 2-norm = 9, extention factor = 8,
pub const PARAM_MESSAGE_6_BEST_PBS_MS_255_EF_3_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(891),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(1.3292631075564801e-06)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.845267479601915e-15)),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(2),
    ks_level: DecompositionLevelCount(9),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(9),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
// p-fail = 2^-80.207, algorithmic cost ~ 1448048388, 2-norm = 18, extention factor = 16,
pub const PARAM_MESSAGE_7_BEST_PBS_MS_256_EF_4_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(935),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(6.221794297398788e-07)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.845267479601915e-15)),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(2),
    ks_level: DecompositionLevelCount(9),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(18),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
// p-fail = 2^-80.159, algorithmic cost ~ 3005964687, 2-norm = 17, extention factor = 32,
pub const PARAM_MESSAGE_8_BEST_PBS_MS_256_EF_5_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(966),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(3.644435945205178e-07)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.845267479601915e-15)),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(19),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(17),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
// p-fail = 2^-80.037, algorithmic cost ~ 6278220299, 2-norm = 34, extention factor = 64,
pub const PARAM_MESSAGE_9_BEST_PBS_MS_255_EF_6_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1013),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(1.6197791086780464e-07)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.845267479601915e-15)),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(21),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(32),
    max_noise_level: MaxNoiseLevel::new(34),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

////////////////////
////////////////////
////////////////////

////////////////////
// 2^-128 CJP
////////////////////
// p-fail = 2^-128.788, algorithmic cost ~ 69773553, 2-norm = 3, extention factor = 1,
pub const PARAM_MESSAGE_2_PBS_MS_0_EF_0_129: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(783),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(8.56767647590072e-06)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.845267479601915e-15)),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(3),
    log2_p_fail: -129.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
// p-fail = 2^-129.884, algorithmic cost ~ 100087020, 2-norm = 7, extention factor = 1,
pub const PARAM_MESSAGE_3_PBS_MS_0_EF_0_130: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(788),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(7.85955004091113e-06)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.845267479601915e-15)),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(7),
    log2_p_fail: -130.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
// p-fail = 2^-129.42, algorithmic cost ~ 232549540, 2-norm = 5, extention factor = 1,
pub const PARAM_MESSAGE_4_PBS_MS_0_EF_0_129: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(860),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.269322810630956e-06)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.168404344971009e-19)),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(5),
    log2_p_fail: -129.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
// p-fail = 2^-130.169, algorithmic cost ~ 780549228, 2-norm = 10, extention factor = 1,
pub const PARAM_MESSAGE_5_PBS_MS_0_EF_0_130: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(916),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(8.635432122258441e-07)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.168404344971009e-19)),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(10),
    log2_p_fail: -130.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
// p-fail = 2^-128.686, algorithmic cost ~ 1771895849, 2-norm = 9, extention factor = 1,
pub const PARAM_MESSAGE_6_PBS_MS_0_EF_0_129: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(983),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.7179911938548217e-07)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.168404344971009e-19)),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(9),
    log2_p_fail: -129.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
// p-fail = 2^-128.522, algorithmic cost ~ 4068506559, 2-norm = 18, extention factor = 1,
pub const PARAM_MESSAGE_7_PBS_MS_0_EF_0_129: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1089),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(4.3649782918638684e-08)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.168404344971009e-19)),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(18),
    log2_p_fail: -129.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
// p-fail = 2^-129.064, algorithmic cost ~ 11817909159, 2-norm = 17, extention factor = 1,
pub const PARAM_MESSAGE_8_PBS_MS_0_EF_0_129: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1113),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.8850164020946995e-08)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.168404344971009e-19)),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(17),
    log2_p_fail: -129.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
// p-fail = 2^-128.537, algorithmic cost ~ 32680967016, 2-norm = 34, extention factor = 1,
pub const PARAM_MESSAGE_9_PBS_MS_0_EF_0_129: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1176),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(131072),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(9.729366365802664e-09)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.168404344971009e-19)),
    pbs_base_log: DecompositionBaseLog(9),
    pbs_level: DecompositionLevelCount(4),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(8),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(32),
    max_noise_level: MaxNoiseLevel::new(34),
    log2_p_fail: -129.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

////////////////////
// 2^-128 LY & Sorted
////////////////////
// p-fail = 2^-128.303, algorithmic cost ~ 149976256, 2-norm = 5, extention factor = 2,
pub const PARAM_MESSAGE_4_SORTED_PBS_MS_0_EF_1_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(832),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(3.678767833597121e-06)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.845267479601915e-15)),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(5),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
// p-fail = 2^-128.06, algorithmic cost ~ 298458231, 2-norm = 10, extention factor = 4,
pub const PARAM_MESSAGE_5_SORTED_PBS_MS_0_EF_2_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(905),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(1.0440177935192313e-06)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.845267479601915e-15)),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(2),
    ks_level: DecompositionLevelCount(9),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(10),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
// p-fail = 2^-128.885, algorithmic cost ~ 815715463, 2-norm = 9, extention factor = 8,
pub const PARAM_MESSAGE_6_SORTED_PBS_MS_0_EF_3_129: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(889),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(1.3759324133784122e-06)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.845267479601915e-15)),
    pbs_base_log: DecompositionBaseLog(16),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(2),
    ks_level: DecompositionLevelCount(9),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(9),
    log2_p_fail: -129.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
// p-fail = 2^-128.015, algorithmic cost ~ 1666380892, 2-norm = 18, extention factor = 16,
pub const PARAM_MESSAGE_7_SORTED_PBS_MS_0_EF_4_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(932),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(6.552316598334162e-07)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.845267479601915e-15)),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(2),
    ks_level: DecompositionLevelCount(9),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(18),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
// p-fail = 2^-128.242, algorithmic cost ~ 3442632765, 2-norm = 17, extention factor = 32,
pub const PARAM_MESSAGE_8_SORTED_PBS_MS_0_EF_5_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(963),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(3.8380404420179945e-07)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.845267479601915e-15)),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(19),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(17),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
// p-fail = 2^-129.257, algorithmic cost ~ 7141200399, 2-norm = 34, extention factor = 64,
pub const PARAM_MESSAGE_9_SORTED_PBS_MS_0_EF_6_129: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1009),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(1.7355138888472488e-07)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.845267479601915e-15)),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(21),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(32),
    max_noise_level: MaxNoiseLevel::new(34),
    log2_p_fail: -129.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

////////////////////
//2^-64 Sorted + new MS
////////////////////

// p-fail = 2^-128.018, algorithmic cost ~ 146109605, 2-norm = 5, extention factor = 2,
pub const PARAM_MESSAGE_4_BEST_PBS_MS_123_EF_1_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(859),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.3088161607134664e-06)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.845267479601915e-15)),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(5),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
// p-fail = 2^-128.06, algorithmic cost ~ 298458231, 2-norm = 10, extention factor = 4,
pub const PARAM_MESSAGE_5_BEST_PBS_MS_0_EF_2_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(905),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(1.0440177935192313e-06)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.845267479601915e-15)),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(2),
    ks_level: DecompositionLevelCount(9),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(10),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
// p-fail = 2^-128.01, algorithmic cost ~ 780457062, 2-norm = 9, extention factor = 8,
pub const PARAM_MESSAGE_6_BEST_PBS_MS_150_EF_3_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(922),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(7.786201243971259e-07)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.845267479601915e-15)),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(2),
    ks_level: DecompositionLevelCount(9),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(9),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
// p-fail = 2^-128.034, algorithmic cost ~ 1601808101, 2-norm = 18, extention factor = 16,
pub const PARAM_MESSAGE_7_BEST_PBS_MS_148_EF_4_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(966),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(3.644435945205178e-07)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.845267479601915e-15)),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(2),
    ks_level: DecompositionLevelCount(10),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(18),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
// p-fail = 2^-128.015, algorithmic cost ~ 3318103753, 2-norm = 17, extention factor = 32,
pub const PARAM_MESSAGE_8_BEST_PBS_MS_137_EF_5_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(994),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.2481444865333218e-07)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.845267479601915e-15)),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(20),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(17),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
// p-fail = 2^-128.013, algorithmic cost ~ 6975513079, 2-norm = 34, extention factor = 64,
pub const PARAM_MESSAGE_9_BEST_PBS_MS_96_EF_6_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1033),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(1.1470815432737178e-07)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.845267479601915e-15)),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(21),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(32),
    max_noise_level: MaxNoiseLevel::new(34),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

////////////////////
//2^-128 Parallel
////////////////////

// p-fail = 2^-128.069, algorithmic cost ~ 48210399, 2-norm = 3, extention factor = 16,
pub const PARAM_MESSAGE_1_CARRY_1_PARALLEL_PBS_MS_0_EF_4_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(801),
    glwe_dimension: GlweDimension(6),
    polynomial_size: PolynomialSize(256),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(6.280405822097679e-06)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(1.9524392655548086e-11)),
    pbs_base_log: DecompositionBaseLog(17),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(3),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};


// p-fail = 2^-128.902, algorithmic cost ~ 64099512, 2-norm = 7, extention factor = 16,
pub const PARAM_MESSAGE_1_CARRY_2_PARALLEL_PBS_MS_0_EF_4_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(840),
    glwe_dimension: GlweDimension(4),
    polynomial_size: PolynomialSize(512),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(3.2044815829012556e-06)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.845267479601915e-15)),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(5),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(7),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};


// p-fail = 2^-128.147, algorithmic cost ~ 67456140, 2-norm = 5, extention factor = 16,
pub const PARAM_MESSAGE_2_CARRY_2_PARALLEL_PBS_MS_0_EF_4_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(884),
    glwe_dimension: GlweDimension(4),
    polynomial_size: PolynomialSize(512),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(1.4999005934396873e-06)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.845267479601915e-15)),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(5),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(5),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};


// p-fail = 2^-128.14, algorithmic cost ~ 74137702, 2-norm = 10, extention factor = 16,
pub const PARAM_MESSAGE_2_CARRY_3_PARALLEL_PBS_MS_0_EF_4_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(922),
    glwe_dimension: GlweDimension(4),
    polynomial_size: PolynomialSize(512),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(7.786201243971259e-07)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.845267479601915e-15)),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(10),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};


// p-fail = 2^-129.194, algorithmic cost ~ 130495554, 2-norm = 9, extention factor = 16,
pub const PARAM_MESSAGE_3_CARRY_3_PARALLEL_PBS_MS_0_EF_4_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(958),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(4.1838385960350906e-07)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.845267479601915e-15)),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(9),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};


// p-fail = 2^-129.025, algorithmic cost ~ 180726849, 2-norm = 18, extention factor = 16,
pub const PARAM_MESSAGE_3_CARRY_4_PARALLEL_PBS_MS_0_EF_4_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(959),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(4.1122721347578657e-07)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.845267479601915e-15)),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(18),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};


// p-fail = 2^-129.164, algorithmic cost ~ 414903265, 2-norm = 17, extention factor = 16,
pub const PARAM_MESSAGE_4_CARRY_4_PARALLEL_PBS_MS_0_EF_4_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1055),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(7.84777675974155e-08)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.168404344971009e-19)),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(17),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};


// p-fail = 2^-129.791, algorithmic cost ~ 1230150592, 2-norm = 34, extention factor = 16,
pub const PARAM_MESSAGE_4_CARRY_5_PARALLEL_PBS_MS_0_EF_4_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1088),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(4.440942634607687e-08)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.168404344971009e-19)),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(32),
    max_noise_level: MaxNoiseLevel::new(34),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

////////////////////
//2^-80 Parallel
////////////////////


// p-fail = 2^-80.804, algorithmic cost ~ 41443329, 2-norm = 3, extention factor = 16,
pub const PARAM_MESSAGE_1_CARRY_1_PARALLEL_PBS_MS_0_EF_4_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(767),
    glwe_dimension: GlweDimension(6),
    polynomial_size: PolynomialSize(256),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(1.1291516144369596e-05)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(1.9524392655548086e-11)),
    pbs_base_log: DecompositionBaseLog(17),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(3),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};


// p-fail = 2^-80.257, algorithmic cost ~ 61734615, 2-norm = 7, extention factor = 16,
pub const PARAM_MESSAGE_1_CARRY_2_PARALLEL_PBS_MS_0_EF_4_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(809),
    glwe_dimension: GlweDimension(4),
    polynomial_size: PolynomialSize(512),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(5.470702610330007e-06)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.845267479601915e-15)),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(7),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};


// p-fail = 2^-80.708, algorithmic cost ~ 66235548, 2-norm = 5, extention factor = 16,
pub const PARAM_MESSAGE_2_CARRY_2_PARALLEL_PBS_MS_0_EF_4_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(868),
    glwe_dimension: GlweDimension(4),
    polynomial_size: PolynomialSize(512),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(1.976749683932629e-06)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.845267479601915e-15)),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(5),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(5),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};


// p-fail = 2^-80.024, algorithmic cost ~ 70736481, 2-norm = 10, extention factor = 16,
pub const PARAM_MESSAGE_2_CARRY_3_PARALLEL_PBS_MS_0_EF_4_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(927),
    glwe_dimension: GlweDimension(4),
    polynomial_size: PolynomialSize(512),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(7.142664464248818e-07)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.845267479601915e-15)),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(5),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(10),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};


// p-fail = 2^-80.025, algorithmic cost ~ 97154114, 2-norm = 9, extention factor = 16,
pub const PARAM_MESSAGE_3_CARRY_3_PARALLEL_PBS_MS_0_EF_4_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(958),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(4.1838385960350906e-07)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.845267479601915e-15)),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(9),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};


// p-fail = 2^-80.917, algorithmic cost ~ 176393304, 2-norm = 18, extention factor = 16,
pub const PARAM_MESSAGE_3_CARRY_4_PARALLEL_PBS_MS_0_EF_4_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(936),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(6.115367677337101e-07)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.845267479601915e-15)),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(18),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};


// p-fail = 2^-80.704, algorithmic cost ~ 405466105, 2-norm = 17, extention factor = 16,
pub const PARAM_MESSAGE_4_CARRY_4_PARALLEL_PBS_MS_0_EF_4_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1031),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(1.1873546081330433e-07)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.168404344971009e-19)),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(17),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};


// p-fail = 2^-80.529, algorithmic cost ~ 947542973, 2-norm = 34, extention factor = 16,
pub const PARAM_MESSAGE_4_CARRY_5_PARALLEL_PBS_MS_0_EF_4_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1091),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(4.2169255933240424e-08)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.168404344971009e-19)),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(32),
    max_noise_level: MaxNoiseLevel::new(34),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};


////////////////////
//2^-64 Parallel
////////////////////


// p-fail = 2^-64.557, algorithmic cost ~ 40525074, 2-norm = 3, extention factor = 16,
pub const PARAM_MESSAGE_1_CARRY_1_PARALLEL_PBS_MS_0_EF_4_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(750),
    glwe_dimension: GlweDimension(6),
    polynomial_size: PolynomialSize(256),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(1.5140301927925663e-05)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(1.9524392655548086e-11)),
    pbs_base_log: DecompositionBaseLog(17),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(3),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};


// p-fail = 2^-65.141, algorithmic cost ~ 60742884, 2-norm = 7, extention factor = 16,
pub const PARAM_MESSAGE_1_CARRY_2_PARALLEL_PBS_MS_0_EF_4_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(796),
    glwe_dimension: GlweDimension(4),
    polynomial_size: PolynomialSize(512),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(6.8462551852215656e-06)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.845267479601915e-15)),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(7),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};


// p-fail = 2^-65.418, algorithmic cost ~ 65701539, 2-norm = 5, extention factor = 16,
pub const PARAM_MESSAGE_2_CARRY_2_PARALLEL_PBS_MS_0_EF_4_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(861),
    glwe_dimension: GlweDimension(4),
    polynomial_size: PolynomialSize(512),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.230505012256408e-06)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.845267479601915e-15)),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(5),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(5),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};


// p-fail = 2^-64.237, algorithmic cost ~ 69744750, 2-norm = 10, extention factor = 16,
pub const PARAM_MESSAGE_2_CARRY_3_PARALLEL_PBS_MS_0_EF_4_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(914),
    glwe_dimension: GlweDimension(4),
    polynomial_size: PolynomialSize(512),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(8.938614855855138e-07)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.845267479601915e-15)),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(5),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(10),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};


// p-fail = 2^-64.068, algorithmic cost ~ 89293890, 2-norm = 9, extention factor = 16,
pub const PARAM_MESSAGE_3_CARRY_3_PARALLEL_PBS_MS_0_EF_4_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(958),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(4.1838385960350906e-07)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.845267479601915e-15)),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(9),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};


// p-fail = 2^-64.162, algorithmic cost ~ 141099055, 2-norm = 18, extention factor = 16,
pub const PARAM_MESSAGE_3_CARRY_4_PARALLEL_PBS_MS_0_EF_4_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(977),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(3.0144389706858286e-07)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.845267479601915e-15)),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(18),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};


// p-fail = 2^-64.046, algorithmic cost ~ 196699093, 2-norm = 17, extention factor = 16,
pub const PARAM_MESSAGE_4_CARRY_4_PARALLEL_PBS_MS_0_EF_4_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1067),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(6.380133111167113e-08)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.845267479601915e-15)),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(17),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};


// p-fail = 2^-64.01, algorithmic cost ~ 605109153, 2-norm = 34, extention factor = 16,
pub const PARAM_MESSAGE_4_CARRY_5_PARALLEL_PBS_MS_0_EF_4_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1119),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.60129637762614e-08)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.168404344971009e-19)),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(8),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(32),
    max_noise_level: MaxNoiseLevel::new(34),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

////////////////////
//2^-40 Parallel
////////////////////


// p-fail = 2^-40.861, algorithmic cost ~ 39228714, 2-norm = 3, extention factor = 16,
pub const PARAM_MESSAGE_1_CARRY_1_PARALLEL_PBS_MS_0_EF_4_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(726),
    glwe_dimension: GlweDimension(6),
    polynomial_size: PolynomialSize(256),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.2907006421064675e-05)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(1.9524392655548086e-11)),
    pbs_base_log: DecompositionBaseLog(17),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(3),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};


// p-fail = 2^-40.402, algorithmic cost ~ 58988283, 2-norm = 7, extention factor = 16,
pub const PARAM_MESSAGE_1_CARRY_2_PARALLEL_PBS_MS_0_EF_4_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(773),
    glwe_dimension: GlweDimension(4),
    polynomial_size: PolynomialSize(512),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(1.0181079047914366e-05)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.845267479601915e-15)),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(7),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};


// p-fail = 2^-40.113, algorithmic cost ~ 64480947, 2-norm = 5, extention factor = 16,
pub const PARAM_MESSAGE_2_CARRY_2_PARALLEL_PBS_MS_0_EF_4_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(845),
    glwe_dimension: GlweDimension(4),
    polynomial_size: PolynomialSize(512),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.939628197543817e-06)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.845267479601915e-15)),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(5),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(5),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};


// p-fail = 2^-40.942, algorithmic cost ~ 68142723, 2-norm = 10, extention factor = 16,
pub const PARAM_MESSAGE_2_CARRY_3_PARALLEL_PBS_MS_0_EF_4_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(893),
    glwe_dimension: GlweDimension(4),
    polynomial_size: PolynomialSize(512),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(1.2841767458419213e-06)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.845267479601915e-15)),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(5),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(10),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};


// p-fail = 2^-40.002, algorithmic cost ~ 75343447, 2-norm = 9, extention factor = 16,
pub const PARAM_MESSAGE_3_CARRY_3_PARALLEL_PBS_MS_0_EF_4_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(937),
    glwe_dimension: GlweDimension(4),
    polynomial_size: PolynomialSize(512),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(6.010761532996138e-07)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.845267479601915e-15)),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(9),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};


// p-fail = 2^-40.176, algorithmic cost ~ 132946992, 2-norm = 18, extention factor = 16,
pub const PARAM_MESSAGE_3_CARRY_4_PARALLEL_PBS_MS_0_EF_4_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(976),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(3.066899684081891e-07)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.845267479601915e-15)),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(18),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};


// p-fail = 2^-40.355, algorithmic cost ~ 182799414, 2-norm = 17, extention factor = 16,
pub const PARAM_MESSAGE_4_CARRY_4_PARALLEL_PBS_MS_0_EF_4_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(970),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(3.4014024577352406e-07)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.845267479601915e-15)),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(17),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};


// p-fail = 2^-40.203, algorithmic cost ~ 420801490, 2-norm = 34, extention factor = 16,
pub const PARAM_MESSAGE_4_CARRY_5_PARALLEL_PBS_MS_0_EF_4_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1070),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(6.058296361594748e-08)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.168404344971009e-19)),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(32),
    max_noise_level: MaxNoiseLevel::new(34),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
