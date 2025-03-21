#![allow(clippy::excessive_precision)]
//! Module with the definition of cryptographic parameters.
//!
//! This module provides the structure containing the cryptographic parameters required for the
//! homomorphic evaluation of integer circuits as well as a list of secure cryptographic parameter
//! sets.

use crate::conformance::ListSizeConstraint;
pub use crate::core_crypto::commons::dispersion::{StandardDev, Variance};
pub use crate::core_crypto::commons::parameters::{
    CiphertextModulus as CoreCiphertextModulus, CiphertextModulusLog, DecompositionBaseLog,
    DecompositionLevelCount, DynamicDistribution, EncryptionKeyChoice, GlweDimension,
    LweBskGroupingFactor, LweCiphertextCount, LweDimension, NoiseEstimationMeasureBound,
    PolynomialSize, RSigmaFactor,
};
use crate::core_crypto::fft_impl::fft64::crypto::bootstrap::LweBootstrapKeyConformanceParams;
use crate::core_crypto::prelude::{
    GlweCiphertextConformanceParams, LweCiphertextConformanceParams,
    LweCiphertextListConformanceParams, LweKeyswitchKeyConformanceParams,
};
use crate::shortint::backward_compatibility::parameters::*;
#[cfg(feature = "zk-pok")]
use crate::zk::CompactPkeZkScheme;
use serde::{Deserialize, Serialize};

use tfhe_versionable::Versionize;

pub mod aliases;
pub mod classic;
pub mod compact_public_key_only;
#[cfg(tarpaulin)]
pub mod coverage_parameters;
pub mod key_switching;
pub mod list_compression;
pub mod multi_bit;
pub mod noise_squashing;
pub mod parameters_wopbs;
pub mod parameters_wopbs_message_carry;
pub mod parameters_wopbs_only;
#[cfg(test)]
pub mod test_params;
pub mod v0_10;
pub mod v0_11;
pub mod v1_0;
pub mod v1_1;

// TODO, what do we do about this one ?
pub use aliases::*;
pub use v1_1 as current_params;

use super::backward_compatibility::parameters::modulus_switch_noise_reduction::ModulusSwitchNoiseReductionParamsVersions;
pub use super::ciphertext::{Degree, MaxNoiseLevel, NoiseLevel};
use super::server_key::PBSConformanceParams;
pub use super::PBSOrder;
use crate::shortint::ciphertext::MaxDegree;
pub use crate::shortint::parameters::list_compression::CompressionParameters;
pub use classic::ClassicPBSParameters;
pub use compact_public_key_only::{
    CastingFunctionsOwned, CastingFunctionsView, CompactCiphertextListExpansionKind,
    CompactPublicKeyEncryptionParameters, ShortintCompactCiphertextListCastingMode,
};
#[cfg(tarpaulin)]
pub use coverage_parameters::*;
pub use key_switching::ShortintKeySwitchingParameters;
pub use multi_bit::MultiBitPBSParameters;
pub use noise_squashing::NoiseSquashingParameters;
pub use parameters_wopbs::*;

/// The modulus of the message space. For a given plaintext $p$ we have the message $m$ defined as
/// $m = p\bmod{MessageModulus}$ and so $0 <= m < MessageModulus$.
///
/// # Note
///
/// The total plaintext modulus is given by $MessageModulus \times CarryModulus$
#[derive(Debug, Hash, PartialEq, Eq, Copy, Clone, Serialize, Deserialize, Versionize)]
#[versionize(MessageModulusVersions)]
pub struct MessageModulus(pub u64);

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
#[derive(Debug, Hash, PartialEq, Eq, Copy, Clone, Serialize, Deserialize, Versionize)]
#[versionize(CarryModulusVersions)]
pub struct CarryModulus(pub u64);

/// Determines in what ring computations are made
pub type CiphertextModulus = CoreCiphertextModulus<u64>;

impl From<&PBSConformanceParams> for LweBootstrapKeyConformanceParams<u64> {
    fn from(value: &PBSConformanceParams) -> Self {
        Self {
            decomp_base_log: value.base_log,
            decomp_level_count: value.level,
            input_lwe_dimension: value.in_lwe_dimension,
            output_glwe_size: value.out_glwe_dimension.to_glwe_size(),
            polynomial_size: value.out_polynomial_size,
            ciphertext_modulus: value.ciphertext_modulus,
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
    pub ct_params: LweCiphertextConformanceParams<u64>,
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
    pub ct_params: GlweCiphertextConformanceParams<u64>,
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
#[derive(Copy, Clone)]
pub struct CiphertextListConformanceParams {
    pub ct_list_params: LweCiphertextListConformanceParams<u64>,
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
    pub degree: Degree,
    pub expansion_kind: CompactCiphertextListExpansionKind,
}

impl CiphertextConformanceParams {
    pub fn to_ct_list_conformance_parameters(
        &self,
        list_constraint: ListSizeConstraint,
    ) -> CiphertextListConformanceParams {
        CiphertextListConformanceParams {
            ct_list_params: LweCiphertextListConformanceParams {
                lwe_dim: self.ct_params.lwe_dim,
                ct_modulus: self.ct_params.ct_modulus,
                lwe_ciphertext_count_constraint: list_constraint,
            },
            message_modulus: self.message_modulus,
            carry_modulus: self.carry_modulus,
            degree: self.degree,
            expansion_kind: self.pbs_order.into(),
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

impl From<&PBSParameters> for LweKeyswitchKeyConformanceParams {
    fn from(value: &PBSParameters) -> Self {
        Self {
            decomp_base_log: value.ks_base_log(),
            decomp_level_count: value.ks_level(),
            output_lwe_size: value.lwe_dimension().to_lwe_size(),
            input_lwe_dimension: value
                .glwe_dimension()
                .to_equivalent_lwe_dimension(value.polynomial_size()),
            ciphertext_modulus: value.ciphertext_modulus(),
        }
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
#[allow(clippy::large_enum_variant)]
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

/// The Zk scheme for compact private key encryption supported by these parameters.
///
/// The Zk Scheme is available in 2 versions. In case of doubt, you should prefer the V2 which is
/// more efficient.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Versionize)]
#[versionize(SupportedCompactPkeZkSchemeVersions)]
pub enum SupportedCompactPkeZkScheme {
    /// The given parameters do not support zk proof of encryption
    ZkNotSupported,
    V1,
    V2,
}

#[cfg(feature = "zk-pok")]
impl TryFrom<SupportedCompactPkeZkScheme> for CompactPkeZkScheme {
    type Error = ();

    fn try_from(value: SupportedCompactPkeZkScheme) -> Result<Self, Self::Error> {
        match value {
            SupportedCompactPkeZkScheme::ZkNotSupported => Err(()),
            SupportedCompactPkeZkScheme::V1 => Ok(Self::V1),
            SupportedCompactPkeZkScheme::V2 => Ok(Self::V2),
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(ModulusSwitchNoiseReductionParamsVersions)]
pub struct ModulusSwitchNoiseReductionParams {
    pub modulus_switch_zeros_count: LweCiphertextCount,
    pub ms_bound: NoiseEstimationMeasureBound,
    pub ms_r_sigma_factor: RSigmaFactor,
    pub ms_input_variance: Variance,
}
