use std::ops::RangeInclusive;

use crate::conformance::EnumSet;
use crate::core_crypto::prelude::{CastInto, UnsignedInteger};
use crate::shortint::parameters::{
    Backend, CompactPublicKeyEncryptionParameters, CompressionParameters,
    MetaNoiseSquashingParameters, ShortintKeySwitchingParameters, SupportedCompactPkeZkScheme,
};
use crate::shortint::{
    AtomicPatternParameters, CarryModulus, EncryptionKeyChoice, MessageModulus,
    MultiBitPBSParameters, PBSParameters,
};

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct DedicatedCompactPublicKeyParameters {
    /// Parameters used by the dedicated compact public key
    pub pke_params: CompactPublicKeyEncryptionParameters,
    /// Parameters used to key switch from the compact public key
    /// parameters to compute parameters
    pub ksk_params: ShortintKeySwitchingParameters,
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct MetaParameters {
    pub backend: Backend,
    /// The parameters used by ciphertext when doing computations
    pub compute_parameters: AtomicPatternParameters,
    /// Parameters when using a dedicated compact public key
    /// (For smaller and more efficient CompactCiphertextList)
    pub dedicated_compact_public_key_parameters: Option<DedicatedCompactPublicKeyParameters>,
    /// Parameters for compression CompressedCiphertextList
    pub compression_parameters: Option<CompressionParameters>,
    /// Parameters for noise squashing
    pub noise_squashing_parameters: Option<MetaNoiseSquashingParameters>,
}

impl MetaParameters {
    pub fn noise_distribution_kind(&self) -> NoiseDistributionKind {
        match self.compute_parameters {
            AtomicPatternParameters::Standard(pbsparameters) => match pbsparameters {
                PBSParameters::PBS(pbs) => pbs.lwe_noise_distribution.kind(),
                PBSParameters::MultiBitPBS(multi_bit_pbs) => {
                    multi_bit_pbs.lwe_noise_distribution.kind()
                }
            },
            AtomicPatternParameters::KeySwitch32(key_switch32_pbsparameters) => {
                key_switch32_pbsparameters.lwe_noise_distribution.kind()
            }
        }
    }

    pub fn failure_probability(&self) -> Log2PFail {
        Log2PFail(self.compute_parameters.log2_p_fail())
    }
}

/// Represents the type of noise distribution used in cryptographic operations.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum NoiseDistributionKind {
    Gaussian = 0,
    TUniform = 1,
}

impl CastInto<usize> for NoiseDistributionKind {
    fn cast_into(self) -> usize {
        self as usize
    }
}

/// Struct to express the allowed noise distribution kinds for parameter selection.
///
/// This struct is used to specify which [`NoiseDistributionKind`]s are acceptable
/// when searching for compatible cryptographic parameters.
#[derive(Debug, Copy, Clone)]
pub struct NoiseDistributionChoice(EnumSet<NoiseDistributionKind>);

impl NoiseDistributionChoice {
    /// Creates a new empty choice, i.e. no distributions are allowed.
    ///
    /// Starting point for building a custom choice by then [add]ing allowed noise distributions.
    pub fn new() -> Self {
        Self(EnumSet::new())
    }

    /// Creates new choice that allows all noise distributions.
    pub fn allow_all() -> Self {
        Self::new()
            .allow(NoiseDistributionKind::Gaussian)
            .allow(NoiseDistributionKind::TUniform)
    }

    /// Adds a noise distribution kind to the choice.
    ///
    /// `kind` will be allowed
    pub fn allow(mut self, kind: NoiseDistributionKind) -> Self {
        self.0.insert(kind);
        self
    }

    /// Removes a noise distribution kind from the choice.
    ///
    /// `kind` won't be allowed
    pub fn deny(mut self, kind: NoiseDistributionKind) -> Self {
        self.0.remove(kind);
        self
    }

    fn is_compatible(&self, params: &MetaParameters) -> bool {
        self.0.contains(params.noise_distribution_kind())
    }
}

impl Default for NoiseDistributionChoice {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: UnsignedInteger> super::DynamicDistribution<T> {
    fn kind(&self) -> NoiseDistributionKind {
        match self {
            Self::Gaussian(_) => NoiseDistributionKind::Gaussian,
            Self::TUniform(_) => NoiseDistributionKind::TUniform,
        }
    }
}

/// Represents a constraint on a value
#[derive(Debug)]
pub enum Constraint<T> {
    /// The value must be less than (<) the specified constraint
    LessThan(T),
    /// The value must be less than or equal (<=) tothe specified constraint
    LessThanOrEqual(T),
    /// The value must be greater than (>) the specified constraint
    GreaterThan(T),
    /// The value must be greater than or equal (>=) tothe specified constraint
    GreaterThanOrEqual(T),
    /// The value must be equal to the specified constraint
    Equal(T),
    /// The value must be withing the given range (min..=max)
    Within(RangeInclusive<T>),
}

impl<T> Constraint<T>
where
    T: PartialOrd + PartialEq,
{
    fn is_compatible(&self, value: &T) -> bool {
        match self {
            Self::LessThan(v) => value < v,
            Self::LessThanOrEqual(v) => value <= v,
            Self::GreaterThan(v) => value > v,
            Self::GreaterThanOrEqual(v) => value >= v,
            Self::Equal(v) => value == v,
            Self::Within(range) => range.contains(value),
        }
    }
}

/// Represents the failure probability in logarithmic scale.
///
/// Log2PFail(-x) = failure probability of 2^-128
#[derive(Debug, Copy, Clone, PartialEq, PartialOrd)]
pub struct Log2PFail(pub f64);

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Version(pub u8, pub u8, pub u8);

impl Version {
    fn major(self) -> u8 {
        self.0
    }
    fn minor(self) -> u8 {
        self.1
    }
    fn patch(self) -> u8 {
        self.2
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let major_cmp = self.major().cmp(&other.major());

        if major_cmp != std::cmp::Ordering::Equal {
            return major_cmp;
        }

        let minor_cmp = self.minor().cmp(&other.minor());
        if minor_cmp != std::cmp::Ordering::Equal {
            return minor_cmp;
        }

        self.patch().cmp(&other.patch())
    }
}

/// Allows specification of constraints for the multi-bit PBS
pub struct MultiBitPBSChoice {
    pub(crate) grouping_factor: Constraint<usize>,
}

impl MultiBitPBSChoice {
    /// Creates a new choice with the given `grouping_factor`
    pub fn new(grouping_factor: Constraint<usize>) -> Self {
        Self { grouping_factor }
    }

    fn is_compatible(&self, params: &MultiBitPBSParameters) -> bool {
        self.grouping_factor
            .is_compatible(&params.grouping_factor.0)
    }
}

/// Choices for the AtomicPattern
///
/// 3 Atomic Patterns are available
///
/// * Classic PBS
/// * Multi-Bit PBS
/// * Keyswitch 32-bit
pub struct AtomicPatternChoice {
    classical: bool,
    multibit: Option<MultiBitPBSChoice>,
    keyswitch32: bool,
}

impl AtomicPatternChoice {
    /// Creates a choice which will not allow any atomic pattern
    pub fn new() -> Self {
        Self {
            classical: false,
            multibit: None,
            keyswitch32: false,
        }
    }

    /// Sets the possible choice for classic PBS
    pub fn classic_pbs(mut self, allowed: bool) -> Self {
        self.classical = allowed;
        self
    }

    /// Sets the possible choice for multi-bit PBS
    pub fn multi_bit_pbs(mut self, constraints: Option<MultiBitPBSChoice>) -> Self {
        self.multibit = constraints;
        self
    }

    /// Sets the choice for Keyswitch32
    pub fn keyswitch32(mut self, allowed: bool) -> Self {
        self.keyswitch32 = allowed;
        self
    }

    fn is_compatible(&self, ap: &AtomicPatternParameters) -> bool {
        match ap {
            AtomicPatternParameters::Standard(pbs_params) => match pbs_params {
                PBSParameters::PBS(_) => self.classical,
                PBSParameters::MultiBitPBS(multi_bit_params) => self
                    .multibit
                    .as_ref()
                    .is_some_and(|constraints| constraints.is_compatible(multi_bit_params)),
            },
            AtomicPatternParameters::KeySwitch32(_) => self.keyswitch32,
        }
    }

    fn default_for_device(device: Backend) -> Self {
        match device {
            Backend::Cpu => Self::default_cpu(),
            Backend::CudaGpu => Self::default_gpu(),
        }
    }

    fn default_cpu() -> Self {
        Self {
            classical: true,
            multibit: None,
            keyswitch32: false,
        }
    }

    fn default_gpu() -> Self {
        Self {
            classical: false,
            multibit: Some(MultiBitPBSChoice::new(Constraint::LessThanOrEqual(4))),
            keyswitch32: false,
        }
    }
}

impl Default for AtomicPatternChoice {
    fn default() -> Self {
        Self::new()
    }
}

/// Constraints for the Zero-Knowledge proofs used within Compact Public Encryption
#[derive(Copy, Clone, Debug)]
pub struct CompactPkeZkSchemeChoice(EnumSet<SupportedCompactPkeZkScheme>);

impl CastInto<usize> for SupportedCompactPkeZkScheme {
    fn cast_into(self) -> usize {
        self as usize
    }
}

impl CompactPkeZkSchemeChoice {
    pub fn new() -> Self {
        Self(EnumSet::new())
    }

    pub fn not_used() -> Self {
        Self::new().allow(SupportedCompactPkeZkScheme::ZkNotSupported)
    }

    pub fn allow_all() -> Self {
        Self::new()
            .allow(SupportedCompactPkeZkScheme::V1)
            .allow(SupportedCompactPkeZkScheme::V2)
    }

    pub fn allow(mut self, v: SupportedCompactPkeZkScheme) -> Self {
        self.0.insert(v);
        self
    }

    pub fn deny(mut self, v: SupportedCompactPkeZkScheme) -> Self {
        self.0.remove(v);
        self
    }

    fn is_compatible(&self, v: SupportedCompactPkeZkScheme) -> bool {
        if self.0.contains(SupportedCompactPkeZkScheme::ZkNotSupported) {
            true
        } else {
            self.0.contains(v)
        }
    }
}

impl Default for CompactPkeZkSchemeChoice {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Copy, Clone, Debug)]
pub struct PkeSwitchChoice(EnumSet<EncryptionKeyChoice>);

impl CastInto<usize> for EncryptionKeyChoice {
    fn cast_into(self) -> usize {
        self as usize
    }
}

impl PkeSwitchChoice {
    pub fn new() -> Self {
        Self(EnumSet::new())
    }

    pub fn allow_all() -> Self {
        Self::new()
            .allow(EncryptionKeyChoice::Big)
            .allow(EncryptionKeyChoice::Small)
    }

    pub fn allow(mut self, v: EncryptionKeyChoice) -> Self {
        self.0.insert(v);
        self
    }

    pub fn deny(mut self, v: EncryptionKeyChoice) -> Self {
        self.0.remove(v);
        self
    }

    fn is_compatible(&self, v: EncryptionKeyChoice) -> bool {
        self.0.contains(v)
    }
}

impl Default for PkeSwitchChoice {
    fn default() -> Self {
        Self::new()
    }
}

/// Constraints for the dedicated compact public key
pub struct DedicatedPublicKeyChoice {
    zk_scheme: CompactPkeZkSchemeChoice,
    pke_switch: PkeSwitchChoice,
}

impl DedicatedPublicKeyChoice {
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the Zero-Knowledge scheme constraints
    pub fn with_zk_scheme(mut self, zk_scheme: CompactPkeZkSchemeChoice) -> Self {
        self.zk_scheme = zk_scheme;
        self
    }

    /// Sets the keyswitch constraints scheme constraints
    pub fn with_pke_switch(mut self, pke_switch: PkeSwitchChoice) -> Self {
        self.pke_switch = pke_switch;
        self
    }

    fn is_compatible(&self, dedicated_pk_params: &DedicatedCompactPublicKeyParameters) -> bool {
        self.pke_switch
            .is_compatible(dedicated_pk_params.ksk_params.destination_key)
            && self
                .zk_scheme
                .is_compatible(dedicated_pk_params.pke_params.zk_scheme)
    }
}

impl Default for DedicatedPublicKeyChoice {
    fn default() -> Self {
        Self {
            zk_scheme: CompactPkeZkSchemeChoice::allow_all(),
            pke_switch: PkeSwitchChoice::allow_all(),
        }
    }
}

/// Choices for the noise squashing
#[derive(Copy, Clone, Debug)]
pub enum NoiseSquashingChoice {
    /// Noise squashing required, with or without compression
    Yes { with_compression: bool },
    /// No noise squashing required
    No,
}

impl NoiseSquashingChoice {
    fn is_compatible(self, params: Option<&MetaNoiseSquashingParameters>) -> bool {
        match (self, params) {
            (Self::Yes { .. }, None) => false,
            (Self::Yes { with_compression }, Some(params)) => {
                params.compression_parameters.is_some() == with_compression
            }
            (Self::No, None | Some(_)) => true,
        }
    }
}

const KNOW_PARAMETERS: [(Version, &[(&MetaParameters, &str)]); 1] =
    [(Version(1, 4, 0), &super::v1_4::VEC_ALL_META_PARAMETERS)];

/// Struct that allows to search for known parameters of TFHE-RS given some
/// constraints/choices.
pub struct MetaParameterFinder {
    msg_mod: MessageModulus,
    carry_modulus: CarryModulus,
    failure_probability: Constraint<Log2PFail>,
    version: Version,
    backend: Backend,
    atomic_pattern_choice: AtomicPatternChoice,
    noise_distribution: NoiseDistributionChoice,
    dedicated_compact_public_key_choice: Option<DedicatedPublicKeyChoice>,
    use_compression: bool,
    noise_squashing_choice: NoiseSquashingChoice,
}

impl MetaParameterFinder {
    /// Creates a finder with the given pfail constraint, version and target backend
    ///
    /// * The default message and carry modulus are both 2^2
    /// * The atomic pattern constraints depends on the `backend`
    /// * No other extra 'features' like compression, dedicated public key encryption, noise
    ///   squashing are 'enabled'
    pub fn new(pfail: Constraint<Log2PFail>, version: Version, backend: Backend) -> Self {
        Self {
            msg_mod: MessageModulus(4),
            carry_modulus: CarryModulus(4),
            failure_probability: pfail,
            version,
            backend,
            atomic_pattern_choice: AtomicPatternChoice::default_for_device(backend),
            dedicated_compact_public_key_choice: None,
            use_compression: false,
            noise_squashing_choice: NoiseSquashingChoice::No,
            noise_distribution: NoiseDistributionChoice::allow_all(),
        }
    }

    /// Sets the noise distribution choice
    pub const fn with_noise_distribution(
        mut self,
        noise_distribution: NoiseDistributionChoice,
    ) -> Self {
        self.noise_distribution = noise_distribution;
        self
    }

    /// Sets the atomic pattern choice
    pub const fn with_atomic_pattern(mut self, atomic_pattern_choice: AtomicPatternChoice) -> Self {
        self.atomic_pattern_choice = atomic_pattern_choice;
        self
    }

    /// Sets the dedicated compact public key choice
    pub const fn with_dedicated_compact_public_key(
        mut self,
        choice: Option<DedicatedPublicKeyChoice>,
    ) -> Self {
        self.dedicated_compact_public_key_choice = choice;
        self
    }

    /// Sets whether compression is desired
    pub const fn with_compression(mut self, enabled: bool) -> Self {
        self.use_compression = enabled;
        self
    }

    /// Sets the noise squashing choice
    pub const fn with_noise_squashing(mut self, choice: NoiseSquashingChoice) -> Self {
        self.noise_squashing_choice = choice;
        self
    }

    /// Sets the block moduluses (MessageModulus, CarryModulus)
    ///
    /// Only MessageModulus is required as MessageModulus == CarryModulus is forced
    pub const fn with_block_moduluses(mut self, message_modulus: MessageModulus) -> Self {
        self.msg_mod = message_modulus;
        self.carry_modulus = CarryModulus(message_modulus.0);
        self
    }

    /// Checks if the meta parameter is compatible with the choices of the finder
    ///
    /// A parameter that has more capabilities (e.g. compression), when the user did not ask for
    /// compression is deemed compatible because we can remove the compression params from the
    /// struct.
    fn is_compatible(&self, parameters: &MetaParameters) -> bool {
        if self.backend != parameters.backend {
            return false;
        }

        if self.msg_mod != parameters.compute_parameters.message_modulus()
            || self.carry_modulus != parameters.compute_parameters.carry_modulus()
        {
            return false;
        }

        if !self
            .failure_probability
            .is_compatible(&parameters.failure_probability())
        {
            return false;
        }

        if !self.noise_distribution.is_compatible(parameters) {
            return false;
        }

        if !self
            .atomic_pattern_choice
            .is_compatible(&parameters.compute_parameters)
        {
            return false;
        }

        match (
            self.dedicated_compact_public_key_choice.as_ref(),
            &parameters.dedicated_compact_public_key_parameters,
        ) {
            (None, None | Some(_)) => {}
            (Some(_), None) => return false,
            (Some(choice), Some(params)) => {
                if !choice.is_compatible(params) {
                    return false;
                }
            }
        }

        if self.use_compression && parameters.compression_parameters.is_none() {
            return false;
        }

        if !self
            .noise_squashing_choice
            .is_compatible(parameters.noise_squashing_parameters.as_ref())
        {
            return false;
        }

        true
    }

    /// Returns None if the parameters are not compatible
    /// Returns Some(_) if the parameters are compatible
    ///     The returned params may come from more 'capable' parameters
    ///     where unnecessary params were removed
    fn fit(&self, parameters: &MetaParameters) -> Option<MetaParameters> {
        if self.is_compatible(parameters) {
            let mut result = *parameters;
            if self.dedicated_compact_public_key_choice.is_none() {
                result.dedicated_compact_public_key_parameters = None;
            }

            if !self.use_compression {
                result.compression_parameters = None;
            }

            match self.noise_squashing_choice {
                NoiseSquashingChoice::Yes { with_compression } => {
                    if !with_compression {
                        if let Some(ns_params) = result.noise_squashing_parameters.as_mut() {
                            ns_params.compression_parameters.take();
                        }
                    }
                }
                NoiseSquashingChoice::No => result.noise_squashing_parameters = None,
            }

            Some(result)
        } else {
            None
        }
    }

    /// Returns all known meta parameter that satisfy the choices
    pub fn find_all(&self) -> Vec<MetaParameters> {
        self.named_find_all().into_iter().map(|(p, _)| p).collect()
    }

    /// Tries to find parameters that matches the constraints/choices
    ///
    /// Returns Some(_) if at least 1 compatible parameter was found,
    /// None otherwise
    pub fn find(&self) -> Option<MetaParameters> {
        let mut candidates = self.named_find_all();

        if candidates.is_empty() {
            return None;
        }

        if candidates.len() == 1 {
            return candidates.pop().map(|(param, _)| param);
        }

        // higest failure probability is the last element,
        // and higher failure probability means better performance
        //
        // Since pfails are negative e.g: -128, -40 for 2^-128 and 2^-40
        // the closest pfail the constraint is the last one
        candidates.sort_by(|(a, _), (b, _)| {
            a.failure_probability()
                .partial_cmp(&b.failure_probability())
                .unwrap()
        });

        match self.backend {
            // On CPU we prefer Classical PBS with TUniform
            Backend::Cpu => candidates
                .iter()
                .rfind(|(params, _)| {
                    matches!(
                        params.compute_parameters,
                        AtomicPatternParameters::Standard(PBSParameters::PBS(_))
                    ) && params.noise_distribution_kind() == NoiseDistributionKind::TUniform
                })
                .copied()
                .or_else(|| candidates.pop())
                .map(|(param, _)| param),
            // On GPU we prefer MultiBit PBS with TUniform
            Backend::CudaGpu => candidates
                .iter()
                .rfind(|(params, _)| {
                    matches!(
                        params.compute_parameters,
                        AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(_))
                    ) && params.noise_distribution_kind() == NoiseDistributionKind::TUniform
                })
                .copied()
                .or_else(|| candidates.pop())
                .map(|(param, _)| param),
        }
    }

    /// Returns all known meta parameter that satisfy the choices
    ///
    /// This also returns the name of the original params, as it could help to make
    /// debugging easier
    fn named_find_all(&self) -> Vec<(MetaParameters, &'static str)> {
        let mut candidates = Vec::new();

        for (version, parameter_list) in KNOW_PARAMETERS.iter() {
            if *version != self.version {
                continue; // Skip parameters from different versions
            }

            for (parameters, name) in *parameter_list {
                if let Some(params) = self.fit(parameters) {
                    candidates.push((params, *name));
                }
            }
        }

        candidates
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parameter_finder() {
        {
            let finder = MetaParameterFinder::new(
                Constraint::LessThanOrEqual(Log2PFail(-64.0)),
                Version(1, 4, 0),
                Backend::Cpu,
            )
            .with_compression(true)
            .with_noise_squashing(NoiseSquashingChoice::Yes {
                with_compression: true,
            });

            let params = finder.find();

            let mut expected =
                super::super::v1_4::meta::cpu::V1_4_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_BIG_ZKV1_TUNIFORM_2M128;
            expected.dedicated_compact_public_key_parameters = None;
            assert_eq!(params, Some(expected));

            let finder = MetaParameterFinder::new(
                Constraint::LessThanOrEqual(Log2PFail(-64.0)),
                Version(1, 4, 0),
                Backend::Cpu,
            )
            .with_atomic_pattern(AtomicPatternChoice::new().classic_pbs(true))
            .with_compression(true)
            .with_noise_squashing(NoiseSquashingChoice::Yes {
                with_compression: true,
            });
            let params = finder.find();
            assert_eq!(params.unwrap(), expected);
        }

        {
            // Try to find multi-bit params for CPU
            let finder = MetaParameterFinder::new(
                Constraint::LessThanOrEqual(Log2PFail(-40.0)),
                Version(1, 4, 0),
                Backend::Cpu,
            )
            .with_atomic_pattern(
                AtomicPatternChoice::new()
                    .multi_bit_pbs(Some(MultiBitPBSChoice::new(Constraint::LessThanOrEqual(4)))),
            );
            let params = finder.find();
            assert_eq!(
                params,
                Some(super::super::v1_4::meta::cpu::V1_4_META_PARAM_CPU_2_2_MULTI_BIT_GROUP_4_KS_PBS_GAUSSIAN_2M40)
            );

            // Try to find multi-bit params for GPU
            let finder = MetaParameterFinder::new(
                Constraint::LessThanOrEqual(Log2PFail(-40.0)),
                Version(1, 4, 0),
                Backend::CudaGpu,
            )
            .with_atomic_pattern(
                AtomicPatternChoice::new()
                    .multi_bit_pbs(Some(MultiBitPBSChoice::new(Constraint::LessThanOrEqual(4)))),
            );
            let params = finder.find();

            let mut expected =
                super::super::v1_4::meta::gpu::V1_4_META_PARAM_GPU_2_2_MULTI_BIT_GROUP_3_KS_PBS_TUNIFORM_2M40;
            expected.dedicated_compact_public_key_parameters = None;
            assert_eq!(params, Some(expected));
        }
    }
    #[test]
    fn test_parameter_finder_dedicated_pke() {
        {
            // Select BIG, and dont care about ZK
            let finder = MetaParameterFinder::new(
                Constraint::LessThanOrEqual(Log2PFail(-64.0)),
                Version(1, 4, 0),
                Backend::Cpu,
            )
            .with_dedicated_compact_public_key(Some(
                DedicatedPublicKeyChoice::new()
                    .with_zk_scheme(CompactPkeZkSchemeChoice::not_used())
                    .with_pke_switch(PkeSwitchChoice::new().allow(EncryptionKeyChoice::Big)),
            ));

            let params = finder.find();

            let mut expected =
                super::super::v1_4::meta::cpu::V1_4_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_BIG_ZKV1_TUNIFORM_2M128;
            expected.compression_parameters = None;
            expected.noise_squashing_parameters = None;
            assert_eq!(params, Some(expected));

            // Select SMALL, and dont care about ZK
            let finder = MetaParameterFinder::new(
                Constraint::LessThanOrEqual(Log2PFail(-64.0)),
                Version(1, 4, 0),
                Backend::Cpu,
            )
            .with_dedicated_compact_public_key(Some(
                DedicatedPublicKeyChoice::new()
                    .with_zk_scheme(CompactPkeZkSchemeChoice::not_used())
                    .with_pke_switch(PkeSwitchChoice::new().allow(EncryptionKeyChoice::Small)),
            ));

            let params = finder.find();

            let mut expected =
                super::super::v1_4::meta::cpu::V1_4_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV1_TUNIFORM_2M128;
            expected.compression_parameters = None;
            expected.noise_squashing_parameters = None;
            assert_eq!(params, Some(expected));
        }
    }

    #[test]
    fn test_parameter_finder_ks32() {
        let finder = MetaParameterFinder::new(
            Constraint::LessThanOrEqual(Log2PFail(-64.0)),
            Version(1, 4, 0),
            Backend::Cpu,
        )
        .with_atomic_pattern(AtomicPatternChoice::new().keyswitch32(true));

        let params = finder.find();

        let expected =
            super::super::v1_4::meta::cpu::V1_4_META_PARAM_CPU_2_2_KS32_PBS_TUNIFORM_2M128;
        assert_eq!(params, Some(expected));
    }
}
