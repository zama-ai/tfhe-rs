pub mod backward_compatibility;

use crate::conformance::{EnumSet, ParameterSetConformant};
use crate::core_crypto::commons::math::random::{
    BoundedDistribution, ByteRandomGenerator, RandomGenerator,
};
use crate::core_crypto::prelude::*;
use crate::named::Named;
#[cfg(feature = "shortint")]
use crate::shortint::parameters::CompactPublicKeyEncryptionParameters;
use backward_compatibility::*;
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::Bound;
use std::fmt::Debug;
use tfhe_versionable::Versionize;

use tfhe_zk_pok::proofs::pke::{
    commit as commit_v1, crs_gen as crs_gen_v1, verify as verify_v1, Proof as ProofV1,
    PublicCommit as PublicCommitV1,
};

use tfhe_zk_pok::proofs::pke_v2::{
    commit as commit_v2, crs_gen as crs_gen_v2, PkeV2SupportedHashConfig, Proof as ProofV2,
    PublicCommit as PublicCommitV2, VerificationPairingMode,
};

#[cfg(not(feature = "gpu-experimental-zk"))]
use tfhe_zk_pok::proofs::pke::prove as prove_v1;

#[cfg(not(feature = "gpu-experimental-zk"))]
use tfhe_zk_pok::proofs::pke_v2::{prove as prove_v2, verify as verify_v2};

pub use tfhe_zk_pok::curve_api::Compressible;
pub use tfhe_zk_pok::proofs::pke_v2::PkeV2SupportedHashConfig as ZkPkeV2SupportedHashConfig;
pub use tfhe_zk_pok::proofs::ComputeLoad as ZkComputeLoad;
type Curve = tfhe_zk_pok::curve_api::Bls12_446;

#[derive(Clone, Debug, Serialize, Deserialize, Versionize)]
#[versionize(CompactPkeProofVersions)]
#[allow(clippy::large_enum_variant)]
pub enum CompactPkeProof {
    PkeV1(ProofV1<Curve>),
    PkeV2(ProofV2<Curve>),
}

impl Named for CompactPkeProof {
    const NAME: &'static str = "zk::CompactPkeProof";
}

impl CastInto<usize> for ZkComputeLoad {
    fn cast_into(self) -> usize {
        self as usize
    }
}

impl CastInto<usize> for ZkPkeV2SupportedHashConfig {
    fn cast_into(self) -> usize {
        self as usize
    }
}

#[derive(Copy, Clone)]
/// Used to explicitly reject [`ProofV1`] proofs that come with specific config
pub struct CompactPkeV1ProofConformanceParams {
    accepted_compute_load: EnumSet<ZkComputeLoad>,
}

impl Default for CompactPkeV1ProofConformanceParams {
    fn default() -> Self {
        Self::new()
    }
}

impl CompactPkeV1ProofConformanceParams {
    /// Create new params that accept all proof configurations
    pub fn new() -> Self {
        let mut accepted_compute_load = EnumSet::new();
        accepted_compute_load.insert(ZkComputeLoad::Proof);
        accepted_compute_load.insert(ZkComputeLoad::Verify);

        Self {
            accepted_compute_load,
        }
    }

    /// Forbid proofs coming with the provided [`ZkComputeLoad`]
    pub fn forbid_compute_load(self, forbidden_compute_load: ZkComputeLoad) -> Self {
        let mut accepted_compute_load = self.accepted_compute_load;
        accepted_compute_load.remove(forbidden_compute_load);

        Self {
            accepted_compute_load,
        }
    }
}

impl ParameterSetConformant for ProofV1<Curve> {
    type ParameterSet = CompactPkeV1ProofConformanceParams;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        parameter_set
            .accepted_compute_load
            .contains(self.compute_load())
            && self.is_usable()
    }
}

#[derive(Copy, Clone)]
/// Used to explicitly reject [`ProofV2`] proofs that come with specific config
pub struct CompactPkeV2ProofConformanceParams {
    accepted_compute_load: EnumSet<ZkComputeLoad>,
    accepted_hash_config: EnumSet<PkeV2SupportedHashConfig>,
}

impl Default for CompactPkeV2ProofConformanceParams {
    fn default() -> Self {
        Self::new()
    }
}

impl CompactPkeV2ProofConformanceParams {
    /// Create new params that accept all proof configurations
    pub fn new() -> Self {
        let mut accepted_compute_load = EnumSet::new();
        accepted_compute_load.insert(ZkComputeLoad::Proof);
        accepted_compute_load.insert(ZkComputeLoad::Verify);

        let mut accepted_hash_config = EnumSet::new();
        accepted_hash_config.insert(PkeV2SupportedHashConfig::V0_4_0);
        accepted_hash_config.insert(PkeV2SupportedHashConfig::V0_7_0);
        accepted_hash_config.insert(PkeV2SupportedHashConfig::V0_8_0);

        Self {
            accepted_compute_load,
            accepted_hash_config,
        }
    }

    /// Forbid proofs coming with the provided [`ZkComputeLoad`]
    pub fn forbid_compute_load(self, forbidden_compute_load: ZkComputeLoad) -> Self {
        let mut accepted_compute_load = self.accepted_compute_load;
        accepted_compute_load.remove(forbidden_compute_load);

        Self {
            accepted_compute_load,
            ..self
        }
    }

    /// Forbid proofs coming with the provided [`ZkPkeV2SupportedHashConfig`]
    pub fn forbid_hash_config(self, forbidden_hash_config: ZkPkeV2SupportedHashConfig) -> Self {
        let mut accepted_hash_config = self.accepted_hash_config;
        accepted_hash_config.remove(forbidden_hash_config);

        Self {
            accepted_hash_config,
            ..self
        }
    }
}

impl ParameterSetConformant for ProofV2<Curve> {
    type ParameterSet = CompactPkeV2ProofConformanceParams;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        parameter_set
            .accepted_compute_load
            .contains(self.compute_load())
            && parameter_set
                .accepted_hash_config
                .contains(self.hash_config())
            && self.is_usable()
    }
}

#[derive(Copy, Clone)]
/// Used to specify the kind of proofs that are allowed to be checked by the verifier.
///
/// As this happens during conformance checks, proofs that do not match the correct config will be
/// rejected before zk verification
pub enum CompactPkeProofConformanceParams {
    PkeV1(CompactPkeV1ProofConformanceParams),
    PkeV2(CompactPkeV2ProofConformanceParams),
}

impl CompactPkeProofConformanceParams {
    pub fn new(zk_scheme: CompactPkeZkScheme) -> Self {
        match zk_scheme {
            CompactPkeZkScheme::V1 => Self::PkeV1(CompactPkeV1ProofConformanceParams::new()),
            CompactPkeZkScheme::V2 => Self::PkeV2(CompactPkeV2ProofConformanceParams::new()),
        }
    }

    /// Forbid proofs coming with the provided [`ZkComputeLoad`]
    pub fn forbid_compute_load(self, forbidden_compute_load: ZkComputeLoad) -> Self {
        match self {
            Self::PkeV1(params) => Self::PkeV1(params.forbid_compute_load(forbidden_compute_load)),
            Self::PkeV2(params) => Self::PkeV2(params.forbid_compute_load(forbidden_compute_load)),
        }
    }

    /// Forbid proofs coming with the provided [`ZkPkeV2SupportedHashConfig`]. This has no effect on
    /// PkeV1 proofs
    pub fn forbid_hash_config(self, forbidden_hash_config: ZkPkeV2SupportedHashConfig) -> Self {
        match self {
            // There is no hash mode to configure in PkeV1
            Self::PkeV1(params) => Self::PkeV1(params),
            Self::PkeV2(params) => Self::PkeV2(params.forbid_hash_config(forbidden_hash_config)),
        }
    }
}

impl ParameterSetConformant for CompactPkeProof {
    type ParameterSet = CompactPkeProofConformanceParams;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        match (self, parameter_set) {
            (Self::PkeV1(proof), CompactPkeProofConformanceParams::PkeV1(params)) => {
                proof.is_conformant(params)
            }
            (Self::PkeV2(proof), CompactPkeProofConformanceParams::PkeV2(params)) => {
                proof.is_conformant(params)
            }
            (Self::PkeV1(_), CompactPkeProofConformanceParams::PkeV2(_))
            | (Self::PkeV2(_), CompactPkeProofConformanceParams::PkeV1(_)) => false,
        }
    }
}

pub type ZkCompactPkeV1PublicParams = tfhe_zk_pok::proofs::pke::PublicParams<Curve>;
pub type ZkCompactPkeV2PublicParams = tfhe_zk_pok::proofs::pke_v2::PublicParams<Curve>;

// Keep this to be able to deserialize CRS that were serialized as "CompactPkePublicParams" (TFHE-rs
// 0.10 and before)
pub type SerializableCompactPkePublicParams =
    tfhe_zk_pok::serialization::SerializablePKEv1PublicParams;

impl Named for ZkCompactPkeV1PublicParams {
    const NAME: &'static str = "zk::CompactPkePublicParams";
}

pub struct CompactPkeCrsConformanceParams {
    lwe_dim: LweDimension,
    max_num_message: LweCiphertextCount,
    noise_bound: u64,
    ciphertext_modulus: u64,
    plaintext_modulus: u64,
    msbs_zero_padding_bit_count: ZkMSBZeroPaddingBitCount,
}

#[cfg(feature = "shortint")]
impl CompactPkeCrsConformanceParams {
    pub fn new<E, P: TryInto<CompactPublicKeyEncryptionParameters, Error = E>>(
        value: P,
        max_num_message: LweCiphertextCount,
    ) -> Result<Self, crate::Error>
    where
        E: Into<crate::Error>,
    {
        let params: CompactPublicKeyEncryptionParameters =
            value.try_into().map_err(|e| e.into())?;

        let mut plaintext_modulus = params.message_modulus.0 * params.carry_modulus.0;
        // Add 1 bit of modulus for the padding bit
        plaintext_modulus *= 2;

        let (lwe_dim, max_num_message, noise_bound, ciphertext_modulus, plaintext_modulus) =
            CompactPkeCrs::prepare_crs_parameters(
                params.encryption_lwe_dimension,
                max_num_message,
                params.encryption_noise_distribution,
                params.ciphertext_modulus,
                plaintext_modulus,
                CompactPkeZkScheme::V2,
            )?;

        Ok(Self {
            lwe_dim,
            max_num_message,
            noise_bound,
            ciphertext_modulus,
            plaintext_modulus,
            // CRS created from shortint params have 1 MSB 0bit
            msbs_zero_padding_bit_count: ZkMSBZeroPaddingBitCount(1),
        })
    }
}

impl ParameterSetConformant for ZkCompactPkeV1PublicParams {
    type ParameterSet = CompactPkeCrsConformanceParams;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        self.k <= self.d
            && self.d == parameter_set.lwe_dim.0
            && self.k == parameter_set.max_num_message.0
            && self.b == parameter_set.noise_bound
            && self.q == parameter_set.ciphertext_modulus
            && self.t == parameter_set.plaintext_modulus
            && self.msbs_zero_padding_bit_count == parameter_set.msbs_zero_padding_bit_count.0
            && self.is_usable()
    }
}

impl ParameterSetConformant for ZkCompactPkeV2PublicParams {
    type ParameterSet = CompactPkeCrsConformanceParams;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        self.k <= self.d
            && self.d == parameter_set.lwe_dim.0
            && self.k == parameter_set.max_num_message.0
            && self.B_inf == parameter_set.noise_bound
            && self.q == parameter_set.ciphertext_modulus
            && self.t == parameter_set.plaintext_modulus
            && self.msbs_zero_padding_bit_count == parameter_set.msbs_zero_padding_bit_count.0
            && self.is_usable()
    }
}

// If we call `CompactPkePublicParams::compress` we end up with a
// `SerializableCompactPkePublicParams` that should also impl Named to be serializable with
// `safe_serialization`. Since the `CompactPkePublicParams` is transformed into a
// `SerializableCompactPkePublicParams` anyways before serialization, their impl of `Named` should
// return the same string.
impl Named for SerializableCompactPkePublicParams {
    const NAME: &'static str = ZkCompactPkeV1PublicParams::NAME;
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum ZkVerificationOutcome {
    /// The proof and its entity were valid
    Valid,
    /// The proof and its entity were not
    Invalid,
}

impl ZkVerificationOutcome {
    pub fn is_valid(self) -> bool {
        self == Self::Valid
    }

    pub fn is_invalid(self) -> bool {
        self == Self::Invalid
    }
}

/// The Zk Scheme for compact private key encryption is available in 2 versions. In case of doubt,
/// you should prefer the V2 which is more efficient.
#[derive(Clone, Copy)]
pub enum CompactPkeZkScheme {
    V1,
    V2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkMSBZeroPaddingBitCount(pub u64);

/// The CRS (Common Reference String) of a ZK scheme is a set of values shared between the prover
/// and the verifier.
///
/// The same CRS should be used at the prove and verify steps.
#[derive(Clone, Debug, Serialize, Deserialize, Versionize)]
#[versionize(CompactPkeCrsVersions)]
#[allow(clippy::large_enum_variant)]
pub enum CompactPkeCrs {
    PkeV1(ZkCompactPkeV1PublicParams),
    PkeV2(ZkCompactPkeV2PublicParams),
}

impl Named for CompactPkeCrs {
    const NAME: &'static str = "zk::CompactPkeCrs";

    const BACKWARD_COMPATIBILITY_ALIASES: &'static [&'static str] = &["zk::CompactPkePublicParams"];
}

impl From<ZkCompactPkeV1PublicParams> for CompactPkeCrs {
    fn from(value: ZkCompactPkeV1PublicParams) -> Self {
        Self::PkeV1(value)
    }
}

impl From<ZkCompactPkeV2PublicParams> for CompactPkeCrs {
    fn from(value: ZkCompactPkeV2PublicParams) -> Self {
        Self::PkeV2(value)
    }
}

impl CompactPkeCrs {
    /// Compute the bound used by the V1 Scheme from the noise distribution
    fn compute_bound_v1<Scalar, NoiseDistribution>(
        noise_distribution: NoiseDistribution,
    ) -> Result<Scalar, String>
    where
        Scalar: UnsignedInteger + CastInto<u64> + Debug,
        NoiseDistribution: BoundedDistribution<Scalar::Signed>,
    {
        let high_bound = match noise_distribution.high_bound() {
            Bound::Included(high_b) => high_b,
            Bound::Excluded(high_b) => high_b - Scalar::Signed::ONE,
            Bound::Unbounded => {
                return Err("requires bounded distribution".into());
            }
        };

        let low_bound = match noise_distribution.low_bound() {
            Bound::Included(low_b) => low_b,
            Bound::Excluded(low_b) => low_b + Scalar::Signed::ONE,
            Bound::Unbounded => {
                return Err("requires bounded distribution".into());
            }
        };

        if high_bound != -low_bound {
            return Err("requires a distribution centered around 0".into());
        }

        // The bound for the crs has to be a power of two,
        // it is [-b, b) (non-inclusive for the high bound)
        // so we may have to give a bound that is bigger than
        // what the distribution generates
        let high_bound = high_bound.wrapping_abs().into_unsigned();
        if high_bound.is_power_of_two() {
            Ok(high_bound * Scalar::TWO)
        } else {
            Ok(high_bound.next_power_of_two())
        }
    }

    /// Compute the bound used by the V2 Scheme from the noise distribution
    fn compute_bound_v2<Scalar, NoiseDistribution>(
        noise_distribution: NoiseDistribution,
    ) -> Result<Scalar, String>
    where
        Scalar: UnsignedInteger + CastInto<u64> + Debug,
        NoiseDistribution: BoundedDistribution<Scalar::Signed>,
    {
        // For zk v2 scheme, the proof is valid for an inclusive range on the noise bound
        let high_bound = match noise_distribution.high_bound() {
            Bound::Included(high_b) => high_b,
            Bound::Excluded(high_b) => high_b - Scalar::Signed::ONE,
            Bound::Unbounded => {
                return Err("requires bounded distribution".into());
            }
        };

        let low_bound = match noise_distribution.low_bound() {
            Bound::Included(low_b) => low_b,
            Bound::Excluded(low_b) => low_b + Scalar::Signed::ONE,
            Bound::Unbounded => {
                return Err("requires bounded distribution".into());
            }
        };

        if high_bound != -low_bound {
            return Err("requires a distribution centered around 0".into());
        }

        Ok(high_bound.wrapping_abs().into_unsigned())
    }

    /// Prepare and check the CRS parameters.
    ///
    /// The output of this function can be used in [tfhe_zk_pok::proofs::pke::compute_crs_params].
    pub fn prepare_crs_parameters<Scalar, NoiseDistribution>(
        lwe_dim: LweDimension,
        max_num_cleartext: LweCiphertextCount,
        noise_distribution: NoiseDistribution,
        ciphertext_modulus: CiphertextModulus<Scalar>,
        plaintext_modulus: Scalar,
        zk_scheme: CompactPkeZkScheme,
    ) -> crate::Result<(LweDimension, LweCiphertextCount, Scalar, u64, Scalar)>
    where
        Scalar: UnsignedInteger + CastInto<u64> + Debug,
        NoiseDistribution: BoundedDistribution<Scalar::Signed>,
    {
        if max_num_cleartext.0 > lwe_dim.0 {
            return Err("Maximum number of cleartexts is greater than the lwe dimension".into());
        }

        let noise_bound = match zk_scheme {
            CompactPkeZkScheme::V1 => Self::compute_bound_v1(noise_distribution)?,
            CompactPkeZkScheme::V2 => Self::compute_bound_v2(noise_distribution)?,
        };

        if Scalar::BITS > 64 && noise_bound >= (Scalar::ONE << 64usize) {
            return Err("noise bounds exceeds 64 bits modulus".into());
        }

        if Scalar::BITS > 64 && plaintext_modulus >= (Scalar::ONE << 64usize) {
            return Err("Plaintext modulus exceeds 64 bits modulus".into());
        }

        let q = if ciphertext_modulus.is_native_modulus() {
            match Scalar::BITS.cmp(&64) {
                Ordering::Greater => Err(
                    "Zero Knowledge proof do not support ciphertext modulus > 64 bits".to_string(),
                ),
                Ordering::Equal => Ok(0u64),
                Ordering::Less => Ok(1u64 << Scalar::BITS),
            }
        } else {
            let custom_modulus = ciphertext_modulus.get_custom_modulus();
            if custom_modulus > (u64::MAX) as u128 {
                Err("Zero Knowledge proof do not support ciphertext modulus > 64 bits".to_string())
            } else {
                Ok(custom_modulus as u64)
            }
        }?;

        Ok((
            lwe_dim,
            max_num_cleartext,
            noise_bound,
            q,
            plaintext_modulus,
        ))
    }

    /// Generates a new zk CRS from the tfhe parameters. This the v1 Zk PKE scheme which is less
    /// efficient.
    pub fn new_legacy_v1<Scalar, NoiseDistribution>(
        lwe_dim: LweDimension,
        max_num_cleartext: LweCiphertextCount,
        noise_distribution: NoiseDistribution,
        ciphertext_modulus: CiphertextModulus<Scalar>,
        plaintext_modulus: Scalar,
        msbs_zero_padding_bit_count: ZkMSBZeroPaddingBitCount,
        rng: &mut impl RngCore,
    ) -> crate::Result<Self>
    where
        Scalar: UnsignedInteger + CastInto<u64> + Debug,
        NoiseDistribution: BoundedDistribution<Scalar::Signed>,
    {
        let (d, k, b, q, t) = Self::prepare_crs_parameters(
            lwe_dim,
            max_num_cleartext,
            noise_distribution,
            ciphertext_modulus,
            plaintext_modulus,
            CompactPkeZkScheme::V1,
        )?;
        let public_params = crs_gen_v1(
            d.0,
            k.0,
            b.cast_into(),
            q,
            t.cast_into(),
            msbs_zero_padding_bit_count.0,
            rng,
        );

        Ok(Self::PkeV1(public_params))
    }

    /// Generates a new zk CRS from the tfhe parameters.
    pub fn new<Scalar, NoiseDistribution>(
        lwe_dim: LweDimension,
        max_num_cleartext: LweCiphertextCount,
        noise_distribution: NoiseDistribution,
        ciphertext_modulus: CiphertextModulus<Scalar>,
        plaintext_modulus: Scalar,
        msbs_zero_padding_bit_count: ZkMSBZeroPaddingBitCount,
        rng: &mut impl RngCore,
    ) -> crate::Result<Self>
    where
        Scalar: UnsignedInteger + CastInto<u64> + Debug,
        NoiseDistribution: BoundedDistribution<Scalar::Signed>,
    {
        let (d, k, b, q, t) = Self::prepare_crs_parameters(
            lwe_dim,
            max_num_cleartext,
            noise_distribution,
            ciphertext_modulus,
            plaintext_modulus,
            CompactPkeZkScheme::V2,
        )?;
        let public_params = crs_gen_v2(
            d.0,
            k.0,
            b.cast_into(),
            q,
            t.cast_into(),
            msbs_zero_padding_bit_count.0,
            rng,
        );

        Ok(Self::PkeV2(public_params))
    }

    /// Maximum number of messages that can be proven in a single list using this CRS
    pub fn max_num_messages(&self) -> LweCiphertextCount {
        match self {
            Self::PkeV1(public_params) => LweCiphertextCount(public_params.k),
            Self::PkeV2(public_params) => LweCiphertextCount(public_params.k),
        }
    }

    /// Lwe dimension supported by this CRS
    pub fn lwe_dimension(&self) -> LweDimension {
        match self {
            Self::PkeV1(public_params) => LweDimension(public_params.d),
            Self::PkeV2(public_params) => LweDimension(public_params.d),
        }
    }

    /// Modulus of the ciphertexts supported by this CRS
    pub fn ciphertext_modulus<Scalar: UnsignedInteger>(&self) -> CiphertextModulus<Scalar> {
        match self {
            Self::PkeV1(public_params) => CiphertextModulus::new(public_params.q as u128),
            Self::PkeV2(public_params) => CiphertextModulus::new(public_params.q as u128),
        }
    }

    /// Modulus of the plaintexts supported by this CRS
    pub fn plaintext_modulus(&self) -> u64 {
        match self {
            Self::PkeV1(public_params) => public_params.t,
            Self::PkeV2(public_params) => public_params.t,
        }
    }

    /// Upper bound on the noise accepted by this CRS
    pub fn exclusive_max_noise(&self) -> u64 {
        match self {
            Self::PkeV1(public_params) => public_params.exclusive_max_noise(),
            Self::PkeV2(public_params) => public_params.exclusive_max_noise(),
        }
    }

    /// Return the version of the zk scheme used by this CRS
    pub fn scheme_version(&self) -> CompactPkeZkScheme {
        match self {
            Self::PkeV1(_) => CompactPkeZkScheme::V1,
            Self::PkeV2(_) => CompactPkeZkScheme::V2,
        }
    }

    /// Prove a ciphertext list encryption using this CRS
    #[allow(clippy::too_many_arguments)]
    pub fn prove<Scalar, KeyCont, InputCont, ListCont, G>(
        &self,
        compact_public_key: &LweCompactPublicKey<KeyCont>,
        messages: &InputCont,
        lwe_compact_list: &LweCompactCiphertextList<ListCont>,
        binary_random_vector: &[Scalar],
        mask_noise: &[Scalar],
        body_noise: &[Scalar],
        metadata: &[u8],
        load: ZkComputeLoad,
        random_generator: &mut RandomGenerator<G>,
    ) -> CompactPkeProof
    where
        Scalar: UnsignedInteger,
        i64: CastFrom<Scalar>,
        KeyCont: Container<Element = Scalar>,
        InputCont: Container<Element = Scalar>,
        ListCont: Container<Element = Scalar>,
        G: ByteRandomGenerator,
    {
        let key_mask = compact_public_key
            .get_mask()
            .as_ref()
            .iter()
            .copied()
            .map(|x| i64::cast_from(x))
            .collect();
        let key_body = compact_public_key
            .get_body()
            .as_ref()
            .iter()
            .copied()
            .map(|x| i64::cast_from(x))
            .collect();

        let ct_mask = lwe_compact_list
            .get_mask_list()
            .as_ref()
            .iter()
            .copied()
            .map(|x| i64::cast_from(x))
            .collect();
        let ct_body = lwe_compact_list
            .get_body_list()
            .as_ref()
            .iter()
            .copied()
            .map(|x| i64::cast_from(x))
            .collect();

        let binary_random_vector = binary_random_vector
            .iter()
            .copied()
            .map(CastFrom::cast_from)
            .collect::<Vec<_>>();

        let mask_noise = mask_noise
            .iter()
            .copied()
            .map(CastFrom::cast_from)
            .collect::<Vec<_>>();

        let messages = messages
            .as_ref()
            .iter()
            .copied()
            .map(CastFrom::cast_from)
            .collect::<Vec<_>>();

        let body_noise = body_noise
            .iter()
            .copied()
            .map(CastFrom::cast_from)
            .collect::<Vec<_>>();

        // 128bits seed as defined in the NIST document
        let mut seed = [0u8; 16];
        random_generator.fill_bytes(&mut seed);

        match self {
            Self::PkeV1(public_params) => {
                let (public_commit, private_commit) = commit_v1(
                    key_mask,
                    key_body,
                    ct_mask,
                    ct_body,
                    binary_random_vector,
                    mask_noise,
                    messages,
                    body_noise,
                    public_params,
                );

                #[cfg(feature = "gpu-experimental-zk")]
                let proof = tfhe_zk_pok::proofs::pke::gpu::prove(
                    (public_params, &public_commit),
                    &private_commit,
                    metadata,
                    load,
                    &seed,
                );
                #[cfg(not(feature = "gpu-experimental-zk"))]
                let proof = prove_v1(
                    (public_params, &public_commit),
                    &private_commit,
                    metadata,
                    load,
                    &seed,
                );

                CompactPkeProof::PkeV1(proof)
            }
            Self::PkeV2(public_params) => {
                let (public_commit, private_commit) = commit_v2(
                    key_mask,
                    key_body,
                    ct_mask,
                    ct_body,
                    binary_random_vector,
                    mask_noise,
                    messages,
                    body_noise,
                    public_params,
                );

                #[cfg(feature = "gpu-experimental-zk")]
                let proof = tfhe_zk_pok::proofs::pke_v2::gpu::prove(
                    (public_params, &public_commit),
                    &private_commit,
                    metadata,
                    load,
                    &seed,
                );
                #[cfg(not(feature = "gpu-experimental-zk"))]
                let proof = prove_v2(
                    (public_params, &public_commit),
                    &private_commit,
                    metadata,
                    load,
                    &seed,
                );

                CompactPkeProof::PkeV2(proof)
            }
        }
    }

    /// Verify the validity of a proof using this CRS
    pub fn verify<Scalar, ListCont, KeyCont>(
        &self,
        lwe_compact_list: &LweCompactCiphertextList<ListCont>,
        compact_public_key: &LweCompactPublicKey<KeyCont>,
        proof: &CompactPkeProof,
        metadata: &[u8],
    ) -> ZkVerificationOutcome
    where
        Scalar: UnsignedInteger,
        i64: CastFrom<Scalar>,
        ListCont: Container<Element = Scalar>,
        KeyCont: Container<Element = Scalar>,
    {
        if Scalar::BITS > 64 {
            return ZkVerificationOutcome::Invalid;
        }

        let key_mask = compact_public_key
            .get_mask()
            .as_ref()
            .iter()
            .copied()
            .map(|x| i64::cast_from(x))
            .collect();
        let key_body = compact_public_key
            .get_body()
            .as_ref()
            .iter()
            .copied()
            .map(|x| i64::cast_from(x))
            .collect();

        let ct_mask = lwe_compact_list
            .get_mask_list()
            .as_ref()
            .iter()
            .copied()
            .map(|x| i64::cast_from(x))
            .collect();
        let ct_body = lwe_compact_list
            .get_body_list()
            .as_ref()
            .iter()
            .copied()
            .map(|x| i64::cast_from(x))
            .collect();

        let res = match (self, proof) {
            (Self::PkeV1(public_params), CompactPkeProof::PkeV1(proof)) => {
                let public_commit = PublicCommitV1::new(key_mask, key_body, ct_mask, ct_body);
                verify_v1(proof, (public_params, &public_commit), metadata)
            }
            (Self::PkeV2(public_params), CompactPkeProof::PkeV2(proof)) => {
                let public_commit = PublicCommitV2::new(key_mask, key_body, ct_mask, ct_body);
                #[cfg(feature = "gpu-experimental-zk")]
                let res = tfhe_zk_pok::proofs::pke_v2::gpu::verify(
                    proof,
                    (public_params, &public_commit),
                    metadata,
                    VerificationPairingMode::default(),
                );
                #[cfg(not(feature = "gpu-experimental-zk"))]
                let res = verify_v2(
                    proof,
                    (public_params, &public_commit),
                    metadata,
                    VerificationPairingMode::default(),
                );
                res
            }

            (Self::PkeV1(_), CompactPkeProof::PkeV2(_))
            | (Self::PkeV2(_), CompactPkeProof::PkeV1(_)) => {
                // Proof is not compatible with the CRS, so we refuse it right there
                Err(())
            }
        };

        match res {
            Ok(_) => ZkVerificationOutcome::Valid,
            Err(_) => ZkVerificationOutcome::Invalid,
        }
    }
}

impl ParameterSetConformant for CompactPkeCrs {
    type ParameterSet = CompactPkeCrsConformanceParams;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        match self {
            Self::PkeV1(public_params) => public_params.is_conformant(parameter_set),
            Self::PkeV2(public_params) => public_params.is_conformant(parameter_set),
        }
    }
}

/// The CRS can be compressed by only storing the `x` part of the elliptic curve coordinates.
#[derive(Serialize, Deserialize, Versionize)]
#[versionize(CompressedCompactPkeCrsVersions)]
pub enum CompressedCompactPkeCrs {
    PkeV1(<ZkCompactPkeV1PublicParams as Compressible>::Compressed),
    PkeV2(<ZkCompactPkeV2PublicParams as Compressible>::Compressed),
}

// The NAME impl is the same as CompactPkeCrs because once serialized they are represented with the
// same object. Decompression is done automatically during deserialization.
impl Named for CompressedCompactPkeCrs {
    const NAME: &'static str = CompactPkeCrs::NAME;
}

impl Compressible for CompactPkeCrs {
    type Compressed = CompressedCompactPkeCrs;

    type UncompressError = <ZkCompactPkeV1PublicParams as Compressible>::UncompressError;

    fn compress(&self) -> Self::Compressed {
        match self {
            Self::PkeV1(public_params) => CompressedCompactPkeCrs::PkeV1(public_params.compress()),
            Self::PkeV2(public_params) => CompressedCompactPkeCrs::PkeV2(public_params.compress()),
        }
    }

    fn uncompress(compressed: Self::Compressed) -> Result<Self, Self::UncompressError> {
        Ok(match compressed {
            CompressedCompactPkeCrs::PkeV1(compressed_params) => {
                Self::PkeV1(Compressible::uncompress(compressed_params)?)
            }
            CompressedCompactPkeCrs::PkeV2(compressed_params) => {
                Self::PkeV2(Compressible::uncompress(compressed_params)?)
            }
        })
    }
}

#[cfg(all(test, feature = "shortint"))]
mod test {
    use super::*;
    use crate::safe_serialization::{safe_deserialize_conformant, safe_serialize};
    use crate::shortint::parameters::*;
    use crate::shortint::{CarryModulus, MessageModulus};

    #[test]
    fn test_crs_conformance() {
        let params = PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let mut bad_params = params;
        bad_params.carry_modulus = CarryModulus(8);
        bad_params.message_modulus = MessageModulus(8);

        let mut rng = rand::thread_rng();

        let crs = CompactPkeCrs::new(
            params.encryption_lwe_dimension,
            LweCiphertextCount(4),
            params.encryption_noise_distribution,
            params.ciphertext_modulus,
            params.message_modulus.0 * params.carry_modulus.0 * 2,
            ZkMSBZeroPaddingBitCount(1),
            &mut rng,
        )
        .unwrap();

        let conformance_params =
            CompactPkeCrsConformanceParams::new(params, LweCiphertextCount(4)).unwrap();

        assert!(crs.is_conformant(&conformance_params));

        let conformance_params =
            CompactPkeCrsConformanceParams::new(bad_params, LweCiphertextCount(4)).unwrap();

        assert!(!crs.is_conformant(&conformance_params));

        let conformance_params =
            CompactPkeCrsConformanceParams::new(params, LweCiphertextCount(2)).unwrap();

        assert!(!crs.is_conformant(&conformance_params));
    }

    #[test]
    fn test_crs_serialization() {
        let params = PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

        let mut rng = rand::thread_rng();

        let crs = CompactPkeCrs::new(
            params.encryption_lwe_dimension,
            LweCiphertextCount(4),
            params.encryption_noise_distribution,
            params.ciphertext_modulus,
            params.message_modulus.0 * params.carry_modulus.0 * 2,
            ZkMSBZeroPaddingBitCount(1),
            &mut rng,
        )
        .unwrap();

        let conformance_params =
            CompactPkeCrsConformanceParams::new(params, LweCiphertextCount(4)).unwrap();

        let mut serialized = Vec::new();
        safe_serialize(&crs, &mut serialized, 1 << 30).unwrap();

        let _crs_deser: CompactPkeCrs =
            safe_deserialize_conformant(serialized.as_slice(), 1 << 30, &conformance_params)
                .unwrap();

        // Check with compression
        let mut serialized = Vec::new();
        safe_serialize(&crs.compress(), &mut serialized, 1 << 30).unwrap();

        let _crs_deser: CompactPkeCrs =
            safe_deserialize_conformant(serialized.as_slice(), 1 << 30, &conformance_params)
                .unwrap();
    }
}
