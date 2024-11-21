use crate::conformance::ParameterSetConformant;
use crate::core_crypto::commons::math::random::BoundedDistribution;
use crate::core_crypto::prelude::*;
use crate::named::Named;
#[cfg(feature = "shortint")]
use crate::shortint::parameters::CompactPublicKeyEncryptionParameters;
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::Bound;
use std::fmt::Debug;
use tfhe_versionable::Versionize;
use tfhe_zk_pok::proofs::pke::crs_gen;

pub use tfhe_zk_pok::curve_api::Compressible;
pub use tfhe_zk_pok::proofs::ComputeLoad as ZkComputeLoad;
type Curve = tfhe_zk_pok::curve_api::Bls12_446;
pub type CompactPkeProof = tfhe_zk_pok::proofs::pke::Proof<Curve>;

impl Named for CompactPkeProof {
    const NAME: &'static str = "zk::CompactPkeProof";
}

impl ParameterSetConformant for CompactPkeProof {
    type ParameterSet = ();

    fn is_conformant(&self, _parameter_set: &Self::ParameterSet) -> bool {
        self.is_usable()
    }
}

pub type CompactPkePublicParams = tfhe_zk_pok::proofs::pke::PublicParams<Curve>;
pub type SerializableCompactPkePublicParams =
    tfhe_zk_pok::serialization::SerializablePKEv1PublicParams;

impl Named for CompactPkePublicParams {
    const NAME: &'static str = "zk::CompactPkePublicParams";
}

pub struct CompactPkeCrsConformanceParams {
    lwe_dim: LweDimension,
    max_num_message: usize,
    noise_bound: u64,
    ciphertext_modulus: u64,
    plaintext_modulus: u64,
    msbs_zero_padding_bit_count: ZkMSBZeroPaddingBitCount,
}

#[cfg(feature = "shortint")]
impl CompactPkeCrsConformanceParams {
    pub fn new<E, P: TryInto<CompactPublicKeyEncryptionParameters, Error = E>>(
        value: P,
        max_num_message: usize,
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

impl ParameterSetConformant for CompactPkePublicParams {
    type ParameterSet = CompactPkeCrsConformanceParams;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        self.k <= self.d
            && self.d == parameter_set.lwe_dim.0
            && self.k == parameter_set.max_num_message
            && self.b == parameter_set.noise_bound
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
    const NAME: &'static str = CompactPkePublicParams::NAME;
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum ZkVerificationOutCome {
    /// The proof and its entity were valid
    Valid,
    /// The proof and its entity were not
    Invalid,
}

impl ZkVerificationOutCome {
    pub fn is_valid(self) -> bool {
        self == Self::Valid
    }

    pub fn is_invalid(self) -> bool {
        self == Self::Invalid
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkMSBZeroPaddingBitCount(pub u64);

/// The CRS (Common Reference String) of a ZK scheme is a set of values shared between the prover
/// and the verifier.
///
/// The same CRS should be used at the prove and verify steps.
#[derive(Clone, Debug, Serialize, Deserialize, Versionize)]
#[repr(transparent)]
pub struct CompactPkeCrs {
    public_params: CompactPkePublicParams,
}

impl Named for CompactPkeCrs {
    const NAME: &'static str = "zk::CompactPkeCrs";
}

impl From<CompactPkePublicParams> for CompactPkeCrs {
    fn from(value: CompactPkePublicParams) -> Self {
        Self {
            public_params: value,
        }
    }
}

impl CompactPkeCrs {
    /// Prepare and check the CRS parameters.
    ///
    /// The output of this function can be used in [tfhe_zk_pok::proofs::pke::compute_crs_params].
    pub fn prepare_crs_parameters<Scalar, NoiseDistribution>(
        lwe_dim: LweDimension,
        max_num_cleartext: usize,
        noise_distribution: NoiseDistribution,
        ciphertext_modulus: CiphertextModulus<Scalar>,
        plaintext_modulus: Scalar,
    ) -> crate::Result<(LweDimension, usize, Scalar, u64, Scalar)>
    where
        Scalar: UnsignedInteger + CastInto<u64> + Debug,
        NoiseDistribution: BoundedDistribution<Scalar::Signed>,
    {
        // The bound for the crs has to be a power of two,
        // it is [-b, b) (non-inclusive for the high bound)
        // so we may have to give a bound that is bigger than
        // what the distribution generates
        let high_bound = match noise_distribution.high_bound() {
            Bound::Included(high_b) => {
                let high_b = high_b.wrapping_abs().into_unsigned();
                if high_b.is_power_of_two() {
                    high_b * Scalar::TWO
                } else {
                    high_b.next_power_of_two()
                }
            }
            Bound::Excluded(high_b) => {
                let high_b = high_b.wrapping_abs().into_unsigned();
                if high_b.is_power_of_two() {
                    high_b
                } else {
                    high_b.next_power_of_two()
                }
            }
            Bound::Unbounded => {
                return Err("requires bounded distribution".into());
            }
        };

        let abs_low_bound = match noise_distribution.low_bound() {
            Bound::Included(low_b) => {
                let low_b = low_b.wrapping_abs().into_unsigned();
                if low_b.is_power_of_two() {
                    low_b * Scalar::TWO
                } else {
                    low_b.next_power_of_two()
                }
            }
            Bound::Excluded(low_b) => {
                let low_b = low_b.wrapping_abs().into_unsigned();
                if low_b.is_power_of_two() {
                    low_b
                } else {
                    low_b.next_power_of_two()
                }
            }
            Bound::Unbounded => {
                return Err("requires bounded distribution".into());
            }
        };

        let noise_bound = abs_low_bound.max(high_bound);

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

    /// Generates a new zk CRS from the tfhe parameters.
    pub fn new<Scalar, NoiseDistribution>(
        lwe_dim: LweDimension,
        max_num_cleartext: usize,
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
        )?;
        let public_params = crs_gen(
            d.0,
            k,
            b.cast_into(),
            q,
            t.cast_into(),
            msbs_zero_padding_bit_count.0,
            rng,
        );

        Ok(Self { public_params })
    }

    /// Maximum number of messages that can be proven in a single list using this CRS
    pub fn max_num_messages(&self) -> usize {
        self.public_params().k
    }

    pub fn public_params(&self) -> &CompactPkePublicParams {
        &self.public_params
    }
}

impl ParameterSetConformant for CompactPkeCrs {
    type ParameterSet = CompactPkeCrsConformanceParams;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        self.public_params.is_conformant(parameter_set)
    }
}

/// The CRS can be compressed by only storing the `x` part of the elliptic curve coordinates.
#[derive(Serialize, Deserialize, Versionize)]
#[repr(transparent)]
pub struct CompressedCompactPkeCrs {
    public_params: <CompactPkePublicParams as Compressible>::Compressed,
}

// The NAME impl is the same as CompactPkeCrs because once serialized they are represented with the
// same object. Decompression is done automatically during deserialization.
impl Named for CompressedCompactPkeCrs {
    const NAME: &'static str = CompactPkeCrs::NAME;
}

impl Compressible for CompactPkeCrs {
    type Compressed = CompressedCompactPkeCrs;

    type UncompressError = <CompactPkePublicParams as Compressible>::UncompressError;

    fn compress(&self) -> Self::Compressed {
        CompressedCompactPkeCrs {
            public_params: self.public_params.compress(),
        }
    }

    fn uncompress(compressed: Self::Compressed) -> Result<Self, Self::UncompressError> {
        Ok(Self {
            public_params: Compressible::uncompress(compressed.public_params)?,
        })
    }
}

#[cfg(all(test, feature = "shortint"))]
mod test {
    use super::*;
    use crate::safe_serialization::{safe_deserialize_conformant, safe_serialize};
    use crate::shortint::parameters::compact_public_key_only::p_fail_2_minus_64::ks_pbs::PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
    use crate::shortint::{CarryModulus, MessageModulus};

    #[test]
    fn test_crs_conformance() {
        let params = PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
        let mut bad_params = params;
        bad_params.carry_modulus = CarryModulus(8);
        bad_params.message_modulus = MessageModulus(8);

        let mut rng = rand::thread_rng();

        let crs = CompactPkeCrs::new(
            params.encryption_lwe_dimension,
            4,
            params.encryption_noise_distribution,
            params.ciphertext_modulus,
            params.message_modulus.0 * params.carry_modulus.0 * 2,
            ZkMSBZeroPaddingBitCount(1),
            &mut rng,
        )
        .unwrap();

        let conformance_params = CompactPkeCrsConformanceParams::new(params, 4).unwrap();

        assert!(crs.is_conformant(&conformance_params));

        let conformance_params = CompactPkeCrsConformanceParams::new(bad_params, 4).unwrap();

        assert!(!crs.is_conformant(&conformance_params));

        let conformance_params = CompactPkeCrsConformanceParams::new(params, 2).unwrap();

        assert!(!crs.is_conformant(&conformance_params));
    }

    #[test]
    fn test_crs_serialization() {
        let params = PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;

        let mut rng = rand::thread_rng();

        let crs = CompactPkeCrs::new(
            params.encryption_lwe_dimension,
            4,
            params.encryption_noise_distribution,
            params.ciphertext_modulus,
            params.message_modulus.0 * params.carry_modulus.0 * 2,
            ZkMSBZeroPaddingBitCount(1),
            &mut rng,
        )
        .unwrap();

        let conformance_params = CompactPkeCrsConformanceParams::new(params, 4).unwrap();

        let mut serialized = Vec::new();
        safe_serialize(&crs, &mut serialized, 1 << 30).unwrap();

        let _crs_deser: CompactPkeCrs =
            safe_deserialize_conformant(serialized.as_slice(), 1 << 30, &conformance_params)
                .unwrap();

        // Check that we are able to load public params
        let mut serialized = Vec::new();
        safe_serialize(crs.public_params(), &mut serialized, 1 << 30).unwrap();

        let _params_deser: CompactPkePublicParams =
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
