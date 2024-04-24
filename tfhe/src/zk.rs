use crate::core_crypto::commons::math::random::{BoundedDistribution, Deserialize, Serialize};
use crate::core_crypto::prelude::*;
use rand_core::RngCore;
use std::cmp::Ordering;
use std::collections::Bound;
use std::fmt::Debug;
use tfhe_zk_pok::proofs::pke::crs_gen;

pub use tfhe_zk_pok::proofs::ComputeLoad as ZkComputeLoad;
type Curve = tfhe_zk_pok::curve_api::Bls12_446;
pub type CompactPkeProof = tfhe_zk_pok::proofs::pke::Proof<Curve>;
pub type CompactPkePublicParams = tfhe_zk_pok::proofs::pke::PublicParams<Curve>;

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum ZkVerificationOutCome {
    /// The proof ands its entity were valid
    Valid,
    /// The proof ands its entity were not
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

#[derive(Serialize, Deserialize)]
pub struct CompactPkeCrs {
    public_params: CompactPkePublicParams,
}

impl CompactPkeCrs {
    /// Prepare and check the CRS parameters.
    ///
    /// The output of this function can be used in [tfhe_zk_pok::proofs::pke::compute_crs_len].
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

    pub fn new<Scalar, NoiseDistribution>(
        lwe_dim: LweDimension,
        max_num_cleartext: usize,
        noise_distribution: NoiseDistribution,
        ciphertext_modulus: CiphertextModulus<Scalar>,
        plaintext_modulus: Scalar,
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
        let public_params = crs_gen(d.0, k, b.cast_into(), q, t.cast_into(), rng);

        Ok(Self { public_params })
    }

    pub fn public_params(&self) -> &CompactPkePublicParams {
        &self.public_params
    }
}
