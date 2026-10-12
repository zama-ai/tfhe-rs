use tfhe_versionable::{Upgrade, Version, VersionsDispatch};

use crate::core_crypto::prelude::packed_integers::PackedIntegers;
use crate::core_crypto::prelude::{CiphertextModulusLog, UnsignedInteger};

#[derive(Version)]
pub struct PackedIntegersV0<Scalar: UnsignedInteger> {
    packed_coeffs: Vec<Scalar>,
    log_modulus: CiphertextModulusLog,
    initial_len: usize,
}

impl<Scalar: UnsignedInteger> Upgrade<PackedIntegers<Scalar>> for PackedIntegersV0<Scalar> {
    type Error = crate::Error;

    fn upgrade(self) -> Result<PackedIntegers<Scalar>, Self::Error> {
        let Self {
            packed_coeffs,
            log_modulus,
            initial_len,
        } = self;

        let expected_len = initial_len
            .checked_mul(log_modulus.0)
            .map(|used_bits| used_bits.div_ceil(Scalar::BITS));

        if expected_len != Some(packed_coeffs.len()) {
            return Err(crate::Error::new(format!(
                "Invalid PackedIntegers: {} packed coefficients do not hold {initial_len} \
                integers of {} bits",
                packed_coeffs.len(),
                log_modulus.0
            )));
        }

        // Lists compressed on the GPU may hold non zero values in the unused bits of their last
        // coefficient
        let mut packed_integers =
            PackedIntegers::from_raw_parts(packed_coeffs, log_modulus, initial_len);
        packed_integers
            .clear_unused_bits()
            .map_err(|_| crate::error!("Failed to canonicalize packed ciphertext to cpu form"))?;

        Ok(packed_integers)
    }
}

#[derive(VersionsDispatch)]
pub enum PackedIntegersVersions<Scalar: UnsignedInteger> {
    V0(PackedIntegersV0<Scalar>),
    V1(PackedIntegers<Scalar>),
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::conformance::ParameterSetConformant;
    use crate::core_crypto::prelude::packed_integers::PackedIntegersConformanceParams;

    #[test]
    fn test_upgrade_clears_unused_bits() {
        // `700 * 12 = 8400` bits span 132 u64, the last one holds 16 meaningful bits
        let initial_len = 700;
        let log_modulus = CiphertextModulusLog(12);
        let params = PackedIntegersConformanceParams::new::<u64>(initial_len);

        let mut packed_coeffs = vec![u64::MAX; 132];
        let upgraded = PackedIntegersV0 {
            packed_coeffs: packed_coeffs.clone(),
            log_modulus,
            initial_len,
        }
        .upgrade()
        .unwrap();
        assert!(upgraded.is_conformant(&params));

        *packed_coeffs.last_mut().unwrap() = (1 << 16) - 1;
        let expected = PackedIntegers::from_raw_parts(packed_coeffs, log_modulus, initial_len);
        assert_eq!(upgraded, expected);

        // A length that does not match the number of integers is an error, not a panic
        let upgraded = PackedIntegersV0 {
            packed_coeffs: vec![0u64; 131],
            log_modulus,
            initial_len,
        }
        .upgrade();
        assert!(upgraded.is_err());
    }
}
