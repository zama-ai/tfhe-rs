use tfhe_versionable::{Upgrade, Version, VersionsDispatch};

use crate::core_crypto::prelude::packed_integers::PackedIntegers;
use crate::core_crypto::prelude::{CiphertextModulusLog, UnsignedInteger};

/// V0 list is structurally identical to the V1 list. The only difference is that the last coeff
/// of the V0 list might hold garbage, whereas it must be clean in the V1 list.
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

        // `from_raw_parts` will clean the last coeffs if the V0 list was compressed on the gpu
        // then serialized
        let packed_integers =
            PackedIntegers::from_raw_parts(packed_coeffs, log_modulus, initial_len)?;

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

        let packed_coeffs = vec![u64::MAX; 132];
        let upgraded = PackedIntegersV0 {
            packed_coeffs: packed_coeffs.clone(),
            log_modulus,
            initial_len,
        }
        .upgrade()
        .unwrap();

        // Upgrade should clean the last integer
        assert!(upgraded.is_conformant(&params));

        // Newly created list should be clean too
        let expected =
            PackedIntegers::from_raw_parts(packed_coeffs, log_modulus, initial_len).unwrap();
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
