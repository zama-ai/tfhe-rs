use tfhe_versionable::Versionize;

use crate::conformance::ParameterSetConformant;
use crate::core_crypto::backward_compatibility::entities::packed_integers::PackedIntegersVersions;
use crate::core_crypto::prelude::*;

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(PackedIntegersVersions)]
pub struct PackedIntegers<Scalar: UnsignedInteger> {
    packed_coeffs: Vec<Scalar>,
    log_modulus: CiphertextModulusLog,
    initial_len: usize,
}

impl<Scalar: UnsignedInteger> PackedIntegers<Scalar> {
    pub(crate) fn from_raw_parts(
        packed_coeffs: Vec<Scalar>,
        log_modulus: CiphertextModulusLog,
        initial_len: usize,
    ) -> Self {
        let required_bits_packed = initial_len * log_modulus.0;
        let expected_len = required_bits_packed.div_ceil(Scalar::BITS);

        assert_eq!(
            packed_coeffs.len(),
            expected_len,
            "Invalid size for the packed coeffs, got {}, expected {}",
            packed_coeffs.len(),
            expected_len
        );

        Self {
            packed_coeffs,
            log_modulus,
            initial_len,
        }
    }

    pub fn pack<InputScalar: UnsignedInteger + CastInto<Scalar>>(
        slice: &[InputScalar],
        log_modulus: CiphertextModulusLog,
    ) -> Self {
        assert!(log_modulus.0 <= InputScalar::BITS);
        assert!(log_modulus.0 <= Scalar::BITS);

        let log_modulus = log_modulus.0;

        let in_len = slice.len();

        assert!(log_modulus <= Scalar::BITS);

        let number_bits_to_pack = in_len * log_modulus;

        let len = number_bits_to_pack.div_ceil(Scalar::BITS);

        // Lowest bits are on the right
        //
        // Target mapping:
        //                          log_modulus
        //                           |-------|
        //
        // slice        :    |  k+2  |  k+1  |   k   |
        // packed_coeffs:  i+1   |       i       |     i-1
        //
        //                       |---------------|
        //                         Scalar::BITS
        //
        //                                       |---|
        //                                    start_shift
        //
        //                                   |---|
        //                                   shift1
        //                             (1st loop iteration)
        //
        //                           |-----------|
        //                               shift2
        //                        (2nd loop iteration)
        //
        // packed_coeffs[i] =
        //                    slice[k] >> start_shift
        //                  | slice[k+1] << shift1
        //                  | slice[k+2] << shift2
        //
        // In the lowest bits of packed_coeffs[i], we want the highest bits of slice[k],
        // hence the right shift
        // The next bits should be the bits of slice[k+1] which we must left shifted to avoid
        // overlapping
        // This goes on
        let packed_coeffs = (0..len)
            .map(|i| {
                let k = Scalar::BITS * i / log_modulus;
                let mut j = k;

                let start_shift = i * Scalar::BITS - j * log_modulus;

                debug_assert!(
                    log_modulus == InputScalar::BITS
                        || (slice[j] >> log_modulus == InputScalar::ZERO)
                );

                let value: Scalar = slice[j].cast_into();
                let mut value = value >> start_shift;
                j += 1;

                while j * log_modulus < ((i + 1) * Scalar::BITS) && j < slice.len() {
                    let shift = j * log_modulus - i * Scalar::BITS;

                    debug_assert!(
                        log_modulus == InputScalar::BITS
                            || (slice[j] >> log_modulus == InputScalar::ZERO)
                    );

                    let value2: Scalar = slice[j].cast_into();

                    value |= value2 << shift;

                    j += 1;
                }
                value
            })
            .collect();

        let log_modulus = CiphertextModulusLog(log_modulus);

        Self {
            packed_coeffs,
            log_modulus,
            initial_len: slice.len(),
        }
    }

    pub fn unpack<OutputScalar>(&self) -> impl Iterator<Item = OutputScalar> + '_
    where
        Scalar: CastInto<OutputScalar>,
        OutputScalar: UnsignedInteger,
    {
        let log_modulus = self.log_modulus.0;

        assert!(log_modulus <= Scalar::BITS);
        assert!(log_modulus <= OutputScalar::BITS);

        // log_modulus lowest bits set to 1
        let mask = if log_modulus < Scalar::BITS {
            (Scalar::ONE << log_modulus) - Scalar::ONE
        } else {
            assert_eq!(log_modulus, Scalar::BITS);
            Scalar::MAX
        };

        (0..self.initial_len).map(move |i| {
            let start = i * log_modulus;
            let end = (i + 1) * log_modulus;

            let start_block = start / Scalar::BITS;
            let start_remainder = start % Scalar::BITS;

            let end_block_inclusive = (end - 1) / Scalar::BITS;

            let result = if start_block == end_block_inclusive {
                // Lowest bits are on the right
                //
                // Target mapping:
                //                                   Scalar::BITS
                //                                |---------------|
                //
                // packed_coeffs: | start_block+1 |  start_block  |
                // container    :             |  i+1  |   i   |  i-1  |
                //
                //                                    |-------|
                //                                   log_modulus
                //
                //                                            |---|
                //                                       start_remainder
                //
                // In container[i] we want the bits of packed_coeffs[start_block] starting from
                // index start_remainder
                //
                // container[i] = lowest_bits of single_part
                //
                let single_part = self.packed_coeffs[start_block] >> start_remainder;

                single_part & mask
            } else {
                // Lowest bits are on the right
                //
                // Target mapping:
                //                                   Scalar::BITS
                //                                 |---------------|
                //
                // packed_coeffs:  | start_block+1 |  start_block  |
                // container    :      |  i+1  |   i   |  i-1  |
                //
                //                             |-------|
                //                            log_modulus
                //
                //                                     |-----------|
                //                                    start_remainder
                //
                //                                 |---|
                //                     Scalar::BITS - start_remainder
                //
                // In the lowest bits of container[i] we want the highest bits of
                // packed_coeffs[start_block] starting from index start_remainder
                //
                // In the next bits, we want the lowest bits of packed_coeffs[start_block + 1]
                // left shifted to avoid overlapping
                //
                // container[i] = lowest_bits of (first_part|second_part)
                //
                assert_eq!(end_block_inclusive, start_block + 1);

                let first_part = self.packed_coeffs[start_block] >> start_remainder;

                let second_part =
                    self.packed_coeffs[start_block + 1] << (Scalar::BITS - start_remainder);

                (first_part | second_part) & mask
            };

            result.cast_into()
        })
    }

    pub fn log_modulus(&self) -> CiphertextModulusLog {
        self.log_modulus
    }

    pub fn packed_coeffs(&self) -> &[Scalar] {
        &self.packed_coeffs
    }

    pub fn initial_len(&self) -> usize {
        self.initial_len
    }
}

impl<Scalar: UnsignedInteger> ParameterSetConformant for PackedIntegers<Scalar> {
    type ParameterSet = usize;

    fn is_conformant(&self, len: &usize) -> bool {
        let Self {
            packed_coeffs,
            log_modulus,
            initial_len,
        } = self;

        let number_packed_bits = *len * log_modulus.0;

        let packed_len = number_packed_bits.div_ceil(Scalar::BITS);

        *len == *initial_len && packed_coeffs.len() == packed_len
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::{Fill, Rng};

    #[test]
    fn pack_unpack() {
        pack_unpack_single::<u64>(32, 700);
        pack_unpack_single::<u64>(27, 700);
        pack_unpack_single::<u64>(64, 700);
        pack_unpack_single::<u128>(64, 700);
        pack_unpack_single::<u128>(79, 700);
        pack_unpack_single::<u128>(128, 700);
    }

    fn pack_unpack_single<Scalar>(log_modulus: usize, len: usize)
    where
        [Scalar]: Fill,
        Scalar: UnsignedInteger + CastFrom<usize>,
    {
        let mut cont = vec![Scalar::ZERO; len];

        rand::rng().fill(cont.as_mut_slice());

        for val in cont.iter_mut() {
            *val %= log_modulus.cast_into();
        }

        let packed = PackedIntegers::<Scalar>::pack(&cont, CiphertextModulusLog(log_modulus));

        let unpacked: Vec<Scalar> = packed.unpack().collect();

        assert_eq!(cont, unpacked);
    }
}
