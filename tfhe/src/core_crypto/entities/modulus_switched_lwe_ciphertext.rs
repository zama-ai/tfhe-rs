use crate::core_crypto::fft_impl::common::modulus_switch;
use crate::core_crypto::prelude::*;

/// An object to store a ciphertext in little memory
/// The modulus of the ciphertext is decreased by rounding and the result is stored in a compact way
/// The uncompacted result can be used as the input of a blind rotation to recover a low noise lwe
/// ciphertext
///
/// ```
/// use concrete_csprng::seeders::Seed;
/// use tfhe::core_crypto::prelude::*;
/// use tfhe::core_crypto::fft_impl::common::modulus_switch;
/// use tfhe::core_crypto::prelude::modulus_switched_lwe_ciphertext::PackedModulusSwitchedLweCiphertext;
///
/// let log_modulus = 12;
///
/// let mut secret_generator = SecretRandomGenerator::<ActivatedRandomGenerator>::new(Seed(0));
///
/// // Create the LweSecretKey
/// let lwe_secret_key =
///     allocate_and_generate_new_binary_lwe_secret_key::<u64, _>(LweDimension(2048), &mut secret_generator);
/// let ciphertext_modulus = CiphertextModulus::new_native();
///
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
///
/// let mut encryption_generator =
///     EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
///
///
/// // Unsecure parameters, do not use them
/// let lwe = allocate_and_encrypt_new_lwe_ciphertext(
///     &lwe_secret_key,
///     Plaintext(0),
///     Gaussian::from_standard_dev(StandardDev(0.), 0.),
///     ciphertext_modulus,
///     &mut encryption_generator,
/// );
///
/// // Can be stored using much less space than the standard lwe ciphertexts
/// let compressed = PackedModulusSwitchedLweCiphertext::compress(
///     &lwe,
///     CiphertextModulusLog(log_modulus as usize),
/// );
///
/// let lwe_ms_ed = compressed.extract();
///
/// assert_eq!(
///     modulus_switch(
///         decrypt_lwe_ciphertext(&lwe_secret_key, &lwe_ms_ed).0,
///         CiphertextModulusLog(5)
///     ),
///     0
/// );
/// ```
pub struct PackedModulusSwitchedLweCiphertext<Scalar: UnsignedTorus> {
    packed_coeffs: Vec<Scalar>,
    lwe_dimension: LweDimension,
    log_modulus: CiphertextModulusLog,
    uncompressed_ciphertext_modulus: CiphertextModulus<Scalar>,
}

impl<Scalar: UnsignedTorus> PackedModulusSwitchedLweCiphertext<Scalar> {
    /// Compresses a ciphertext by reducing its modulus
    /// This operation adds a lot of noise
    pub fn compress<Cont: Container<Element = Scalar>>(
        ct: &LweCiphertext<Cont>,
        log_modulus: CiphertextModulusLog,
    ) -> Self {
        let switch_modulus = |x| modulus_switch(x, log_modulus);

        let log_modulus = log_modulus.0;

        let uncompressed_ciphertext_modulus = ct.ciphertext_modulus();

        assert!(
            ct.ciphertext_modulus().is_power_of_two(),
            "Modulus switch compression doe not support non power of 2 input moduli",
        );

        let uncompressed_ciphertext_modulus_log =
            if uncompressed_ciphertext_modulus.is_native_modulus() {
                Scalar::BITS
            } else {
                uncompressed_ciphertext_modulus.get_custom_modulus().ilog2() as usize
            };

        assert!(
            log_modulus <= uncompressed_ciphertext_modulus_log,
            "The log_modulus (={log_modulus}) for modulus switch compression must be smaller than the uncompressed ciphertext_modulus_log (={uncompressed_ciphertext_modulus_log})",
        );

        let lwe_size = ct.lwe_size().0;

        let number_bits_to_pack = lwe_size * log_modulus;

        let len = number_bits_to_pack.div_ceil(Scalar::BITS);

        let slice = ct.as_ref();
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

                let mut value = switch_modulus(slice[j]) >> start_shift;
                j += 1;

                while j * log_modulus < ((i + 1) * Scalar::BITS) && j < lwe_size {
                    let shift = j * log_modulus - i * Scalar::BITS;

                    value |= switch_modulus(slice[j]) << shift;

                    j += 1;
                }
                value
            })
            .collect();

        let log_modulus = CiphertextModulusLog(log_modulus);

        Self {
            packed_coeffs,
            lwe_dimension: ct.lwe_size().to_lwe_dimension(),
            log_modulus,
            uncompressed_ciphertext_modulus,
        }
    }

    /// Converts back a compressed ciphertext to its initial modulus
    /// The noise added during the compression says int hte output
    /// The output must got through a PBS to reduce the noise
    pub fn extract(&self) -> LweCiphertextOwned<Scalar> {
        let log_modulus = self.log_modulus.0;

        let container = (0..(self.lwe_dimension.to_lwe_size().0))
            .map(|i| {
                let start = i * log_modulus;
                let end = (i + 1) * log_modulus;

                let start_block = start / Scalar::BITS;
                let start_remainder = start % Scalar::BITS;

                let end_block_inclusive = (end - 1) / Scalar::BITS;

                if start_block == end_block_inclusive {
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
                    // The highest bits of single_part will be discarded during scaling
                    //
                    // single_part =
                    self.packed_coeffs[start_block] >> start_remainder
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
                    // The highest bits of (first_part|second_part) will be discarded during scaling
                    assert_eq!(end_block_inclusive, start_block + 1);

                    let first_part = self.packed_coeffs[start_block] >> start_remainder;

                    let second_part =
                        self.packed_coeffs[start_block + 1] << (Scalar::BITS - start_remainder);

                    first_part | second_part
                }
            })
            // Scaling
            .map(|a| a << (Scalar::BITS - log_modulus))
            .collect();

        LweCiphertextOwned::from_container(container, self.uncompressed_ciphertext_modulus)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::core_crypto::prelude::test::TestResources;

    #[test]
    fn ms_compression_() {
        ms_compression::<u32>(1, 100);
        ms_compression::<u32>(10, 64);
        ms_compression::<u32>(11, 700);
        ms_compression::<u32>(12, 751);

        ms_compression::<u64>(1, 100);
        ms_compression::<u64>(10, 64);
        ms_compression::<u64>(11, 700);
        ms_compression::<u64>(12, 751);
        ms_compression::<u64>(33, 10);
        ms_compression::<u64>(53, 37);
        ms_compression::<u64>(63, 63);

        ms_compression::<u128>(127, 127);
    }

    fn ms_compression<Scalar: UnsignedTorus + CastInto<usize> + CastFrom<usize>>(
        log_modulus: usize,
        len: usize,
    ) {
        let mut rsc: TestResources = TestResources::new();

        let ciphertext_modulus = CiphertextModulus::new_native();

        let mut lwe = vec![Scalar::ZERO; len];

        rsc.encryption_random_generator
            .fill_slice_with_random_uniform_mask(&mut lwe);

        let lwe = LweCiphertextOwned::from_container(lwe, ciphertext_modulus);

        let compressed =
            PackedModulusSwitchedLweCiphertext::compress(&lwe, CiphertextModulusLog(log_modulus));

        let lwe_ms_ed: Vec<Scalar> = compressed.extract().into_container();

        let lwe = lwe.into_container();

        for (i, output) in lwe_ms_ed.into_iter().enumerate() {
            assert_eq!(
                output,
                (output >> (Scalar::BITS - log_modulus)) << (Scalar::BITS - log_modulus),
            );

            assert_eq!(
                output >> (Scalar::BITS - log_modulus),
                modulus_switch(lwe[i], CiphertextModulusLog(log_modulus))
            )
        }
    }
}
