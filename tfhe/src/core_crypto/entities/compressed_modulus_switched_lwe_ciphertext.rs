use tfhe_versionable::Versionize;

use self::packed_integers::PackedIntegers;

use crate::conformance::ParameterSetConformant;
use crate::core_crypto::backward_compatibility::entities::compressed_modulus_switched_lwe_ciphertext::CompressedModulusSwitchedLweCiphertextVersions;
use crate::core_crypto::fft_impl::common::modulus_switch;
use crate::core_crypto::prelude::*;

/// An object to store a ciphertext using less memory
/// The modulus of the ciphertext is decreased by rounding and the result is stored in a compact way
/// The uncompacted result can be used as the input of a blind rotation to recover a low noise lwe
/// ciphertext
///
/// ```rust
/// use tfhe_csprng::seeders::Seed;
/// use tfhe::core_crypto::fft_impl::common::modulus_switch;
/// use tfhe::core_crypto::prelude::*;
/// use tfhe::core_crypto::prelude::compressed_modulus_switched_lwe_ciphertext::CompressedModulusSwitchedLweCiphertext;
///
/// let log_modulus = 12;
///
/// let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(Seed(0));
///
/// // Create the LweSecretKey
/// let lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key::<u64, _>(
///     LweDimension(2048),
///     &mut secret_generator,
/// );
/// let ciphertext_modulus = CiphertextModulus::new_native();
///
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
///
/// let mut encryption_generator =
///     EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
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
/// let compressed = CompressedModulusSwitchedLweCiphertext::<u64>::compress(
///     &lwe,
///     CiphertextModulusLog(log_modulus as usize),
/// );
///
/// let lwe_ms_ed = compressed.extract(ciphertext_modulus);
///
/// assert_eq!(
///     modulus_switch(
///         decrypt_lwe_ciphertext(&lwe_secret_key, &lwe_ms_ed).0,
///         CiphertextModulusLog(5)
///     ),
///     0
/// );
/// ```
#[derive(Clone, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(CompressedModulusSwitchedLweCiphertextVersions)]
pub struct CompressedModulusSwitchedLweCiphertext<PackingScalar: UnsignedInteger> {
    packed_integers: PackedIntegers<PackingScalar>,
    lwe_dimension: LweDimension,
}

impl<PackingScalar: UnsignedInteger> CompressedModulusSwitchedLweCiphertext<PackingScalar> {
    pub(crate) fn from_raw_parts(
        packed_integers: PackedIntegers<PackingScalar>,
        lwe_dimension: LweDimension,
    ) -> Self {
        assert_eq!(packed_integers.initial_len(), lwe_dimension.to_lwe_size().0,
            "Packed integers list is not of the correct size for the uncompressed LWE: expected {}, got {}",
            lwe_dimension.to_lwe_size().0,
            packed_integers.initial_len());

        Self {
            packed_integers,
            lwe_dimension,
        }
    }

    #[cfg(test)]
    pub(crate) fn into_raw_parts(self) -> (PackedIntegers<PackingScalar>, LweDimension) {
        let Self {
            packed_integers,
            lwe_dimension,
        } = self;

        (packed_integers, lwe_dimension)
    }

    /// Compresses a ciphertext by reducing its modulus
    /// This operation adds a lot of noise
    pub fn compress<Cont, InputScalar>(
        ct: &LweCiphertext<Cont>,
        log_modulus: CiphertextModulusLog,
    ) -> Self
    where
        Cont: Container<Element = InputScalar>,
        InputScalar: UnsignedInteger + CastInto<PackingScalar>,
    {
        assert!(
            ct.ciphertext_modulus().is_power_of_two(),
            "Modulus switch compression doe not support non power of 2 input moduli",
        );

        let modulus_switched: Vec<_> = ct
            .as_ref()
            .iter()
            // cast_into is valid here because the packing scalar bitsize is larger than the
            // ciphertext modulus log, which itself is larger than the compression
            // modulus log
            .map(|a| modulus_switch(*a, log_modulus).cast_into())
            .collect();

        let packed_integers = PackedIntegers::pack::<PackingScalar>(&modulus_switched, log_modulus);

        Self {
            packed_integers,
            lwe_dimension: ct.lwe_size().to_lwe_dimension(),
        }
    }

    /// Converts a compressed ciphertext into a lwe with the given modulus
    /// The noise added during the compression stays in the output
    /// The output must got through a PBS to reduce the noise
    pub fn extract<OutputScalar>(
        &self,
        ciphertext_modulus: CiphertextModulus<OutputScalar>,
    ) -> LweCiphertextOwned<OutputScalar>
    where
        OutputScalar: UnsignedInteger,
        PackingScalar: CastInto<OutputScalar>,
    {
        let lwe_size = self.lwe_dimension.to_lwe_size().0;

        let log_modulus = self.packed_integers.log_modulus().0;

        let number_bits_to_unpack = lwe_size * log_modulus;

        let len = number_bits_to_unpack.div_ceil(PackingScalar::BITS);

        assert_eq!(
            self.packed_integers.packed_coeffs().len(),
            len,
            "Mismatch between actual(={}) and expected(={len}) CompressedModulusSwitchedLweCiphertext packed_coeffs size",
            self.packed_integers.packed_coeffs().len(),
        );

        let container = self
            .packed_integers
            .unpack::<OutputScalar>()
            // Scaling
            .map(|a| a << (OutputScalar::BITS - log_modulus))
            .collect();

        LweCiphertextOwned::from_container(container, ciphertext_modulus)
    }
}

impl<Scalar: UnsignedInteger> ParameterSetConformant
    for CompressedModulusSwitchedLweCiphertext<Scalar>
{
    type ParameterSet = LweCiphertextConformanceParams<Scalar>;

    fn is_conformant(&self, lwe_ct_parameters: &LweCiphertextConformanceParams<Scalar>) -> bool {
        let Self {
            packed_integers,
            lwe_dimension,
        } = self;

        let lwe_size = lwe_dimension.to_lwe_size().0;

        let number_bits_to_pack = lwe_size * packed_integers.log_modulus().0;

        let len = number_bits_to_pack.div_ceil(Scalar::BITS);

        packed_integers.packed_coeffs().len() == len
            && *lwe_dimension == lwe_ct_parameters.lwe_dim
            && lwe_ct_parameters.ct_modulus.is_power_of_two()
            && matches!(
                lwe_ct_parameters.ms_decompression_method,
                MsDecompressionType::ClassicPbs
            )
    }
}

#[cfg(test)]
mod test {
    use rand::{Fill, Rng};

    use super::*;

    #[test]
    fn ms_compression_() {
        ms_compression::<u32, u32, u32>(1, 100);
        ms_compression::<u32, u32, u32>(10, 64);
        ms_compression::<u32, u32, u32>(11, 700);
        ms_compression::<u32, u32, u32>(12, 751);

        ms_compression::<u64, u64, u64>(1, 100);
        ms_compression::<u64, u64, u64>(10, 64);
        ms_compression::<u64, u64, u64>(11, 700);
        ms_compression::<u64, u64, u64>(12, 751);
        ms_compression::<u64, u64, u64>(33, 10);
        ms_compression::<u64, u64, u64>(53, 37);
        ms_compression::<u64, u64, u64>(63, 63);

        ms_compression::<u128, u128, u128>(127, 127);

        ms_compression::<u32, u64, u32>(1, 100);
        ms_compression::<u32, u64, u32>(10, 64);
        ms_compression::<u32, u64, u32>(11, 700);
        ms_compression::<u32, u64, u32>(12, 751);

        ms_compression::<u32, u64, u64>(1, 100);
        ms_compression::<u32, u64, u64>(10, 64);
        ms_compression::<u32, u64, u64>(11, 700);
        ms_compression::<u32, u64, u64>(12, 751);

        ms_compression::<u64, u128, u64>(1, 100);
        ms_compression::<u64, u128, u64>(10, 64);
        ms_compression::<u64, u128, u64>(11, 700);
        ms_compression::<u64, u128, u64>(12, 751);
        ms_compression::<u64, u128, u64>(33, 10);
        ms_compression::<u64, u128, u64>(53, 37);
        ms_compression::<u64, u128, u64>(63, 63);
    }

    fn ms_compression<
        InputScalar: UnsignedTorus,
        PackingScalar: UnsignedTorus + CastFrom<InputScalar>,
        OutputScalar: UnsignedTorus + CastFrom<PackingScalar> + CastFrom<InputScalar>,
    >(
        log_modulus: usize,
        len: usize,
    ) where
        [InputScalar]: Fill,
    {
        let in_ciphertext_modulus = CiphertextModulus::new_native();
        let out_ciphertext_modulus = CiphertextModulus::new_native();

        let mut lwe = LweCiphertext::new(InputScalar::ZERO, LweSize(len), in_ciphertext_modulus);

        // We don't care about the exact content here
        rand::thread_rng().fill(lwe.as_mut());

        let compressed: CompressedModulusSwitchedLweCiphertext<PackingScalar> =
            CompressedModulusSwitchedLweCiphertext::compress(
                &lwe,
                CiphertextModulusLog(log_modulus),
            );

        let lwe_ms_ed: Vec<OutputScalar> =
            compressed.extract(out_ciphertext_modulus).into_container();

        let lwe = lwe.into_container();

        for (i, output) in lwe_ms_ed.into_iter().enumerate() {
            assert_eq!(
                output,
                (output >> (OutputScalar::BITS - log_modulus))
                    << (OutputScalar::BITS - log_modulus),
            );

            assert_eq!(
                output >> (OutputScalar::BITS - log_modulus),
                modulus_switch(lwe[i], CiphertextModulusLog(log_modulus)).cast_into()
            )
        }
    }

    #[test]
    fn test_from_raw_parts() {
        type Scalar = u64;

        let len = 751;
        let log_modulus = 12;

        let ciphertext_modulus = CiphertextModulus::new_native();

        let mut lwe = LweCiphertext::new(Scalar::ZERO, LweSize(len), ciphertext_modulus);

        // We don't care about the exact content here
        rand::thread_rng().fill(lwe.as_mut());

        let compressed: CompressedModulusSwitchedLweCiphertext<u64> =
            CompressedModulusSwitchedLweCiphertext::compress(
                &lwe,
                CiphertextModulusLog(log_modulus),
            );

        let (packed_integers, lwe_dimension) = compressed.into_raw_parts();

        let rebuilt =
            CompressedModulusSwitchedLweCiphertext::from_raw_parts(packed_integers, lwe_dimension);

        let lwe_ms_ed: Vec<Scalar> = rebuilt.extract(ciphertext_modulus).into_container();
        let lwe = lwe.into_container();

        for (i, output) in lwe_ms_ed.into_iter().enumerate() {
            assert_eq!(
                output,
                (output >> (Scalar::BITS as usize - log_modulus))
                    << (Scalar::BITS as usize - log_modulus),
            );

            assert_eq!(
                output >> (Scalar::BITS as usize - log_modulus),
                modulus_switch(lwe[i], CiphertextModulusLog(log_modulus))
            )
        }
    }
}
