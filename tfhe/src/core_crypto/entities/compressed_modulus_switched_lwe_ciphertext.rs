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
#[derive(Clone, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(CompressedModulusSwitchedLweCiphertextVersions)]
pub struct CompressedModulusSwitchedLweCiphertext<PackingScalar: UnsignedInteger> {
    pub(crate) packed_integers: PackedIntegers<PackingScalar>,
    pub(crate) lwe_dimension: LweDimension,
    pub(crate) uncompressed_ciphertext_modulus: CiphertextModulus<PackingScalar>,
}

impl<PackingScalar: UnsignedInteger> CompressedModulusSwitchedLweCiphertext<PackingScalar> {
    /// Compresses a ciphertext by reducing its modulus
    /// This operation adds a lot of noise
    pub fn compress<Scalar, Cont>(
        ct: &LweCiphertext<Cont>,
        log_modulus: CiphertextModulusLog,
    ) -> Self
    where
        Scalar: UnsignedInteger + CastInto<PackingScalar>,
        Cont: Container<Element = Scalar>,
    {
        assert!(
            Scalar::BITS <= PackingScalar::BITS,
            "The LWE Scalar size (={}) must be smaller or equal to the Packing Scalar size (={}) \
             for modulus switch compression",
            Scalar::BITS,
            PackingScalar::BITS,
        );

        let uncompressed_ciphertext_modulus =
            ct.ciphertext_modulus().try_to().unwrap_or_else(|_| {
                panic!(
                "The ciphertext modulus (={}) for modulus switch compression does not fit in the \
                 PackingScalar (={})",
                ct.ciphertext_modulus(), PackingScalar::BITS)
            });

        assert!(
            ct.ciphertext_modulus().is_power_of_two(),
            "Modulus switch compression doe not support non power of 2 input moduli",
        );

        let uncompressed_ciphertext_modulus_log =
            if uncompressed_ciphertext_modulus.is_native_modulus() {
                PackingScalar::BITS
            } else {
                uncompressed_ciphertext_modulus.get_custom_modulus().ilog2() as usize
            };

        assert!(
            log_modulus.0 <= uncompressed_ciphertext_modulus_log,
            "The log_modulus (={}) for modulus switch compression must be smaller than the \
             uncompressed ciphertext_modulus_log (={})",
            log_modulus.0,
            uncompressed_ciphertext_modulus_log,
        );

        let modulus_switched: Vec<_> = ct
            .as_ref()
            .iter()
            .map(|a| modulus_switch(*a, log_modulus).cast_into())
            .collect();

        let packed_integers = PackedIntegers::pack(&modulus_switched, log_modulus);

        Self {
            packed_integers,
            lwe_dimension: ct.lwe_size().to_lwe_dimension(),
            uncompressed_ciphertext_modulus,
        }
    }

    /// Converts back a compressed ciphertext to its initial modulus
    /// The noise added during the compression stays in the output
    /// The output must got through a PBS to reduce the noise
    pub fn extract<Scalar>(&self) -> LweCiphertextOwned<Scalar>
    where
        Scalar: UnsignedInteger,
        PackingScalar: CastInto<Scalar>,
    {
        assert!(
            Scalar::BITS <= PackingScalar::BITS,
            "The LWE Scalar size (={}) must be smaller or equal to the Packing Scalar size (={}) \
             for modulus switch compression",
            Scalar::BITS,
            PackingScalar::BITS,
        );

        let uncompressed_ciphertext_modulus = self
            .uncompressed_ciphertext_modulus
            .try_to()
            .unwrap_or_else(|_| {
                panic!(
            "The ciphertext modulus (={}) for modulus switch compression does not fit in the LWE \
             Scalar (={})",
                    self.uncompressed_ciphertext_modulus, Scalar::BITS)
            });

        let lwe_size = self.lwe_dimension.to_lwe_size().0;

        let log_modulus = self.packed_integers.log_modulus.0;

        let number_bits_to_unpack = lwe_size * log_modulus;

        let len = number_bits_to_unpack.div_ceil(PackingScalar::BITS);

        assert_eq!(
            self.packed_integers.packed_coeffs.len(),
            len,
            "Mismatch between actual(={}) and expected(={len}) \
             CompressedModulusSwitchedLweCiphertext packed_coeffs size",
            self.packed_integers.packed_coeffs.len(),
        );

        let container = self
            .packed_integers
            .unpack()
            // Scaling
            .map(|a| {
                let a: Scalar = a.cast_into();
                a << (Scalar::BITS - log_modulus)
            })
            .collect();

        LweCiphertextOwned::from_container(container, uncompressed_ciphertext_modulus)
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
            uncompressed_ciphertext_modulus,
        } = self;

        let lwe_size = lwe_dimension.to_lwe_size().0;

        let number_bits_to_pack = lwe_size * packed_integers.log_modulus.0;

        let len = number_bits_to_pack.div_ceil(Scalar::BITS);

        packed_integers.packed_coeffs.len() == len
            && *lwe_dimension == lwe_ct_parameters.lwe_dim
            && lwe_ct_parameters.ct_modulus.is_power_of_two()
            && *uncompressed_ciphertext_modulus == lwe_ct_parameters.ct_modulus
            && matches!(
                lwe_ct_parameters.ms_decompression_method,
                MsDecompressionType::ClassicPbs
            )
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::core_crypto::prelude::test::TestResources;

    #[test]
    fn ms_compression_() {
        ms_compression::<u32, u32>(1, 100);
        ms_compression::<u32, u32>(10, 64);
        ms_compression::<u32, u32>(11, 700);
        ms_compression::<u32, u32>(12, 751);

        ms_compression::<u64, u64>(1, 100);
        ms_compression::<u64, u64>(10, 64);
        ms_compression::<u64, u64>(11, 700);
        ms_compression::<u64, u64>(12, 751);
        ms_compression::<u64, u64>(33, 10);
        ms_compression::<u64, u64>(53, 37);
        ms_compression::<u64, u64>(63, 63);

        ms_compression::<u128, u128>(127, 127);

        ms_compression::<u32, u64>(1, 100);
        ms_compression::<u32, u64>(10, 64);
        ms_compression::<u32, u64>(11, 700);
        ms_compression::<u32, u64>(12, 751);

        ms_compression::<u64, u128>(1, 100);
        ms_compression::<u64, u128>(10, 64);
        ms_compression::<u64, u128>(11, 700);
        ms_compression::<u64, u128>(12, 751);
        ms_compression::<u64, u128>(33, 10);
        ms_compression::<u64, u128>(53, 37);
        ms_compression::<u64, u128>(63, 63);
    }

    fn ms_compression<
        LweScalar: UnsignedTorus + CastFrom<PackingScalar>,
        PackingScalar: UnsignedTorus + CastFrom<LweScalar>,
    >(
        log_modulus: usize,
        len: usize,
    ) {
        let mut rsc: TestResources = TestResources::new();

        let ciphertext_modulus = CiphertextModulus::new_native();

        let mut lwe = vec![LweScalar::ZERO; len];

        rsc.encryption_random_generator
            .fill_slice_with_random_uniform_mask(&mut lwe);

        let lwe = LweCiphertextOwned::from_container(lwe, ciphertext_modulus);

        let compressed: CompressedModulusSwitchedLweCiphertext<PackingScalar> =
            CompressedModulusSwitchedLweCiphertext::compress(
                &lwe,
                CiphertextModulusLog(log_modulus),
            );

        let lwe_ms_ed: Vec<LweScalar> = compressed.extract().into_container();

        let lwe = lwe.into_container();

        for (i, output) in lwe_ms_ed.into_iter().enumerate() {
            assert_eq!(
                output,
                (output >> (LweScalar::BITS - log_modulus)) << (LweScalar::BITS - log_modulus),
            );

            assert_eq!(
                output >> (LweScalar::BITS - log_modulus),
                modulus_switch(lwe[i], CiphertextModulusLog(log_modulus))
            )
        }
    }
}
