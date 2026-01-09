use tfhe_versionable::Versionize;

use self::packed_integers::PackedIntegers;
use crate::conformance::ParameterSetConformant;
use crate::core_crypto::backward_compatibility::entities::compressed_modulus_switched_glwe_ciphertext::CompressedModulusSwitchedGlweCiphertextVersions;
use crate::core_crypto::fft_impl::common::modulus_switch;
use crate::core_crypto::prelude::*;

/// An object to store a ciphertext using less memory
/// The modulus of the ciphertext is decreased by rounding and the result is stored in a compact way
/// The uncompacted result can be used as the input of a blind rotation to recover a low noise lwe
/// ciphertext
///
/// ```rust
/// use tfhe::core_crypto::fft_impl::common::modulus_switch;
/// use tfhe::core_crypto::prelude::compressed_modulus_switched_glwe_ciphertext::CompressedModulusSwitchedGlweCiphertext;
/// use tfhe::core_crypto::prelude::*;
/// use tfhe_csprng::seeders::Seed;
///
/// let log_modulus = 12;
///
/// let glwe_size = GlweSize(2);
/// let polynomial_size = PolynomialSize(1024);
/// let glwe_noise_distribution =
///     Gaussian::from_dispersion_parameter(StandardDev(0.00000000000000029403601535432533), 0.0);
/// let ciphertext_modulus = CiphertextModulus::new_native();
///
/// let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(Seed(0));
///
/// let glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key::<u64, _>(
///     glwe_size.to_glwe_dimension(),
///     polynomial_size,
///     &mut secret_generator,
/// );
///
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
///
/// let mut encryption_generator =
///     EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
///
/// let inputs = [1 << 57, 1 << 58];
///
/// let mut plaintext_list = PlaintextList::new(0, PlaintextCount(polynomial_size.0));
///
/// plaintext_list.as_mut_view().into_container()[0..inputs.len()].copy_from_slice(&inputs);
///
/// let mut glwe = GlweCiphertextOwned::new(0, glwe_size, polynomial_size, ciphertext_modulus);
///
/// encrypt_glwe_ciphertext(
///     &glwe_secret_key,
///     &mut glwe,
///     &plaintext_list,
///     glwe_noise_distribution,
///     &mut encryption_generator,
/// );
///
/// // Can be stored using much less space than the standard lwe ciphertexts
/// let compressed = CompressedModulusSwitchedGlweCiphertext::compress(
///     &glwe,
///     CiphertextModulusLog(log_modulus as usize),
///     LweCiphertextCount(2),
/// );
///
/// let glwe_ms_ed = compressed.extract();
///
/// let mut output_list = PlaintextList::new(0, PlaintextCount(polynomial_size.0));
///
/// decrypt_glwe_ciphertext(&glwe_secret_key, &glwe_ms_ed, &mut output_list);
///
/// let output_list = output_list.into_container();
///
/// for (i, input) in inputs.iter().enumerate() {
///     assert_eq!(
///         modulus_switch(input.wrapping_sub(output_list[i]), CiphertextModulusLog(5)),
///         0,
///     );
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(CompressedModulusSwitchedGlweCiphertextVersions)]
pub struct CompressedModulusSwitchedGlweCiphertext<Scalar: UnsignedInteger> {
    packed_integers: PackedIntegers<Scalar>,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    bodies_count: LweCiphertextCount,
    uncompressed_ciphertext_modulus: CiphertextModulus<Scalar>,
}

impl<Scalar: UnsignedInteger> CompressedModulusSwitchedGlweCiphertext<Scalar> {
    pub fn from_raw_parts(
        packed_integers: PackedIntegers<Scalar>,
        glwe_dimension: GlweDimension,
        polynomial_size: PolynomialSize,
        bodies_count: LweCiphertextCount,
        uncompressed_ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        assert_eq!(
            glwe_dimension.0 * polynomial_size.0 + bodies_count.0,
            packed_integers.initial_len(),
            "Packed integers list is not of the correct size for the uncompressed GLWE: expected {}, got {}",
            glwe_dimension.0 * polynomial_size.0 + bodies_count.0,
            packed_integers.initial_len(),
        );

        assert!(
            packed_integers.log_modulus().0
                <= CiphertextModulusLog::from(uncompressed_ciphertext_modulus).0,
            "Compressed modulus (={}) should be smaller than the uncompressed modulus (={})",
            packed_integers.log_modulus().0,
            CiphertextModulusLog::from(uncompressed_ciphertext_modulus).0,
        );

        Self {
            packed_integers,
            glwe_dimension,
            polynomial_size,
            bodies_count,
            uncompressed_ciphertext_modulus,
        }
    }

    #[cfg(test)]
    pub(crate) fn into_raw_parts(
        self,
    ) -> (
        PackedIntegers<Scalar>,
        GlweDimension,
        PolynomialSize,
        LweCiphertextCount,
        CiphertextModulus<Scalar>,
    ) {
        let Self {
            packed_integers,
            glwe_dimension,
            polynomial_size,
            bodies_count,
            uncompressed_ciphertext_modulus,
        } = self;

        (
            packed_integers,
            glwe_dimension,
            polynomial_size,
            bodies_count,
            uncompressed_ciphertext_modulus,
        )
    }

    pub fn glwe_dimension(&self) -> GlweDimension {
        self.glwe_dimension
    }
    pub fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }
    pub fn bodies_count(&self) -> LweCiphertextCount {
        self.bodies_count
    }
    pub fn uncompressed_ciphertext_modulus(&self) -> CiphertextModulus<Scalar> {
        self.uncompressed_ciphertext_modulus
    }

    pub fn packed_integers(&self) -> &PackedIntegers<Scalar> {
        &self.packed_integers
    }

    /// Compresses a ciphertext by reducing its modulus
    /// This operation adds a lot of noise
    pub fn compress<Cont: Container<Element = Scalar>>(
        ct: &GlweCiphertext<Cont>,
        log_modulus: CiphertextModulusLog,
        bodies_count: LweCiphertextCount,
    ) -> Self {
        let uncompressed_ciphertext_modulus = ct.ciphertext_modulus();

        assert!(
            ct.ciphertext_modulus().is_power_of_two(),
            "Modulus switch compression does not support non power of 2 input moduli",
        );

        let uncompressed_ciphertext_modulus_log =
            if uncompressed_ciphertext_modulus.is_native_modulus() {
                Scalar::BITS
            } else {
                uncompressed_ciphertext_modulus.get_custom_modulus().ilog2() as usize
            };

        let glwe_dimension = ct.glwe_size().to_glwe_dimension();
        let polynomial_size = ct.polynomial_size();

        assert!(
            bodies_count.0 <= polynomial_size.0,
            "Number of stored bodies (asked {}) cannot be bigger than polynomial_size ={}",
            bodies_count.0,
            polynomial_size.0,
        );

        assert!(
            log_modulus.0 <= uncompressed_ciphertext_modulus_log,
            "The log_modulus (={}) for modulus switch compression must be smaller than the uncompressed ciphertext_modulus_log (={})",
            log_modulus.0,
            uncompressed_ciphertext_modulus_log,
        );

        let modulus_switched: Vec<_> = ct.as_ref()
            [0..glwe_dimension.0 * polynomial_size.0 + bodies_count.0]
            .iter()
            .map(|a| modulus_switch(*a, log_modulus))
            .collect();

        let packed_integers = PackedIntegers::pack(&modulus_switched, log_modulus);

        Self {
            packed_integers,
            glwe_dimension,
            polynomial_size,
            bodies_count,
            uncompressed_ciphertext_modulus,
        }
    }

    /// Converts back a compressed ciphertext to its initial modulus
    /// The noise added during the compression stays in the output
    /// The output must got through a PBS to reduce the noise
    // TODO: refactor so output is hardcoded msed type
    pub fn extract(&self) -> GlweCiphertextOwned<Scalar> {
        let log_modulus = self.packed_integers.log_modulus().0;

        let number_bits_to_unpack =
            (self.glwe_dimension.0 * self.polynomial_size.0 + self.bodies_count.0) * log_modulus;

        let len: usize = number_bits_to_unpack.div_ceil(Scalar::BITS);

        assert_eq!(
            self.packed_integers.packed_coeffs().len(), len,
            "Mismatch between actual(={}) and maximal(={len}) CompressedModulusSwitchedGlweCiphertext packed_coeffs size",
            self.packed_integers.packed_coeffs().len(),
        );

        let container = self
            .packed_integers
            .unpack::<Scalar>()
            // Scaling
            .map(|a| a << (Scalar::BITS - log_modulus))
            .chain(std::iter::repeat_n(
                Scalar::ZERO,
                self.polynomial_size.0 - self.bodies_count.0,
            ))
            .collect();

        GlweCiphertextOwned::from_container(
            container,
            self.polynomial_size,
            self.uncompressed_ciphertext_modulus,
        )
    }
}

impl<Scalar: UnsignedInteger> ParameterSetConformant
    for CompressedModulusSwitchedGlweCiphertext<Scalar>
{
    type ParameterSet = GlweCiphertextConformanceParams<Scalar>;

    fn is_conformant(&self, lwe_ct_parameters: &GlweCiphertextConformanceParams<Scalar>) -> bool {
        let Self {
            packed_integers,
            glwe_dimension,
            polynomial_size,
            bodies_count,
            uncompressed_ciphertext_modulus,
        } = self;
        let log_modulus = packed_integers.log_modulus().0;

        let number_bits_to_unpack =
            (glwe_dimension.0 * polynomial_size.0 + bodies_count.0) * log_modulus;

        let len = number_bits_to_unpack.div_ceil(Scalar::BITS);

        packed_integers.packed_coeffs().len() == len
            && *glwe_dimension == lwe_ct_parameters.glwe_dim
            && *polynomial_size == lwe_ct_parameters.polynomial_size
            && lwe_ct_parameters.ct_modulus.is_power_of_two()
            && *uncompressed_ciphertext_modulus == lwe_ct_parameters.ct_modulus
    }
}

#[cfg(test)]
mod test {
    use rand::{Fill, Rng};

    use super::*;

    #[test]
    fn glwe_ms_compression_() {
        glwe_ms_compression::<u32>(1, GlweDimension(1), PolynomialSize(512), 0);
        glwe_ms_compression::<u32>(10, GlweDimension(1), PolynomialSize(512), 1);
        glwe_ms_compression::<u32>(11, GlweDimension(1), PolynomialSize(512), 511);
        glwe_ms_compression::<u32>(12, GlweDimension(1), PolynomialSize(512), 512);

        glwe_ms_compression::<u64>(1, GlweDimension(1), PolynomialSize(512), 100);
        glwe_ms_compression::<u64>(10, GlweDimension(1), PolynomialSize(512), 512);
        glwe_ms_compression::<u64>(11, GlweDimension(1), PolynomialSize(512), 512);
        glwe_ms_compression::<u64>(12, GlweDimension(1), PolynomialSize(512), 512);
        glwe_ms_compression::<u64>(33, GlweDimension(1), PolynomialSize(512), 512);
        glwe_ms_compression::<u64>(53, GlweDimension(1), PolynomialSize(512), 512);
        glwe_ms_compression::<u64>(63, GlweDimension(1), PolynomialSize(512), 512);

        glwe_ms_compression::<u128>(127, GlweDimension(1), PolynomialSize(512), 100);
    }

    fn glwe_ms_compression<Scalar: UnsignedTorus + CastInto<usize> + CastFrom<usize>>(
        log_modulus: usize,
        glwe_dimension: GlweDimension,
        polynomial_size: PolynomialSize,
        bodies_count: usize,
    ) where
        [Scalar]: Fill,
    {
        let ciphertext_modulus = CiphertextModulus::new_native();

        let mut glwe = GlweCiphertext::new(
            Scalar::ZERO,
            glwe_dimension.to_glwe_size(),
            polynomial_size,
            ciphertext_modulus,
        );

        // We don't care about the exact content here
        rand::rng().fill(glwe.as_mut());

        let compressed = CompressedModulusSwitchedGlweCiphertext::compress(
            &glwe,
            CiphertextModulusLog(log_modulus),
            LweCiphertextCount(bodies_count),
        );

        let glwe_ms_ed: Vec<Scalar> = compressed.extract().into_container();

        let glwe = glwe.into_container();

        for (i, output) in glwe_ms_ed
            .into_iter()
            .enumerate()
            .take(glwe_dimension.0 * polynomial_size.0 + bodies_count)
        {
            assert_eq!(
                output,
                (output >> (Scalar::BITS - log_modulus)) << (Scalar::BITS - log_modulus),
            );

            assert_eq!(
                output >> (Scalar::BITS - log_modulus),
                modulus_switch(glwe[i], CiphertextModulusLog(log_modulus))
            )
        }
    }

    #[test]
    fn test_from_raw_parts() {
        type Scalar = u64;

        let ciphertext_modulus = CiphertextModulus::new_native();
        let glwe_dimension = GlweDimension(1);
        let polynomial_size = PolynomialSize(512);
        let bodies_count = LweCiphertextCount(512);
        let log_modulus = 12;

        let mut glwe = GlweCiphertext::new(
            Scalar::ZERO,
            glwe_dimension.to_glwe_size(),
            polynomial_size,
            ciphertext_modulus,
        );

        // We don't care about the exact content here
        rand::rng().fill(glwe.as_mut());

        let compressed = CompressedModulusSwitchedGlweCiphertext::compress(
            &glwe,
            CiphertextModulusLog(log_modulus),
            bodies_count,
        );

        let (
            packed_integers,
            glwe_dimension,
            polynomial_size,
            bodies_count,
            uncompressed_ciphertext_modulus,
        ) = compressed.into_raw_parts();

        let rebuilt = CompressedModulusSwitchedGlweCiphertext::from_raw_parts(
            packed_integers,
            glwe_dimension,
            polynomial_size,
            bodies_count,
            uncompressed_ciphertext_modulus,
        );

        let glwe_ms_ed = rebuilt.extract().into_container();
        let glwe = glwe.into_container();

        for (i, output) in glwe_ms_ed.into_iter().enumerate() {
            assert_eq!(
                output,
                (output >> (Scalar::BITS as usize - log_modulus))
                    << (Scalar::BITS as usize - log_modulus),
            );

            assert_eq!(
                output >> (Scalar::BITS as usize - log_modulus),
                modulus_switch(glwe[i], CiphertextModulusLog(log_modulus))
            )
        }
    }
}
