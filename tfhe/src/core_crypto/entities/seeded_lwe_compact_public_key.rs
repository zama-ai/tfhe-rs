//! Module containing the definition of the [`SeededLweCompactPublicKey`].

use tfhe_versionable::Versionize;

use crate::conformance::ParameterSetConformant;
use crate::core_crypto::algorithms::decompress_seeded_lwe_compact_public_key;
use crate::core_crypto::backward_compatibility::entities::seeded_lwe_compact_public_key::SeededLweCompactPublicKeyVersions;
use crate::core_crypto::commons::math::random::{CompressionSeed, DefaultRandomGenerator};
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// A [`seeded compact public LWE encryption key`](`SeededLweCompactPublicKey`).
///
/// Implementation of the public key construction described in <https://eprint.iacr.org/2023/603> by
/// M. Joye.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(SeededLweCompactPublicKeyVersions)]
pub struct SeededLweCompactPublicKey<C: Container>
where
    C::Element: UnsignedInteger,
{
    seeded_glwe_ciphertext: SeededGlweCiphertext<C>,
}

impl<T: UnsignedInteger, C: Container<Element = T>> AsRef<[T]> for SeededLweCompactPublicKey<C> {
    fn as_ref(&self) -> &[T] {
        self.seeded_glwe_ciphertext.as_ref()
    }
}

impl<T: UnsignedInteger, C: ContainerMut<Element = T>> AsMut<[T]> for SeededLweCompactPublicKey<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.seeded_glwe_ciphertext.as_mut()
    }
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> SeededLweCompactPublicKey<C> {
    /// Create a [`SeededLweCompactPublicKey`] from an existing container.
    ///
    /// # Note
    ///
    /// This function only wraps a container in the appropriate type. If you want to generate an
    /// [`SeededLweCompactPublicKey`] you need to call
    /// [`crate::core_crypto::algorithms::generate_seeded_lwe_compact_public_key`] using this key as
    /// output.
    ///
    /// This docstring exhibits [`SeededLweCompactPublicKey`] primitives usage.
    ///
    /// ```rust
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for SeededLweCompactPublicKey creation
    /// let lwe_dimension = LweDimension(1024);
    /// let ciphertext_modulus = CiphertextModulus::new_native();
    ///
    /// // Get a seeder
    /// let mut seeder = new_seeder();
    /// let seeder = seeder.as_mut();
    ///
    /// // Create a new SeededLweCompactPublicKey
    /// let seeded_lwe_compact_public_key = SeededLweCompactPublicKey::new(
    ///     0u64,
    ///     lwe_dimension,
    ///     seeder.seed().into(),
    ///     ciphertext_modulus,
    /// );
    ///
    /// assert_eq!(seeded_lwe_compact_public_key.lwe_dimension(), lwe_dimension);
    /// assert_eq!(
    ///     seeded_lwe_compact_public_key.ciphertext_modulus(),
    ///     ciphertext_modulus
    /// );
    ///
    /// let compression_seed = seeded_lwe_compact_public_key.compression_seed();
    ///
    /// // Demonstrate how to recover the allocated container
    /// let underlying_container: Vec<u64> = seeded_lwe_compact_public_key.into_container();
    ///
    /// // Recreate a public key using from_container
    /// let seeded_lwe_compact_public_key = SeededLweCompactPublicKey::from_container(
    ///     underlying_container,
    ///     compression_seed,
    ///     ciphertext_modulus,
    /// );
    ///
    /// assert_eq!(seeded_lwe_compact_public_key.lwe_dimension(), lwe_dimension);
    /// assert_eq!(
    ///     seeded_lwe_compact_public_key.ciphertext_modulus(),
    ///     ciphertext_modulus
    /// );
    ///
    /// let lwe_compact_public_key =
    ///     seeded_lwe_compact_public_key.decompress_into_lwe_compact_public_key();
    ///
    /// assert_eq!(lwe_compact_public_key.lwe_dimension(), lwe_dimension);
    /// assert_eq!(
    ///     lwe_compact_public_key.ciphertext_modulus(),
    ///     ciphertext_modulus
    /// );
    /// ```
    pub fn from_container(
        container: C,
        compression_seed: CompressionSeed,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        assert!(
            ciphertext_modulus.is_compatible_with_native_modulus(),
            "Seeded entities are not yet compatible with non power of 2 moduli."
        );

        assert!(
            container.container_len().is_power_of_two(),
            "SeededLweCompactPublicKey container len must be a power of 2, got len = {}",
            container.container_len()
        );
        Self {
            seeded_glwe_ciphertext: SeededGlweCiphertext::from_container(
                container,
                GlweDimension(1).to_glwe_size(),
                compression_seed,
                ciphertext_modulus,
            ),
        }
    }

    /// Consume the entity and return its underlying container.
    ///
    /// See [`SeededLweCompactPublicKey::from_container`] for usage.
    pub fn into_container(self) -> C {
        self.seeded_glwe_ciphertext.into_container()
    }

    /// Return the [`LweDimension`] of the [`SeededLweCompactPublicKey`].
    ///
    /// See [`SeededLweCompactPublicKey::from_container`] for usage.
    pub fn lwe_dimension(&self) -> LweDimension {
        LweDimension(self.seeded_glwe_ciphertext.polynomial_size().0)
    }

    /// Return the [`CompressionSeed`] of the [`SeededLweCompactPublicKey`].
    ///
    /// See [`SeededLweCompactPublicKey::from_container`] for usage.
    pub fn compression_seed(&self) -> CompressionSeed {
        self.seeded_glwe_ciphertext.compression_seed()
    }

    /// Return the [`CiphertextModulus`] of the [`SeededLweCompactPublicKey`].
    ///
    /// See [`SeededLweCompactPublicKey::from_container`] for usage.
    pub fn ciphertext_modulus(&self) -> CiphertextModulus<Scalar> {
        self.seeded_glwe_ciphertext.ciphertext_modulus()
    }

    /// Return an immutable view to the [`GlweBody`] of the underlying [`GlweCiphertext`] of the
    /// [`SeededLweCompactPublicKey`].
    pub fn get_body(&self) -> GlweBody<&[Scalar]> {
        self.seeded_glwe_ciphertext.get_body()
    }

    /// Return an immutable view to the the underlying [`SeededGlweCiphertext`] of the
    /// [`SeededLweCompactPublicKey`].
    pub fn as_seeded_glwe_ciphertext(&self) -> SeededGlweCiphertextView<'_, Scalar> {
        self.seeded_glwe_ciphertext.as_view()
    }

    /// Consume the [`SeededLweCompactPublicKey`] and decompress it into a standard
    /// [`LweCompactPublicKey`].
    ///
    /// See [`SeededLweCompactPublicKey::from_container`] for usage.
    pub fn decompress_into_lwe_compact_public_key(self) -> LweCompactPublicKeyOwned<Scalar>
    where
        Scalar: UnsignedTorus,
    {
        let mut decompressed_cpk = LweCompactPublicKey::new(
            Scalar::ZERO,
            self.lwe_dimension(),
            self.ciphertext_modulus(),
        );
        decompress_seeded_lwe_compact_public_key::<_, _, _, DefaultRandomGenerator>(
            &mut decompressed_cpk,
            &self,
        );
        decompressed_cpk
    }

    /// Return a view of the [`SeededLweCompactPublicKey`]. This is useful if an algorithm takes a
    /// view by value.
    pub fn as_view(&self) -> SeededLweCompactPublicKey<&[Scalar]> {
        SeededLweCompactPublicKey {
            seeded_glwe_ciphertext: self.seeded_glwe_ciphertext.as_view(),
        }
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> SeededLweCompactPublicKey<C> {
    /// Return a mutable view to the [`GlweBody`] of the underlying [`SeededGlweCiphertext`] of the
    /// [`SeededLweCompactPublicKey`].
    pub fn get_mut_body(&mut self) -> GlweBody<&mut [Scalar]> {
        self.seeded_glwe_ciphertext.get_mut_body()
    }

    /// Return a mutable view to the the underlying [`SeededGlweCiphertext`] of the
    /// [`SeededLweCompactPublicKey`].
    pub fn as_mut_seeded_glwe_ciphertext(&mut self) -> SeededGlweCiphertextMutView<'_, Scalar> {
        self.seeded_glwe_ciphertext.as_mut_view()
    }
}

pub type SeededLweCompactPublicKeyOwned<Scalar> = SeededLweCompactPublicKey<Vec<Scalar>>;

impl<Scalar: UnsignedInteger> SeededLweCompactPublicKeyOwned<Scalar> {
    pub fn new(
        fill_with: Scalar,
        lwe_dimension: LweDimension,
        compression_seed: CompressionSeed,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        assert!(
            lwe_dimension.0.is_power_of_two(),
            "SeededLweCompactPublicKey only supports power of 2 LweDimension. Got lwe_dimension = {}.",
            lwe_dimension.0
        );
        Self::from_container(
            vec![fill_with; lwe_dimension.0],
            compression_seed,
            ciphertext_modulus,
        )
    }
}

impl<C: Container> ParameterSetConformant for SeededLweCompactPublicKey<C>
where
    C::Element: UnsignedInteger,
{
    type ParameterSet = LweCompactPublicKeyEncryptionParameters<C::Element>;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        let Self {
            seeded_glwe_ciphertext,
        } = self;

        if !parameter_set.encryption_lwe_dimension.0.is_power_of_two() {
            return false;
        }

        let glwe_ciphertext_conformance_parameters = GlweCiphertextConformanceParameters {
            glwe_dim: GlweDimension(1),
            polynomial_size: PolynomialSize(parameter_set.encryption_lwe_dimension.0),
            ct_modulus: parameter_set.ciphertext_modulus,
        };

        seeded_glwe_ciphertext.is_conformant(&glwe_ciphertext_conformance_parameters)
    }
}
