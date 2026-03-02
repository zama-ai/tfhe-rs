//! Module containing the definition of the SeededGlweCiphertext.

use misc::check_encrypted_content_respects_mod;
use tfhe_versionable::Versionize;

use crate::conformance::ParameterSetConformant;
use crate::core_crypto::algorithms::*;
use crate::core_crypto::backward_compatibility::entities::seeded_glwe_ciphertext::SeededGlweCiphertextVersions;
use crate::core_crypto::commons::math::random::{CompressionSeed, DefaultRandomGenerator};
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// A [`seeded GLWE ciphertext`](`SeededGlweCiphertext`).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(SeededGlweCiphertextVersions)]
pub struct SeededGlweCiphertext<C: Container>
where
    C::Element: UnsignedInteger,
{
    data: C,
    glwe_size: GlweSize,
    compression_seed: CompressionSeed,
    ciphertext_modulus: CiphertextModulus<C::Element>,
}

impl<T: UnsignedInteger, C: Container<Element = T>> AsRef<[T]> for SeededGlweCiphertext<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T: UnsignedInteger, C: ContainerMut<Element = T>> AsMut<[T]> for SeededGlweCiphertext<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> SeededGlweCiphertext<C> {
    /// Create a [`SeededGlweCiphertext`] from an existing container.
    ///
    /// # Note
    ///
    /// This function only wraps a container in the appropriate type. If you want to encrypt data
    /// you need to use [`crate::core_crypto::algorithms::encrypt_seeded_glwe_ciphertext`] using
    /// this ciphertext as output.
    ///
    /// This docstring exhibits [`SeededGlweCiphertext`] primitives usage.
    ///
    /// ```rust
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for SeededGlweCiphertext creation
    /// let glwe_size = GlweSize(2);
    /// let polynomial_size = PolynomialSize(1024);
    /// let ciphertext_modulus = CiphertextModulus::new_native();
    ///
    /// // Get a seeder
    /// let mut seeder = new_seeder();
    /// let seeder = seeder.as_mut();
    ///
    /// // Create a new SeededGlweCiphertext
    /// let mut glwe = SeededGlweCiphertext::new(
    ///     0u64,
    ///     glwe_size,
    ///     polynomial_size,
    ///     seeder.seed().into(),
    ///     ciphertext_modulus,
    /// );
    ///
    /// assert_eq!(glwe.glwe_size(), glwe_size);
    /// assert_eq!(glwe.polynomial_size(), polynomial_size);
    /// assert_eq!(glwe.ciphertext_modulus(), ciphertext_modulus);
    /// assert_eq!(glwe.get_body().polynomial_size(), polynomial_size);
    /// assert_eq!(glwe.get_mut_body().polynomial_size(), polynomial_size);
    /// assert_eq!(glwe.get_body().ciphertext_modulus(), ciphertext_modulus);
    /// assert_eq!(glwe.get_mut_body().ciphertext_modulus(), ciphertext_modulus);
    ///
    /// let compression_seed = glwe.compression_seed();
    ///
    /// // Demonstrate how to recover the allocated container
    /// let underlying_container: Vec<u64> = glwe.into_container();
    ///
    /// // Recreate a ciphertext using from_container
    /// let mut glwe = SeededGlweCiphertext::from_container(
    ///     underlying_container,
    ///     glwe_size,
    ///     compression_seed,
    ///     ciphertext_modulus,
    /// );
    ///
    /// assert_eq!(glwe.glwe_size(), glwe_size);
    /// assert_eq!(glwe.polynomial_size(), polynomial_size);
    /// assert_eq!(glwe.ciphertext_modulus(), ciphertext_modulus);
    /// assert_eq!(glwe.get_body().polynomial_size(), polynomial_size);
    /// assert_eq!(glwe.get_mut_body().polynomial_size(), polynomial_size);
    /// assert_eq!(glwe.get_body().ciphertext_modulus(), ciphertext_modulus);
    /// assert_eq!(glwe.get_mut_body().ciphertext_modulus(), ciphertext_modulus);
    ///
    /// // Decompress the ciphertext
    /// let mut glwe = glwe.decompress_into_glwe_ciphertext();
    ///
    /// assert_eq!(glwe.glwe_size(), glwe_size);
    /// assert_eq!(glwe.polynomial_size(), polynomial_size);
    /// assert_eq!(glwe.ciphertext_modulus(), ciphertext_modulus);
    /// assert_eq!(glwe.get_body().polynomial_size(), polynomial_size);
    /// assert_eq!(glwe.get_mut_body().polynomial_size(), polynomial_size);
    /// assert_eq!(glwe.get_body().ciphertext_modulus(), ciphertext_modulus);
    /// assert_eq!(glwe.get_mut_body().ciphertext_modulus(), ciphertext_modulus);
    /// assert_eq!(
    ///     glwe.get_mask().glwe_dimension(),
    ///     glwe_size.to_glwe_dimension()
    /// );
    /// assert_eq!(
    ///     glwe.get_mut_mask().glwe_dimension(),
    ///     glwe_size.to_glwe_dimension()
    /// );
    /// assert_eq!(glwe.get_mask().polynomial_size(), polynomial_size);
    /// assert_eq!(glwe.get_mut_mask().polynomial_size(), polynomial_size);
    /// assert_eq!(glwe.get_mask().ciphertext_modulus(), ciphertext_modulus);
    /// assert_eq!(glwe.get_mut_mask().ciphertext_modulus(), ciphertext_modulus);
    /// ```
    pub fn from_container(
        container: C,
        glwe_size: GlweSize,
        compression_seed: CompressionSeed,
        ciphertext_modulus: CiphertextModulus<C::Element>,
    ) -> Self {
        assert!(
            ciphertext_modulus.is_compatible_with_native_modulus(),
            "Seeded entities are not yet compatible with non power of 2 moduli."
        );

        assert!(
            container.container_len() > 0,
            "Got an empty container to create a SeededGlweCiphertext"
        );
        Self {
            data: container,
            glwe_size,
            compression_seed,
            ciphertext_modulus,
        }
    }

    /// Return the [`GlweSize`] of the [`SeededGlweCiphertext`].
    ///
    /// See [`SeededGlweCiphertext::from_container`] for usage.
    pub fn glwe_size(&self) -> GlweSize {
        self.glwe_size
    }

    /// Return the [`PolynomialSize`] of the [`SeededGlweCiphertext`].
    ///
    /// See [`SeededGlweCiphertext::from_container`] for usage.
    pub fn polynomial_size(&self) -> PolynomialSize {
        PolynomialSize(self.data.container_len())
    }

    /// Return the [`CompressionSeed`] of the [`SeededGlweCiphertext`].
    ///
    /// See [`SeededGlweCiphertext::from_container`] for usage.
    pub fn compression_seed(&self) -> CompressionSeed {
        self.compression_seed.clone()
    }

    /// Return the [`CiphertextModulus`] of the [`SeededGlweCiphertext`].
    ///
    /// See [`SeededGlweCiphertext::from_container`] for usage.
    pub fn ciphertext_modulus(&self) -> CiphertextModulus<C::Element> {
        self.ciphertext_modulus
    }

    /// Return an immutable view to the [`GlweBody`] of a [`SeededGlweCiphertext`].
    ///
    /// See [`SeededGlweCiphertext::from_container`] for usage.
    pub fn get_body(&self) -> GlweBody<&[Scalar]> {
        GlweBody::from_container(self.as_ref(), self.ciphertext_modulus())
    }

    /// Consume the entity and return its underlying container.
    ///
    /// See [`SeededGlweCiphertext::from_container`] for usage.
    pub fn into_container(self) -> C {
        self.data
    }

    /// Consume the [`SeededGlweCiphertext`] and decompress it into a standard
    /// [`GlweCiphertext`].
    ///
    /// See [`SeededGlweCiphertext::from_container`] for usage.
    pub fn decompress_into_glwe_ciphertext(self) -> GlweCiphertextOwned<Scalar>
    where
        Scalar: UnsignedTorus,
    {
        let mut decompressed_ct = GlweCiphertext::new(
            Scalar::ZERO,
            self.glwe_size(),
            self.polynomial_size(),
            self.ciphertext_modulus(),
        );
        decompress_seeded_glwe_ciphertext::<_, _, _, DefaultRandomGenerator>(
            &mut decompressed_ct,
            &self,
        );
        decompressed_ct
    }

    /// Return a view of the [`SeededGlweCiphertext`]. This is useful if an algorithm takes a view
    /// by value.
    pub fn as_view(&self) -> SeededGlweCiphertext<&'_ [Scalar]> {
        SeededGlweCiphertext {
            data: self.data.as_ref(),
            glwe_size: self.glwe_size,
            compression_seed: self.compression_seed.clone(),
            ciphertext_modulus: self.ciphertext_modulus,
        }
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> SeededGlweCiphertext<C> {
    /// Mutable variant of [`SeededGlweCiphertext::get_body`].
    ///
    /// See [`SeededGlweCiphertext::from_container`] for usage.
    pub fn get_mut_body(&mut self) -> GlweBody<&mut [Scalar]> {
        let ciphertext_modulus = self.ciphertext_modulus();
        GlweBody::from_container(self.as_mut(), ciphertext_modulus)
    }

    /// Mutable variant of [`SeededGlweCiphertext::as_view`].
    pub fn as_mut_view(&mut self) -> SeededGlweCiphertext<&'_ mut [Scalar]> {
        SeededGlweCiphertext {
            data: self.data.as_mut(),
            glwe_size: self.glwe_size,
            compression_seed: self.compression_seed.clone(),
            ciphertext_modulus: self.ciphertext_modulus,
        }
    }
}

/// A [`SeededGlweCiphertext`] owning the memory for its own storage.
pub type SeededGlweCiphertextOwned<Scalar> = SeededGlweCiphertext<Vec<Scalar>>;
/// A [`SeededGlweCiphertext`] immutably borrowing memory for its own storage.
pub type SeededGlweCiphertextView<'data, Scalar> = SeededGlweCiphertext<&'data [Scalar]>;
/// A [`SeededGlweCiphertext`] mutably borrowing memory for its own storage.
pub type SeededGlweCiphertextMutView<'data, Scalar> = SeededGlweCiphertext<&'data mut [Scalar]>;

impl<Scalar: UnsignedInteger> SeededGlweCiphertextOwned<Scalar> {
    /// Allocate memory and create a new owned [`SeededGlweCiphertext`].
    ///
    /// # Note
    ///
    /// This function allocates a vector of the appropriate size and wraps it in the appropriate
    /// type. If you want to encrypt data you need to use
    /// [`crate::core_crypto::algorithms::encrypt_glwe_ciphertext`] using this ciphertext as
    /// output.
    ///
    ///
    /// See [`SeededGlweCiphertext::from_container`] for usage.
    pub fn new(
        fill_with: Scalar,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        compression_seed: CompressionSeed,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        Self::from_container(
            vec![fill_with; polynomial_size.0],
            glwe_size,
            compression_seed,
            ciphertext_modulus,
        )
    }
}

/// Metadata used in the [`CreateFrom`] implementation to create [`SeededGlweCiphertext`] entities.
#[derive(Clone)]
pub struct SeededGlweCiphertextCreationMetadata<Scalar: UnsignedInteger> {
    pub glwe_size: GlweSize,
    pub compression_seed: CompressionSeed,
    pub ciphertext_modulus: CiphertextModulus<Scalar>,
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> CreateFrom<C>
    for SeededGlweCiphertext<C>
{
    type Metadata = SeededGlweCiphertextCreationMetadata<Scalar>;

    #[inline]
    fn create_from(from: C, meta: Self::Metadata) -> Self {
        let SeededGlweCiphertextCreationMetadata {
            glwe_size,
            compression_seed,
            ciphertext_modulus,
        } = meta;
        Self::from_container(from, glwe_size, compression_seed, ciphertext_modulus)
    }
}

impl<C: Container> ParameterSetConformant for SeededGlweCiphertext<C>
where
    C::Element: UnsignedInteger,
{
    type ParameterSet = GlweCiphertextConformanceParams<C::Element>;

    fn is_conformant(
        &self,
        glwe_ct_parameters: &GlweCiphertextConformanceParams<C::Element>,
    ) -> bool {
        let Self {
            compression_seed: _,
            data,
            ciphertext_modulus,
            glwe_size,
        } = self;

        glwe_ct_parameters.polynomial_size.0.is_power_of_two()
            && check_encrypted_content_respects_mod(self, glwe_ct_parameters.ct_modulus)
            && data.container_len() == glwe_ct_parameters.polynomial_size.0
            && *glwe_size == glwe_ct_parameters.glwe_dim.to_glwe_size()
            && *ciphertext_modulus == glwe_ct_parameters.ct_modulus
    }
}
