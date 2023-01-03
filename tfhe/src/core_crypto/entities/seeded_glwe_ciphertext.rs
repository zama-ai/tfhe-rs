use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::math::random::{ActivatedRandomGenerator, CompressionSeed};
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// A [`seeded GLWE ciphertext`](`SeededGlweCiphertext`).
#[derive(Clone, Debug, PartialEq)]
pub struct SeededGlweCiphertext<C: Container> {
    data: C,
    glwe_size: GlweSize,
    compression_seed: CompressionSeed,
}

impl<T, C: Container<Element = T>> AsRef<[T]> for SeededGlweCiphertext<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T, C: ContainerMut<Element = T>> AsMut<[T]> for SeededGlweCiphertext<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

impl<Scalar, C: Container<Element = Scalar>> SeededGlweCiphertext<C> {
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
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for SeededGlweCiphertext creation
    /// let glwe_size = GlweSize(2);
    /// let polynomial_size = PolynomialSize(1024);
    ///
    /// // Get a seeder
    /// let mut seeder = new_seeder();
    /// let seeder = seeder.as_mut();
    ///
    /// // Create a new SeededGlweCiphertext
    /// let mut glwe =
    ///     SeededGlweCiphertext::new(0u64, glwe_size, polynomial_size, seeder.seed().into());
    ///
    /// assert_eq!(glwe.glwe_size(), glwe_size);
    /// assert_eq!(glwe.polynomial_size(), polynomial_size);
    /// assert_eq!(glwe.get_body().polynomial_size(), polynomial_size);
    /// assert_eq!(glwe.get_mut_body().polynomial_size(), polynomial_size);
    ///
    /// let compression_seed = glwe.compression_seed();
    ///
    /// // Demonstrate how to recover the allocated container
    /// let underlying_container: Vec<u64> = glwe.into_container();
    ///
    /// // Recreate a ciphertext using from_container
    /// let mut glwe =
    ///     SeededGlweCiphertext::from_container(underlying_container, glwe_size, compression_seed);
    ///
    /// assert_eq!(glwe.glwe_size(), glwe_size);
    /// assert_eq!(glwe.polynomial_size(), polynomial_size);
    /// assert_eq!(glwe.get_body().polynomial_size(), polynomial_size);
    /// assert_eq!(glwe.get_mut_body().polynomial_size(), polynomial_size);
    ///
    /// // Decompress the ciphertext
    /// let mut glwe = glwe.decompress_into_glwe_ciphertext();
    ///
    /// assert_eq!(glwe.glwe_size(), glwe_size);
    /// assert_eq!(glwe.polynomial_size(), polynomial_size);
    /// assert_eq!(glwe.get_body().polynomial_size(), polynomial_size);
    /// assert_eq!(glwe.get_mut_body().polynomial_size(), polynomial_size);
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
    /// ```
    pub fn from_container(
        container: C,
        glwe_size: GlweSize,
        compression_seed: CompressionSeed,
    ) -> SeededGlweCiphertext<C> {
        assert!(
            container.container_len() > 0,
            "Got an empty container to create a SeededGlweCiphertext"
        );
        SeededGlweCiphertext {
            data: container,
            glwe_size,
            compression_seed,
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
        self.compression_seed
    }

    /// Return an immutable view to the [`GlweBody`] of a [`SeededGlweCiphertext`].
    ///
    /// See [`SeededGlweCiphertext::from_container`] for usage.
    pub fn get_body(&self) -> GlweBody<&[Scalar]> {
        GlweBody::from_container(self.as_ref())
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
        let mut decompressed_ct =
            GlweCiphertext::new(Scalar::ZERO, self.glwe_size(), self.polynomial_size());
        decompress_seeded_glwe_ciphertext::<_, _, _, ActivatedRandomGenerator>(
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
            compression_seed: self.compression_seed,
        }
    }
}

impl<Scalar, C: ContainerMut<Element = Scalar>> SeededGlweCiphertext<C> {
    /// Mutable variant of [`SeededGlweCiphertext::get_body`].
    ///
    /// See [`SeededGlweCiphertext::from_container`] for usage.
    pub fn get_mut_body(&mut self) -> GlweBody<&mut [Scalar]> {
        GlweBody::from_container(self.as_mut())
    }

    /// Mutable variant of [`SeededGlweCiphertext::as_view`].
    pub fn as_mut_view(&mut self) -> SeededGlweCiphertext<&'_ mut [Scalar]> {
        SeededGlweCiphertext {
            data: self.data.as_mut(),
            glwe_size: self.glwe_size,
            compression_seed: self.compression_seed,
        }
    }
}

/// A [`SeededGlweCiphertext`] owning the memory for its own storage.
pub type SeededGlweCiphertextOwned<Scalar> = SeededGlweCiphertext<Vec<Scalar>>;
/// A [`SeededGlweCiphertext`] immutably borrowing memory for its own storage.
pub type SeededGlweCiphertextView<'data, Scalar> = SeededGlweCiphertext<&'data [Scalar]>;
/// A [`SeededGlweCiphertext`] mutably borrowing memory for its own storage.
pub type SeededGlweCiphertextMutView<'data, Scalar> = SeededGlweCiphertext<&'data mut [Scalar]>;

impl<Scalar: Copy> SeededGlweCiphertextOwned<Scalar> {
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
    ) -> SeededGlweCiphertextOwned<Scalar> {
        SeededGlweCiphertextOwned::from_container(
            vec![fill_with; polynomial_size.0],
            glwe_size,
            compression_seed,
        )
    }
}

/// Metadata used in the [`CreateFrom`] implementation to create [`SeededGlweCiphertext`] entities.
#[derive(Clone, Copy)]
pub struct SeededGlweCiphertextCreationMetadata(pub GlweSize, pub CompressionSeed);

impl<C: Container> CreateFrom<C> for SeededGlweCiphertext<C> {
    type Metadata = SeededGlweCiphertextCreationMetadata;

    #[inline]
    fn create_from(from: C, meta: Self::Metadata) -> SeededGlweCiphertext<C> {
        let SeededGlweCiphertextCreationMetadata(glwe_size, compression_seed) = meta;
        SeededGlweCiphertext::from_container(from, glwe_size, compression_seed)
    }
}
