//! Module containing the definition of the SeededGlweCiphertextList.

use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::math::random::{ActivatedRandomGenerator, CompressionSeed};
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// A seeded list containing
/// [`GLWE ciphertexts`](`crate::core_crypto::entities::GlweCiphertext`).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SeededGlweCiphertextList<C: Container> {
    data: C,
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    compression_seed: CompressionSeed,
}

impl<T, C: Container<Element = T>> AsRef<[T]> for SeededGlweCiphertextList<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T, C: ContainerMut<Element = T>> AsMut<[T]> for SeededGlweCiphertextList<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

impl<Scalar, C: Container<Element = Scalar>> SeededGlweCiphertextList<C> {
    /// Create an [`SeededGlweCiphertextList`] from an existing container.
    ///
    /// # Note
    ///
    /// This function only wraps a container in the appropriate type. If you want to encrypt data
    /// you need to use [`crate::core_crypto::algorithms::encrypt_seeded_glwe_ciphertext_list`] or
    /// using this list as output.
    ///
    /// This docstring exhibits [`SeededGlweCiphertextList`] primitives usage.
    ///
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for SeededGlweCiphertextList creation
    /// let glwe_size = GlweSize(2);
    /// let polynomial_size = PolynomialSize(1024);
    /// let glwe_ciphertext_count = GlweCiphertextCount(2);
    ///
    /// // Get a seeder
    /// let mut seeder = new_seeder();
    /// let seeder = seeder.as_mut();
    ///
    /// // Create a new SeededGlweCiphertextList
    /// let mut seeded_glwe_list = SeededGlweCiphertextList::new(
    ///     0u64,
    ///     glwe_size,
    ///     polynomial_size,
    ///     glwe_ciphertext_count,
    ///     seeder.seed().into(),
    /// );
    ///
    /// assert_eq!(seeded_glwe_list.glwe_size(), glwe_size);
    /// assert_eq!(seeded_glwe_list.polynomial_size(), polynomial_size);
    /// assert_eq!(
    ///     seeded_glwe_list.glwe_ciphertext_count(),
    ///     glwe_ciphertext_count
    /// );
    ///
    /// let compression_seed = seeded_glwe_list.compression_seed();
    ///
    /// // Demonstrate how to recover the allocated container
    /// let underlying_container: Vec<u64> = seeded_glwe_list.into_container();
    ///
    /// // Recreate a list using from_container
    /// let seeded_glwe_list = SeededGlweCiphertextList::from_container(
    ///     underlying_container,
    ///     glwe_size,
    ///     polynomial_size,
    ///     compression_seed,
    /// );
    ///
    /// assert_eq!(seeded_glwe_list.glwe_size(), glwe_size);
    /// assert_eq!(seeded_glwe_list.polynomial_size(), polynomial_size);
    /// assert_eq!(
    ///     seeded_glwe_list.glwe_ciphertext_count(),
    ///     glwe_ciphertext_count
    /// );
    ///
    /// // Decompress the list
    /// let glwe_list = seeded_glwe_list.decompress_into_glwe_ciphertext_list();
    ///
    /// assert_eq!(glwe_list.glwe_size(), glwe_size);
    /// assert_eq!(glwe_list.polynomial_size(), polynomial_size);
    /// assert_eq!(glwe_list.glwe_ciphertext_count(), glwe_ciphertext_count);
    /// ```
    pub fn from_container(
        container: C,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        compression_seed: CompressionSeed,
    ) -> SeededGlweCiphertextList<C> {
        SeededGlweCiphertextList {
            data: container,
            glwe_size,
            polynomial_size,
            compression_seed,
        }
    }

    /// Return the [`GlweSize`] of the compressed [`GlweCiphertext`] stored in the list.
    ///
    /// See [`SeededGlweCiphertextList::from_container`] for usage.
    pub fn glwe_size(&self) -> GlweSize {
        self.glwe_size
    }

    /// Return the [`PolynomialSize`] of the compressed [`GlweCiphertext`] stored in the list.
    ///
    /// See [`SeededGlweCiphertextList::from_container`] for usage.
    pub fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    /// Return the [`CompressionSeed`] of the [`SeededGlweCiphertextList`].
    ///
    /// See [`SeededGlweCiphertextList::from_container`] for usage.
    pub fn compression_seed(&self) -> CompressionSeed {
        self.compression_seed
    }

    /// Return the [`GlweCiphertextCount`] of the [`SeededGlweCiphertextList`].
    ///
    /// See [`SeededGlweCiphertextList::from_container`] for usage.
    pub fn glwe_ciphertext_count(&self) -> GlweCiphertextCount {
        GlweCiphertextCount(self.data.container_len() / self.polynomial_size.0)
    }

    /// Consume the entity and return its underlying container.
    ///
    /// See [`SeededGlweCiphertextList::from_container`] for usage.
    pub fn into_container(self) -> C {
        self.data
    }

    /// Consume the [`SeededGlweCiphertextList`] and decompress it into a standard
    /// [`GlweCiphertextList`].
    ///
    /// See [`SeededGlweCiphertextList::from_container`] for usage.
    pub fn decompress_into_glwe_ciphertext_list(self) -> GlweCiphertextListOwned<Scalar>
    where
        Scalar: UnsignedTorus,
    {
        let mut decompressed_list = GlweCiphertextList::new(
            Scalar::ZERO,
            self.glwe_size(),
            self.polynomial_size(),
            self.glwe_ciphertext_count(),
        );
        decompress_seeded_glwe_ciphertext_list::<_, _, _, ActivatedRandomGenerator>(
            &mut decompressed_list,
            &self,
        );
        decompressed_list
    }

    /// Return a view of the [`SeededGlweCiphertextList`]. This is useful if an algorithm takes a
    /// view by value.
    pub fn as_view(&self) -> SeededGlweCiphertextList<&'_ [Scalar]> {
        SeededGlweCiphertextList::from_container(
            self.as_ref(),
            self.glwe_size(),
            self.polynomial_size(),
            self.compression_seed(),
        )
    }
}

impl<Scalar, C: ContainerMut<Element = Scalar>> SeededGlweCiphertextList<C> {
    /// Mutable variant of [`SeededGlweCiphertextList::as_view`].
    pub fn as_mut_view(&mut self) -> SeededGlweCiphertextList<&'_ mut [Scalar]> {
        let glwe_size = self.glwe_size();
        let polynomial_size = self.polynomial_size();
        let compression_seed = self.compression_seed();
        SeededGlweCiphertextList::from_container(
            self.as_mut(),
            glwe_size,
            polynomial_size,
            compression_seed,
        )
    }
}

/// An [`SeededGlweCiphertextList`] owning the memory for its own storage.
pub type SeededGlweCiphertextListOwned<Scalar> = SeededGlweCiphertextList<Vec<Scalar>>;
/// An [`SeededGlweCiphertextList`] immutably borrowing memory for its own storage.
pub type SeededGlweCiphertextListView<'data, Scalar> = SeededGlweCiphertextList<&'data [Scalar]>;
/// An [`SeededGlweCiphertextList`] mutably borrowing memory for its own storage.
pub type SeededGlweCiphertextListMutView<'data, Scalar> =
    SeededGlweCiphertextList<&'data mut [Scalar]>;

impl<Scalar: Copy> SeededGlweCiphertextListOwned<Scalar> {
    /// Allocate memory and create a new owned [`SeededGlweCiphertextList`].
    ///
    /// # Note
    ///
    /// This function allocates a vector of the appropriate size and wraps it in the appropriate
    /// type. If you want to encrypt data you need to use
    /// [`crate::core_crypto::algorithms::encrypt_seeded_glwe_ciphertext_list`] using this list as
    /// output.
    ///
    /// See [`SeededGlweCiphertextList::from_container`] for usage.
    pub fn new(
        fill_with: Scalar,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        ciphertext_count: GlweCiphertextCount,
        compression_seed: CompressionSeed,
    ) -> SeededGlweCiphertextListOwned<Scalar> {
        SeededGlweCiphertextListOwned::from_container(
            vec![fill_with; ciphertext_count.0 * polynomial_size.0],
            glwe_size,
            polynomial_size,
            compression_seed,
        )
    }
}

impl<C: Container> ContiguousEntityContainer for SeededGlweCiphertextList<C> {
    type Element = C::Element;

    type EntityViewMetadata = SeededGlweCiphertextCreationMetadata;

    type EntityView<'this> = SeededGlweCiphertext<&'this [Self::Element]>
    where
        Self: 'this;

    type SelfViewMetadata = ();

    type SelfView<'this> = DummyCreateFrom
    where
        Self: 'this;

    fn get_entity_view_creation_metadata(&self) -> Self::EntityViewMetadata {
        SeededGlweCiphertextCreationMetadata(self.glwe_size(), self.compression_seed())
    }

    fn get_entity_view_pod_size(&self) -> usize {
        self.polynomial_size().0
    }

    /// Unimplemented for [`SeededGlweCiphertextList`]. At the moment it does not make sense to
    /// return "sub" seeded lists.
    fn get_self_view_creation_metadata(&self) -> Self::SelfViewMetadata {
        unimplemented!(
            "This function is not supported for SeededGlweCiphertextList. \
        At the moment it does not make sense to return 'sub' seeded lists."
        )
    }
}

impl<C: ContainerMut> ContiguousEntityContainerMut for SeededGlweCiphertextList<C> {
    type EntityMutView<'this> = SeededGlweCiphertext<&'this mut [Self::Element]>
    where
        Self: 'this;

    type SelfMutView<'this> = DummyCreateFrom
    where
        Self: 'this;
}
