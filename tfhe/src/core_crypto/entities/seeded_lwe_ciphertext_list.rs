use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::math::random::{ActivatedRandomGenerator, CompressionSeed};
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// A seeded list containing
/// [`LWE ciphertexts`](`crate::core_crypto::entities::LweCiphertext`).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SeededLweCiphertextList<C: Container> {
    data: C,
    lwe_size: LweSize,
    compression_seed: CompressionSeed,
}

impl<T, C: Container<Element = T>> AsRef<[T]> for SeededLweCiphertextList<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T, C: ContainerMut<Element = T>> AsMut<[T]> for SeededLweCiphertextList<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

impl<Scalar, C: Container<Element = Scalar>> SeededLweCiphertextList<C> {
    /// Create an [`SeededLweCiphertextList`] from an existing container.
    ///
    /// # Note
    ///
    /// This function only wraps a container in the appropriate type. If you want to encrypt data
    /// you need to use [`crate::core_crypto::algorithms::encrypt_seeded_lwe_ciphertext_list`] using
    /// this list as output.
    ///
    /// This docstring exhibits [`SeededLweCiphertextList`] primitives usage.
    ///
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    /// use tfhe::seeders::new_seeder;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for LweCiphertext creation
    /// let lwe_dimension = LweDimension(742);
    /// let lwe_ciphertext_count = LweCiphertextCount(2);
    ///
    /// // Get a seeder
    /// let mut seeder = new_seeder();
    /// let seeder = seeder.as_mut();
    ///
    /// // Create a new SeededLweCiphertextList
    /// let mut seeded_lwe_list = SeededLweCiphertextList::new(
    ///     0u64,
    ///     lwe_dimension.to_lwe_size(),
    ///     lwe_ciphertext_count,
    ///     seeder,
    /// );
    ///
    /// assert_eq!(seeded_lwe_list.lwe_size(), lwe_dimension.to_lwe_size());
    /// assert_eq!(seeded_lwe_list.lwe_ciphertext_count(), lwe_ciphertext_count);
    ///
    /// let compression_seed = seeded_lwe_list.compression_seed();
    ///
    /// // Demonstrate how to recover the allocated container
    /// let underlying_container: Vec<u64> = seeded_lwe_list.into_container();
    ///
    /// // Recreate a list using from_container
    /// let seeded_lwe_list = SeededLweCiphertextList::from_container(
    ///     underlying_container,
    ///     lwe_dimension.to_lwe_size(),
    ///     compression_seed,
    /// );
    ///
    /// assert_eq!(seeded_lwe_list.lwe_size(), lwe_dimension.to_lwe_size());
    /// assert_eq!(seeded_lwe_list.lwe_ciphertext_count(), lwe_ciphertext_count);
    ///
    /// // Decompress the list
    /// let lwe_list = seeded_lwe_list.decompress_into_lwe_ciphertext_list();
    ///
    /// assert_eq!(lwe_list.lwe_size(), lwe_dimension.to_lwe_size());
    /// assert_eq!(lwe_list.lwe_ciphertext_count(), lwe_ciphertext_count);
    /// ```
    pub fn from_container(
        container: C,
        lwe_size: LweSize,
        compression_seed: CompressionSeed,
    ) -> SeededLweCiphertextList<C> {
        SeededLweCiphertextList {
            data: container,
            lwe_size,
            compression_seed,
        }
    }

    /// Return the [`LweSize`] of the compressed [`LweCiphertext`] stored in the list.
    ///
    /// See [`SeededLweCiphertextList::from_container`] for usage.
    pub fn lwe_size(&self) -> LweSize {
        self.lwe_size
    }

    /// Return the [`CompressionSeed`] of the [`SeededLweCiphertextList`].
    ///
    /// See [`SeededLweCiphertextList::from_container`] for usage.
    pub fn compression_seed(&self) -> CompressionSeed {
        self.compression_seed
    }

    /// Return the [`LweCiphertextCount`] of the [`SeededLweCiphertextList`].
    ///
    /// See [`SeededLweCiphertextList::from_container`] for usage.
    pub fn lwe_ciphertext_count(&self) -> LweCiphertextCount {
        LweCiphertextCount(self.data.container_len())
    }

    /// Consume the entity and return its underlying container.
    ///
    /// See [`SeededLweCiphertextList::from_container`] for usage.
    pub fn into_container(self) -> C {
        self.data
    }

    /// Consume the [`SeededLweCiphertextList`] and decompress it into a standard
    /// [`LweCiphertextList`].
    ///
    /// See [`SeededLweCiphertextList::from_container`] for usage.
    pub fn decompress_into_lwe_ciphertext_list(self) -> LweCiphertextListOwned<Scalar>
    where
        Scalar: UnsignedTorus,
    {
        let mut decompressed_list =
            LweCiphertextListOwned::new(Scalar::ZERO, self.lwe_size(), self.lwe_ciphertext_count());
        decompress_seeded_lwe_ciphertext_list::<_, _, _, ActivatedRandomGenerator>(
            &mut decompressed_list,
            &self,
        );
        decompressed_list
    }
}

/// An [`SeededLweCiphertextList`] owning the memory for its own storage.
pub type SeededLweCiphertextListOwned<Scalar> = SeededLweCiphertextList<Vec<Scalar>>;
/// An [`SeededLweCiphertextList`] immutably borrowing memory for its own storage.
pub type SeededLweCiphertextListView<'data, Scalar> = SeededLweCiphertextList<&'data [Scalar]>;
/// An [`SeededLweCiphertextList`] mutably borrowing memory for its own storage.
pub type SeededLweCiphertextListMutView<'data, Scalar> =
    SeededLweCiphertextList<&'data mut [Scalar]>;

impl<Scalar: Copy> SeededLweCiphertextListOwned<Scalar> {
    /// Allocate memory and create a new owned [`SeededLweCiphertextList`].
    ///
    /// # Note
    ///
    /// This function allocates a vector of the appropriate size and wraps it in the appropriate
    /// type. If you want to encrypt data you need to use
    /// [`crate::core_crypto::algorithms::encrypt_seeded_lwe_ciphertext_list`] using this list as
    /// output.
    ///
    /// See [`SeededLweCiphertextList::from_container`] for usage.
    pub fn new(
        fill_with: Scalar,
        lwe_size: LweSize,
        ciphertext_count: LweCiphertextCount,
        seeder: &mut dyn Seeder,
    ) -> SeededLweCiphertextListOwned<Scalar> {
        SeededLweCiphertextListOwned::from_container(
            vec![fill_with; ciphertext_count.0],
            lwe_size,
            CompressionSeed {
                seed: seeder.seed(),
            },
        )
    }
}

impl<C: Container> ContiguousEntityContainer for SeededLweCiphertextList<C> {
    type Element = C::Element;

    type EntityViewMetadata = ();

    type EntityView<'this> = LweBody<&'this Self::Element>
    where
        Self: 'this;

    type SelfViewMetadata = ();

    type SelfView<'this> = DummyCreateFrom
    where
        Self: 'this;

    fn get_entity_view_creation_metadata(&self) {}

    fn get_entity_view_pod_size(&self) -> usize {
        1
    }

    /// Unimplemented for [`SeededLweCiphertextList`]. At the moment it does not make sense to
    /// return "sub" seeded lists.
    fn get_self_view_creation_metadata(&self) {
        unimplemented!(
            "This function is not supported for SeededLweCiphertextList. \
        At the moment it does not make sense to return 'sub' seeded lists."
        )
    }
}

impl<C: ContainerMut> ContiguousEntityContainerMut for SeededLweCiphertextList<C> {
    type EntityMutView<'this> = LweBody<&'this mut Self::Element>
    where
        Self: 'this;

    type SelfMutView<'this> = DummyCreateFrom
    where
        Self: 'this;
}
