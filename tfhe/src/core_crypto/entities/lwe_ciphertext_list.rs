//! Module containing the definition of the [`LweCiphertextList`].

use tfhe_versionable::Versionize;

use crate::core_crypto::backward_compatibility::entities::lwe_ciphertext_list::LweCiphertextListVersions;
use crate::core_crypto::commons::generators::EncryptionRandomGeneratorForkConfig;
use crate::core_crypto::commons::math::random::{Distribution, RandomGenerable};
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// A contiguous list containing
/// [`LWE ciphertexts`](`crate::core_crypto::entities::LweCiphertext`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(LweCiphertextListVersions)]
pub struct LweCiphertextList<C: Container>
where
    C::Element: UnsignedInteger,
{
    data: C,
    lwe_size: LweSize,
    ciphertext_modulus: CiphertextModulus<C::Element>,
}

impl<T: UnsignedInteger, C: Container<Element = T>> AsRef<[T]> for LweCiphertextList<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T: UnsignedInteger, C: ContainerMut<Element = T>> AsMut<[T]> for LweCiphertextList<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

/// Return the number of mask samples used during encryption of an [`LweCiphertextList`] given an
/// [`LweDimension`] and an [`LweCiphertextCount`].
pub fn lwe_ciphertext_list_encryption_mask_sample_count(
    lwe_dimension: LweDimension,
    lwe_ciphertext_count: LweCiphertextCount,
) -> EncryptionMaskSampleCount {
    lwe_ciphertext_count.0 * lwe_ciphertext_encryption_mask_sample_count(lwe_dimension)
}

/// Return the number of noise samples required to encrypt an [`LweCiphertextList`] given an
/// [`LweCiphertextCount`]`.
pub fn lwe_ciphertext_list_encryption_noise_sample_count(
    lwe_ciphertext_count: LweCiphertextCount,
) -> EncryptionNoiseSampleCount {
    lwe_ciphertext_count.0 * lwe_ciphertext_encryption_noise_sample_count()
}

pub fn lwe_ciphertext_list_encryption_fork_config<Scalar, MaskDistribution, NoiseDistribution>(
    lwe_ciphertext_count: LweCiphertextCount,
    lwe_dimension: LweDimension,
    mask_distribution: MaskDistribution,
    noise_distribution: NoiseDistribution,
    ciphertext_modulus: CiphertextModulus<Scalar>,
) -> EncryptionRandomGeneratorForkConfig
where
    Scalar: UnsignedInteger
        + RandomGenerable<MaskDistribution, CustomModulus = Scalar>
        + RandomGenerable<NoiseDistribution, CustomModulus = Scalar>,
    MaskDistribution: Distribution,
    NoiseDistribution: Distribution,
{
    let lwe_mask_sample_count = lwe_ciphertext_encryption_mask_sample_count(lwe_dimension);
    let lwe_noise_sample_count = lwe_ciphertext_encryption_noise_sample_count();

    let modulus = ciphertext_modulus.get_custom_modulus_as_optional_scalar();

    EncryptionRandomGeneratorForkConfig::new(
        lwe_ciphertext_count.0,
        lwe_mask_sample_count,
        mask_distribution,
        lwe_noise_sample_count,
        noise_distribution,
        modulus,
    )
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> LweCiphertextList<C> {
    /// Create an [`LweCiphertextList`] from an existing container.
    ///
    /// # Note
    ///
    /// This function only wraps a container in the appropriate type. If you want to encrypt data
    /// you need to use [`crate::core_crypto::algorithms::encrypt_lwe_ciphertext_list`] or its
    /// parallel variant [`crate::core_crypto::algorithms::par_encrypt_lwe_ciphertext_list`] using
    /// this list as output.
    ///
    /// This docstring exhibits [`LweCiphertextList`] primitives usage.
    ///
    /// ```rust
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for LweCiphertextList creation
    /// let lwe_size = LweSize(601);
    /// let lwe_ciphertext_count = LweCiphertextCount(3);
    /// let ciphertext_modulus = CiphertextModulus::new_native();
    ///
    /// // Create a new LweCiphertextList and fill it using copies of a single element
    /// let lwe_list = LweCiphertextList::new(0u64, lwe_size, lwe_ciphertext_count, ciphertext_modulus);
    ///
    /// assert_eq!(lwe_list.lwe_size(), lwe_size);
    /// assert_eq!(lwe_list.lwe_ciphertext_count(), lwe_ciphertext_count);
    /// assert_eq!(lwe_list.ciphertext_modulus(), ciphertext_modulus);
    ///
    /// // Alternatively, create a new LweCiphertextList and fill it using a function
    /// let lwe_list = LweCiphertextList::from_fn(
    ///     lwe_size,
    ///     lwe_ciphertext_count,
    ///     ciphertext_modulus,
    ///     |i, j| {
    ///         // The `i` value represents the index in the list being filled;
    ///         // The `j` value represents the index in the ciphertext being filled;
    ///         // In this example, for every index pair `(i, j)`, we fill the
    ///         // corresponding value using the formula `i + j`
    ///         (i + j) as u64
    ///     },
    /// );
    ///
    /// assert_eq!(lwe_list.lwe_size(), lwe_size);
    /// assert_eq!(lwe_list.lwe_ciphertext_count(), lwe_ciphertext_count);
    /// assert_eq!(lwe_list.ciphertext_modulus(), ciphertext_modulus);
    ///
    /// // Demonstrate how to recover the allocated container
    /// let underlying_container: Vec<u64> = lwe_list.into_container();
    ///
    /// // Recreate a list using from_container
    /// let lwe_list =
    ///     LweCiphertextList::from_container(underlying_container, lwe_size, ciphertext_modulus);
    ///
    /// assert_eq!(lwe_list.lwe_size(), lwe_size);
    /// assert_eq!(lwe_list.lwe_ciphertext_count(), lwe_ciphertext_count);
    /// assert_eq!(lwe_list.ciphertext_modulus(), ciphertext_modulus);
    /// ```
    pub fn from_container(
        container: C,
        lwe_size: LweSize,
        ciphertext_modulus: CiphertextModulus<C::Element>,
    ) -> Self {
        assert!(
            container.container_len() % lwe_size.0 == 0,
            "The provided container length is not valid. \
        It needs to be dividable by lwe_size. \
        Got container length: {} and lwe_size: {lwe_size:?}.",
            container.container_len()
        );
        Self {
            data: container,
            lwe_size,
            ciphertext_modulus,
        }
    }

    /// Return the [`LweSize`] of the [`LweCiphertext`] stored in the list.
    ///
    /// See [`LweCiphertextList::from_container`] for usage.
    pub fn lwe_size(&self) -> LweSize {
        self.lwe_size
    }

    /// Return the [`LweCiphertextCount`] of the [`LweCiphertextList`].
    ///
    /// See [`LweCiphertextList::from_container`] for usage.
    pub fn lwe_ciphertext_count(&self) -> LweCiphertextCount {
        LweCiphertextCount(self.data.container_len() / self.lwe_size.0)
    }

    /// Return a view of the [`LweCiphertextList`]. This is useful if an algorithm takes a view by
    /// value.
    pub fn as_view(&self) -> LweCiphertextListView<'_, Scalar> {
        LweCiphertextListView::from_container(
            self.as_ref(),
            self.lwe_size(),
            self.ciphertext_modulus(),
        )
    }

    /// Consume the entity and return its underlying container.
    ///
    /// See [`LweCiphertextList::from_container`] for usage.
    pub fn into_container(self) -> C {
        self.data
    }

    /// Return the [`CiphertextModulus`] of the [`LweCiphertextList`].
    ///
    /// See [`LweCiphertextList::from_container`] for usage.
    pub fn ciphertext_modulus(&self) -> CiphertextModulus<C::Element> {
        self.ciphertext_modulus
    }

    pub fn encryption_fork_config<MaskDistribution, NoiseDistribution>(
        &self,
        mask_distribution: MaskDistribution,
        noise_distribution: NoiseDistribution,
    ) -> EncryptionRandomGeneratorForkConfig
    where
        MaskDistribution: Distribution,
        NoiseDistribution: Distribution,
        Scalar: RandomGenerable<MaskDistribution, CustomModulus = Scalar>
            + RandomGenerable<NoiseDistribution, CustomModulus = Scalar>,
    {
        lwe_ciphertext_list_encryption_fork_config(
            self.lwe_ciphertext_count(),
            self.lwe_size().to_lwe_dimension(),
            mask_distribution,
            noise_distribution,
            self.ciphertext_modulus(),
        )
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> LweCiphertextList<C> {
    /// Mutable variant of [`LweCiphertextList::as_view`].
    pub fn as_mut_view(&mut self) -> LweCiphertextListMutView<'_, Scalar> {
        let lwe_size = self.lwe_size();
        let ciphertext_modulus = self.ciphertext_modulus();
        LweCiphertextListMutView::from_container(self.as_mut(), lwe_size, ciphertext_modulus)
    }
}

/// An [`LweCiphertextList`] owning the memory for its own storage.
pub type LweCiphertextListOwned<Scalar> = LweCiphertextList<Vec<Scalar>>;
/// An [`LweCiphertextList`] immutably borrowing memory for its own storage.
pub type LweCiphertextListView<'data, Scalar> = LweCiphertextList<&'data [Scalar]>;
/// An [`LweCiphertextList`] mutably borrowing memory for its own storage.
pub type LweCiphertextListMutView<'data, Scalar> = LweCiphertextList<&'data mut [Scalar]>;

impl<Scalar: UnsignedInteger> LweCiphertextListOwned<Scalar> {
    /// Allocate memory and create a new owned [`LweCiphertextList`].
    ///
    /// # Note
    ///
    /// This function allocates a vector of the appropriate size and wraps it in the appropriate
    /// type. If you want to encrypt data you need to use
    /// [`crate::core_crypto::algorithms::encrypt_lwe_ciphertext_list`] or its parallel variant
    /// [`crate::core_crypto::algorithms::par_encrypt_lwe_ciphertext_list`] using this list as
    /// output.
    ///
    /// See [`LweCiphertextList::from_container`] for usage.
    pub fn new(
        fill_with: Scalar,
        lwe_size: LweSize,
        ciphertext_count: LweCiphertextCount,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        Self::from_container(
            vec![fill_with; lwe_size.0 * ciphertext_count.0],
            lwe_size,
            ciphertext_modulus,
        )
    }

    pub fn new_from_lwe_ciphertext_iterator<'a, LweIter>(iter: LweIter) -> crate::Result<Self>
    where
        LweIter: IntoIterator<Item = LweCiphertextView<'a, Scalar>>,
    {
        let mut iter = iter.into_iter();

        let Some(first) = iter.next() else {
            return Err(crate::Error::new(
                "Empty iterator while trying to create an LweCiphertextList".to_string(),
            ));
        };

        let ref_lwe_size = first.lwe_size();
        let ref_ciphertext_modulus = first.ciphertext_modulus();

        let mut container = first.as_ref().to_vec();

        for lwe in iter {
            if lwe.lwe_size() == ref_lwe_size && lwe.ciphertext_modulus() == ref_ciphertext_modulus
            {
                container.extend_from_slice(lwe.as_ref());
            } else {
                return Err(crate::Error::new(
                    "Mismatched LweCiphertextMetadata".to_string(),
                ));
            }
        }

        Ok(Self::from_container(
            container,
            ref_lwe_size,
            ref_ciphertext_modulus,
        ))
    }

    /// Allocate memory and create a new owned [`LweCiphertextList`], where each element
    /// is provided by the `fill_with` function, invoked for each consecutive index.
    ///
    /// # Note
    ///
    /// This function allocates a vector of the appropriate size and wraps it in the appropriate
    /// type. If you want to encrypt data you need to use
    /// [`crate::core_crypto::algorithms::encrypt_lwe_ciphertext_list`] or its parallel variant
    /// [`crate::core_crypto::algorithms::par_encrypt_lwe_ciphertext_list`] using this list as
    /// output.
    ///
    /// See [`LweCiphertextList::from_container`] for usage.
    pub fn from_fn<F>(
        lwe_size: LweSize,
        ciphertext_count: LweCiphertextCount,
        ciphertext_modulus: CiphertextModulus<Scalar>,
        mut fill_with: F,
    ) -> Self
    where
        F: FnMut(usize, usize) -> Scalar,
    {
        let container: Vec<_> = (0..ciphertext_count.0)
            .flat_map(move |i| (0..lwe_size.0).map(move |j| (i, j)))
            .map(|(i, j)| fill_with(i, j))
            .collect();
        Self::from_container(container, lwe_size, ciphertext_modulus)
    }
}

/// Metadata used in the [`CreateFrom`] implementation to create [`LweCiphertextList`] entities.
#[derive(Clone, Copy)]
pub struct LweCiphertextListCreationMetadata<Scalar: UnsignedInteger> {
    pub lwe_size: LweSize,
    pub ciphertext_modulus: CiphertextModulus<Scalar>,
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> CreateFrom<C>
    for LweCiphertextList<C>
{
    type Metadata = LweCiphertextListCreationMetadata<Scalar>;

    #[inline]
    fn create_from(from: C, meta: Self::Metadata) -> Self {
        let LweCiphertextListCreationMetadata {
            lwe_size,
            ciphertext_modulus,
        } = meta;
        Self::from_container(from, lwe_size, ciphertext_modulus)
    }
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> ContiguousEntityContainer
    for LweCiphertextList<C>
{
    type Element = C::Element;

    type EntityViewMetadata = LweCiphertextCreationMetadata<Self::Element>;

    type EntityView<'this>
        = LweCiphertextView<'this, Self::Element>
    where
        Self: 'this;

    type SelfViewMetadata = LweCiphertextListCreationMetadata<Self::Element>;

    type SelfView<'this>
        = LweCiphertextListView<'this, Self::Element>
    where
        Self: 'this;

    fn get_entity_view_creation_metadata(&self) -> Self::EntityViewMetadata {
        LweCiphertextCreationMetadata {
            ciphertext_modulus: self.ciphertext_modulus(),
        }
    }

    fn get_entity_view_pod_size(&self) -> usize {
        self.lwe_size().0
    }

    fn get_self_view_creation_metadata(&self) -> Self::SelfViewMetadata {
        LweCiphertextListCreationMetadata {
            lwe_size: self.lwe_size(),
            ciphertext_modulus: self.ciphertext_modulus(),
        }
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> ContiguousEntityContainerMut
    for LweCiphertextList<C>
{
    type EntityMutView<'this>
        = LweCiphertextMutView<'this, Self::Element>
    where
        Self: 'this;

    type SelfMutView<'this>
        = LweCiphertextListMutView<'this, Self::Element>
    where
        Self: 'this;
}
