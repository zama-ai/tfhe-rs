use crate::core_crypto::backward_compatibility::entities::ntt_ggsw_ciphertext_list::NttGgswCiphertextListVersions;
use crate::core_crypto::commons::numeric::UnsignedInteger;
use crate::core_crypto::commons::parameters::{
    CiphertextModulus, DecompositionBaseLog, DecompositionLevelCount, GgswCiphertextCount,
    GlweSize, PolynomialSize,
};
use crate::core_crypto::commons::traits::{Container, ContainerMut, Split};
use crate::core_crypto::entities::ggsw_ciphertext::ggsw_ciphertext_size;
pub use crate::core_crypto::entities::ggsw_ciphertext_list::ggsw_ciphertext_list_size;
use crate::core_crypto::entities::ntt_ggsw_ciphertext::NttGgswCiphertext;
use crate::core_crypto::entities::polynomial_list::{
    PolynomialList, PolynomialListMutView, PolynomialListView,
};
use aligned_vec::{avec, ABox};
use tfhe_versionable::Versionize;

/// A contiguous list containing
/// [`GGSW ciphertexts in the NTT domain`](`crate::core_crypto::entities::NttGgswCiphertext`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(NttGgswCiphertextListVersions)]
pub struct NttGgswCiphertextList<C: Container>
where
    C::Element: UnsignedInteger,
{
    data: C,
    polynomial_size: PolynomialSize,
    glwe_size: GlweSize,
    decomposition_level_count: DecompositionLevelCount,
    decomposition_base_log: DecompositionBaseLog,
    ciphertext_modulus: CiphertextModulus<C::Element>,
}

impl<T: UnsignedInteger, C: Container<Element = T>> AsRef<[T]> for NttGgswCiphertextList<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T: UnsignedInteger, C: ContainerMut<Element = T>> AsMut<[T]> for NttGgswCiphertextList<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> NttGgswCiphertextList<C> {
    /// Create an [`NttGgswCiphertextList`] from an existing container.
    ///
    /// # Note
    ///
    /// This docstring exhibits [`NttGgswCiphertextList`] primitives usage.
    ///
    /// ```rust
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for NttGgswCiphertextList creation
    /// let glwe_size = GlweSize(2);
    /// let polynomial_size = PolynomialSize(1024);
    /// let decomp_base_log = DecompositionBaseLog(8);
    /// let decomp_level_count = DecompositionLevelCount(3);
    /// let ciphertext_count = GgswCiphertextCount(2);
    /// let ciphertext_modulus = CiphertextModulus::try_new((1 << 64) - (1 << 32) + 1).unwrap();
    ///
    /// // Create a new NttGgswCiphertextList
    /// let ggsw_list = NttGgswCiphertextList::new(
    ///     0u64,
    ///     glwe_size,
    ///     polynomial_size,
    ///     decomp_base_log,
    ///     decomp_level_count,
    ///     ciphertext_count,
    ///     ciphertext_modulus,
    /// );
    ///
    /// assert_eq!(ggsw_list.glwe_size(), glwe_size);
    /// assert_eq!(ggsw_list.polynomial_size(), polynomial_size);
    /// assert_eq!(ggsw_list.decomposition_base_log(), decomp_base_log);
    /// assert_eq!(ggsw_list.decomposition_level_count(), decomp_level_count);
    /// assert_eq!(ggsw_list.ggsw_ciphertext_count(), ciphertext_count);
    /// assert_eq!(ggsw_list.ciphertext_modulus(), ciphertext_modulus);
    ///
    /// // Demonstrate how to recover the allocated container
    /// let underlying_container = ggsw_list.into_container();
    ///
    /// // Recreate a list using from_container
    /// let ggsw_list = GgswCiphertextList::from_container(
    ///     underlying_container,
    ///     glwe_size,
    ///     polynomial_size,
    ///     decomp_base_log,
    ///     decomp_level_count,
    ///     ciphertext_modulus,
    /// );
    ///
    /// assert_eq!(ggsw_list.glwe_size(), glwe_size);
    /// assert_eq!(ggsw_list.polynomial_size(), polynomial_size);
    /// assert_eq!(ggsw_list.decomposition_base_log(), decomp_base_log);
    /// assert_eq!(ggsw_list.decomposition_level_count(), decomp_level_count);
    /// assert_eq!(ggsw_list.ggsw_ciphertext_count(), ciphertext_count);
    /// assert_eq!(ggsw_list.ciphertext_modulus(), ciphertext_modulus);
    /// ```
    pub fn from_container(
        data: C,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        assert!(
            data.container_len()
                % ggsw_ciphertext_size(glwe_size, polynomial_size, decomposition_level_count)
                == 0,
            "The provided container length is not valid. \
            It needs to be dividable by the size of a GGSW ciphertext: {}. \
            Got container length: {}.",
            ggsw_ciphertext_size(glwe_size, polynomial_size, decomposition_level_count),
            data.container_len(),
        );

        Self {
            data,
            polynomial_size,
            glwe_size,
            decomposition_level_count,
            decomposition_base_log,
            ciphertext_modulus,
        }
    }

    /// Consume the entity and return its underlying container.
    ///
    /// See [`NttGgswCiphertextList::from_container`] for usage.
    pub fn into_container(self) -> C {
        self.data
    }

    /// Return the [`PolynomialSize`] of the [`NttGgswCiphertextList`].
    ///
    /// See [`NttGgswCiphertextList::from_container`] for usage.
    pub fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    /// Return the [`GgswCiphertextCount`] of the [`NttGgswCiphertextList`].
    ///
    /// See [`NttGgswCiphertextList::from_container`] for usage.
    pub fn ggsw_ciphertext_count(&self) -> GgswCiphertextCount {
        GgswCiphertextCount(
            self.data.container_len()
                / ggsw_ciphertext_size(
                    self.glwe_size,
                    self.polynomial_size,
                    self.decomposition_level_count,
                ),
        )
    }

    /// Return the [`GlweSize`] of the [`NttGgswCiphertextList`].
    ///
    /// See [`NttGgswCiphertextList::from_container`] for usage.
    pub fn glwe_size(&self) -> GlweSize {
        self.glwe_size
    }

    /// Return the [`DecompositionLevelCount`] of the [`NttGgswCiphertextList`].
    ///
    /// See [`NttGgswCiphertextList::from_container`] for usage.
    pub fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.decomposition_level_count
    }

    /// Return the [`DecompositionBaseLog`] of the [`NttGgswCiphertextList`].
    ///
    /// See [`NttGgswCiphertextList::from_container`] for usage.
    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.decomposition_base_log
    }

    /// Return the [`CiphertextModulus`] of the [`NttGgswCiphertextList`].
    ///
    /// See [`NttGgswCiphertextList::from_container`] for usage.
    pub fn ciphertext_modulus(&self) -> CiphertextModulus<Scalar> {
        self.ciphertext_modulus
    }

    /// Return a view of the [`NttGgswCiphertextList`]. This is useful if an algorithm takes a view
    /// by value.
    pub fn as_view(&self) -> NttGgswCiphertextListView<'_, Scalar> {
        NttGgswCiphertextListView {
            data: self.data.as_ref(),
            polynomial_size: self.polynomial_size,
            glwe_size: self.glwe_size,
            decomposition_level_count: self.decomposition_level_count,
            decomposition_base_log: self.decomposition_base_log,
            ciphertext_modulus: self.ciphertext_modulus,
        }
    }

    /// Interpret the [`NttGgswCiphertextList`] as a [`PolynomialList`].
    pub fn as_polynomial_list(&self) -> PolynomialListView<'_, Scalar> {
        PolynomialList::from_container(self.data.as_ref(), self.polynomial_size())
    }

    /// Return an iterator over the contiguous [`NttGgswCiphertext`]. This consumes the entity,
    /// consider calling [`NttGgswCiphertextList::as_view`] or
    /// [`NttGgswCiphertextList::as_mut_view`] first to have an iterator over borrowed contents
    /// instead of consuming the original entity.
    pub fn into_ggsw_iter(self) -> impl DoubleEndedIterator<Item = NttGgswCiphertext<C>>
    where
        C: Split,
    {
        let ggsw_ciphertext_count = self.ggsw_ciphertext_count();
        self.data
            .split_into(ggsw_ciphertext_count.0)
            .map(move |slice| {
                NttGgswCiphertext::from_container(
                    slice,
                    self.glwe_size,
                    self.polynomial_size,
                    self.decomposition_base_log,
                    self.decomposition_level_count,
                )
            })
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> NttGgswCiphertextList<C> {
    /// Mutable variant of [`NttGgswCiphertextList::as_view`].
    pub fn as_mut_view(&mut self) -> NttGgswCiphertextListMutView<'_, Scalar> {
        NttGgswCiphertextListMutView {
            data: self.data.as_mut(),
            polynomial_size: self.polynomial_size,
            glwe_size: self.glwe_size,
            decomposition_level_count: self.decomposition_level_count,
            decomposition_base_log: self.decomposition_base_log,
            ciphertext_modulus: self.ciphertext_modulus,
        }
    }

    /// Mutable variant of [`NttGgswCiphertextList::as_polynomial_list`].
    pub fn as_mut_polynomial_list(&mut self) -> PolynomialListMutView<'_, Scalar> {
        PolynomialList::from_container(self.data.as_mut(), self.polynomial_size)
    }
}

pub type NttGgswCiphertextListOwned<Scalar> = NttGgswCiphertextList<ABox<[Scalar]>>;
pub type NttGgswCiphertextListView<'data, Scalar> = NttGgswCiphertextList<&'data [Scalar]>;
pub type NttGgswCiphertextListMutView<'data, Scalar> = NttGgswCiphertextList<&'data mut [Scalar]>;

impl<Scalar: UnsignedInteger> NttGgswCiphertextListOwned<Scalar> {
    /// Allocate memory and create a new owned [`NttGgswCiphertextList`].
    ///
    /// # Note
    ///
    /// This function allocates a vector of the appropriate size and wraps it in the appropriate
    /// type. If you want to have useful data in the [`NttGgswCiphertextList`] you will first need
    /// to convert it from a standard
    /// [`GgswCiphertextList`](`crate::core_crypto::entities::GgswCiphertextList`).
    ///
    /// See [`NttGgswCiphertextList::from_container`] for usage.
    pub fn new(
        fill_with: Scalar,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        ciphertext_count: GgswCiphertextCount,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        let container_size = ggsw_ciphertext_list_size(
            ciphertext_count,
            glwe_size,
            polynomial_size,
            decomposition_level_count,
        );
        Self::from_container(
            avec![fill_with; container_size].into_boxed_slice(),
            glwe_size,
            polynomial_size,
            decomposition_base_log,
            decomposition_level_count,
            ciphertext_modulus,
        )
    }
}
