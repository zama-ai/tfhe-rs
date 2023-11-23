//! Module containing the definition of the [`LweCompactCiphertextList`] a space efficient
//! encryption of a list of LWE ciphertexts.

use crate::conformance::{ListSizeConstraint, ParameterSetConformant};
use crate::core_crypto::algorithms::{
    expand_lwe_compact_ciphertext_list, par_expand_lwe_compact_ciphertext_list,
};
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::prelude::misc::check_encrypted_content_respects_mod;

/// A [`compact list of LWE ciphertexts`](`LweCompactCiphertextList`) obtained through encryption
/// with a [`compact LWE public key`](`super::LweCompactPublicKey`).
///
/// See section 4 of the public key construction described in <https://eprint.iacr.org/2023/603> by
/// M. Joye.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LweCompactCiphertextList<C: Container>
where
    C::Element: UnsignedInteger,
{
    data: C,
    lwe_size: LweSize,
    lwe_ciphertext_count: LweCiphertextCount,
    ciphertext_modulus: CiphertextModulus<C::Element>,
}

impl<T: UnsignedInteger, C: Container<Element = T>> AsRef<[T]> for LweCompactCiphertextList<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T: UnsignedInteger, C: ContainerMut<Element = T>> AsMut<[T]> for LweCompactCiphertextList<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

pub fn lwe_compact_ciphertext_list_mask_count(
    lwe_dimension: LweDimension,
    lwe_ciphertext_count: LweCiphertextCount,
) -> LweMaskCount {
    LweMaskCount(
        lwe_ciphertext_count.0 / lwe_dimension.0
            + if lwe_ciphertext_count.0 % lwe_dimension.0 == 0 {
                0
            } else {
                1
            },
    )
}

pub fn lwe_compact_ciphertext_list_size(
    lwe_dimension: LweDimension,
    lwe_ciphertext_count: LweCiphertextCount,
) -> usize {
    // we expect one mask per "ciphertext bin" plus the bodies, so mask_count * lwe_dimension +
    // ciphertext_count
    let mask_count = lwe_compact_ciphertext_list_mask_count(lwe_dimension, lwe_ciphertext_count);
    mask_count.0 * lwe_dimension.0 + lwe_ciphertext_count.0
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> LweCompactCiphertextList<C> {
    /// Create an [`LweCompactCiphertextList`] from an existing container.
    ///
    /// # Note
    ///
    /// This function only wraps a container in the appropriate type. If you want to encrypt data
    /// you need to use
    /// [`crate::core_crypto::algorithms::encrypt_lwe_compact_ciphertext_list_with_compact_public_key`]
    /// or its parallel variant
    /// [`crate::core_crypto::algorithms::par_encrypt_lwe_compact_ciphertext_list_with_compact_public_key`] using this list as
    /// output.
    ///
    /// This docstring exhibits [`LweCompactCiphertextList`] primitives usage.
    ///
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for LweCompactCiphertextList creation
    /// let lwe_size = LweSize(1025);
    /// let lwe_ciphertext_count = LweCiphertextCount(5);
    /// let ciphertext_modulus = CiphertextModulus::new_native();
    ///
    /// // Create a new LweCiphertextList
    /// let lwe_compact_list =
    ///     LweCompactCiphertextList::new(0u64, lwe_size, lwe_ciphertext_count, ciphertext_modulus);
    ///
    /// assert_eq!(lwe_compact_list.lwe_size(), lwe_size);
    /// assert_eq!(
    ///     lwe_compact_list.lwe_ciphertext_count(),
    ///     lwe_ciphertext_count
    /// );
    /// assert_eq!(lwe_compact_list.ciphertext_modulus(), ciphertext_modulus);
    ///
    /// // Demonstrate how to recover the allocated container
    /// let underlying_container: Vec<u64> = lwe_compact_list.into_container();
    ///
    /// // Recreate a list using from_container
    /// let lwe_compact_list = LweCompactCiphertextList::from_container(
    ///     underlying_container,
    ///     lwe_size,
    ///     lwe_ciphertext_count,
    ///     ciphertext_modulus,
    /// );
    ///
    /// assert_eq!(lwe_compact_list.lwe_size(), lwe_size);
    /// assert_eq!(
    ///     lwe_compact_list.lwe_ciphertext_count(),
    ///     lwe_ciphertext_count
    /// );
    /// assert_eq!(lwe_compact_list.ciphertext_modulus(), ciphertext_modulus);
    ///
    /// let lwe_list = lwe_compact_list.expand_into_lwe_ciphertext_list();
    /// assert_eq!(lwe_list.lwe_size(), lwe_size);
    /// assert_eq!(lwe_list.lwe_ciphertext_count(), lwe_ciphertext_count);
    /// assert_eq!(lwe_list.ciphertext_modulus(), ciphertext_modulus);
    /// ```
    pub fn from_container(
        container: C,
        lwe_size: LweSize,
        lwe_ciphertext_count: LweCiphertextCount,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        let expected_container_len =
            lwe_compact_ciphertext_list_size(lwe_size.to_lwe_dimension(), lwe_ciphertext_count);
        assert!(
            container.container_len() == expected_container_len,
            "Expected container for be of length {}, got length {}",
            expected_container_len,
            container.container_len()
        );

        Self {
            data: container,
            lwe_size,
            lwe_ciphertext_count,
            ciphertext_modulus,
        }
    }

    /// Consume the entity and return its underlying container.
    ///
    /// See [`LweCompactCiphertextList::from_container`] for usage.
    pub fn into_container(self) -> C {
        self.data
    }

    /// Return the [`LweSize`] of the [`LweCompactCiphertextList`].
    ///
    /// See [`LweCompactCiphertextList::from_container`] for usage.
    pub fn lwe_size(&self) -> LweSize {
        self.lwe_size
    }

    /// Return the [`LweCiphertextCount`] of the [`LweCompactCiphertextList`].
    ///
    /// See [`LweCompactCiphertextList::from_container`] for usage.
    pub fn lwe_ciphertext_count(&self) -> LweCiphertextCount {
        self.lwe_ciphertext_count
    }

    /// Return the [`CiphertextModulus`] of the [`LweCompactCiphertextList`].
    ///
    /// See [`LweCompactCiphertextList::from_container`] for usage.
    pub fn ciphertext_modulus(&self) -> CiphertextModulus<Scalar> {
        self.ciphertext_modulus
    }

    /// Return the [`LweMaskCount`] of the [`LweCompactCiphertextList`].
    ///
    /// See [`LweCompactCiphertextList::from_container`] for usage.
    pub fn lwe_mask_count(&self) -> LweMaskCount {
        lwe_compact_ciphertext_list_mask_count(
            self.lwe_size().to_lwe_dimension(),
            self.lwe_ciphertext_count(),
        )
    }

    /// Return an immutable view to the [`LweMaskList`] of a [`LweCompactCiphertextList`].
    pub fn get_mask_list(&self) -> LweMaskListView<'_, Scalar> {
        let lwe_mask_list_size =
            lwe_mask_list_size(self.lwe_size().to_lwe_dimension(), self.lwe_mask_count());
        LweMaskList::from_container(
            &self.data.as_ref()[..lwe_mask_list_size],
            self.lwe_size().to_lwe_dimension(),
            self.ciphertext_modulus(),
        )
    }

    /// Return an immutable view to the [`LweBodyList`] of a [`LweCompactCiphertextList`].
    pub fn get_body_list(&self) -> LweBodyListView<'_, Scalar> {
        let lwe_mask_list_size =
            lwe_mask_list_size(self.lwe_size().to_lwe_dimension(), self.lwe_mask_count());
        LweBodyList::from_container(
            &self.data.as_ref()[lwe_mask_list_size..],
            self.ciphertext_modulus(),
        )
    }

    /// Return immutable views to the [`LweMaskList`] and [`LweBodyList`] of a
    /// [`LweCompactCiphertextList`].
    pub fn get_mask_and_body_list(
        &self,
    ) -> (LweMaskListView<'_, Scalar>, LweBodyListView<'_, Scalar>) {
        (self.get_mask_list(), self.get_body_list())
    }

    /// Consume the [`LweCompactCiphertextList`] and expand it into a standard
    /// [`LweCiphertextList`].
    ///
    /// See [`LweCompactCiphertextList::from_container`] for usage.
    pub fn expand_into_lwe_ciphertext_list(self) -> LweCiphertextListOwned<Scalar> {
        let mut lwe_ciphertext_list = LweCiphertextListOwned::new(
            Scalar::ZERO,
            self.lwe_size(),
            self.lwe_ciphertext_count(),
            self.ciphertext_modulus(),
        );

        expand_lwe_compact_ciphertext_list(&mut lwe_ciphertext_list, &self);
        lwe_ciphertext_list
    }

    /// Parallel variant of [`Self::expand_into_lwe_ciphertext_list`]
    pub fn par_expand_into_lwe_ciphertext_list(self) -> LweCiphertextListOwned<Scalar>
    where
        Scalar: UnsignedInteger + Send + Sync,
    {
        let mut lwe_ciphertext_list = LweCiphertextListOwned::new(
            Scalar::ZERO,
            self.lwe_size(),
            self.lwe_ciphertext_count(),
            self.ciphertext_modulus(),
        );

        par_expand_lwe_compact_ciphertext_list(&mut lwe_ciphertext_list, &self);
        lwe_ciphertext_list
    }

    pub fn size_elements(&self) -> usize {
        self.data.container_len()
    }

    pub fn size_bytes(&self) -> usize {
        std::mem::size_of_val(self.data.as_ref())
    }
}

// These accessors are used to create invalid objects and test the conformance functions
// But these functions should not be used in other contexts, hence the `#[cfg(test)]`
#[cfg(test)]
#[allow(dead_code)]
impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> LweCompactCiphertextList<C> {
    pub(crate) fn get_mut_lwe_size(&mut self) -> &mut LweSize {
        &mut self.lwe_size
    }

    pub(crate) fn get_mut_lwe_ciphertext_count(&mut self) -> &mut LweCiphertextCount {
        &mut self.lwe_ciphertext_count
    }

    pub(crate) fn get_mut_ciphertext_modulus(&mut self) -> &mut CiphertextModulus<Scalar> {
        &mut self.ciphertext_modulus
    }

    pub(crate) fn get_mut_container(&mut self) -> &mut C {
        &mut self.data
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> LweCompactCiphertextList<C> {
    /// Return a mutable view to the [`LweMaskList`] of a [`LweCompactCiphertextList`].
    pub fn get_mut_mask_list(&mut self) -> LweMaskListMutView<'_, Scalar> {
        let lwe_dimension = self.lwe_size().to_lwe_dimension();
        let lwe_mask_count = self.lwe_mask_count();
        let ciphertext_modulus = self.ciphertext_modulus();
        let lwe_mask_list_size = lwe_mask_list_size(lwe_dimension, lwe_mask_count);
        LweMaskList::from_container(
            &mut self.data.as_mut()[..lwe_mask_list_size],
            lwe_dimension,
            ciphertext_modulus,
        )
    }

    /// Return a mutable view to the [`LweBodyList`] of a [`LweCompactCiphertextList`].
    pub fn get_mut_body_list(&mut self) -> LweBodyListMutView<'_, Scalar> {
        let lwe_dimension = self.lwe_size().to_lwe_dimension();
        let lwe_mask_count = self.lwe_mask_count();
        let ciphertext_modulus = self.ciphertext_modulus();
        let lwe_mask_list_size = lwe_mask_list_size(lwe_dimension, lwe_mask_count);
        LweBodyList::from_container(
            &mut self.data.as_mut()[lwe_mask_list_size..],
            ciphertext_modulus,
        )
    }

    /// Return mutable views to the [`LweMaskList`] and [`LweBodyList`] of a
    /// [`LweCompactCiphertextList`].
    pub fn get_mut_mask_and_body_list(
        &mut self,
    ) -> (
        LweMaskListMutView<'_, Scalar>,
        LweBodyListMutView<'_, Scalar>,
    ) {
        let lwe_dimension = self.lwe_size().to_lwe_dimension();
        let lwe_mask_count = self.lwe_mask_count();
        let ciphertext_modulus = self.ciphertext_modulus();
        let lwe_mask_list_size = lwe_mask_list_size(lwe_dimension, lwe_mask_count);

        let (mask_slice, body_slice) = self.as_mut().split_at_mut(lwe_mask_list_size);

        (
            LweMaskList::from_container(mask_slice, lwe_dimension, ciphertext_modulus),
            LweBodyList::from_container(body_slice, ciphertext_modulus),
        )
    }
}

pub type LweCompactCiphertextListOwned<Scalar> = LweCompactCiphertextList<Vec<Scalar>>;
pub type LweCompactCiphertextListView<'data, Scalar> = LweCompactCiphertextList<&'data [Scalar]>;
pub type LweCompactCiphertextListMutView<'data, Scalar> =
    LweCompactCiphertextList<&'data mut [Scalar]>;

/// Structure to store the expected properties of a ciphertext
/// Can be used on a server to check if client inputs are well formed
/// before running a computation on them
pub struct LweCiphertextListParameters<T: UnsignedInteger> {
    pub lwe_dim: LweDimension,
    pub lwe_ciphertext_count_constraint: ListSizeConstraint,
    pub ct_modulus: CiphertextModulus<T>,
}

impl<T: UnsignedInteger> ParameterSetConformant for LweCompactCiphertextListOwned<T> {
    type ParameterSet = LweCiphertextListParameters<T>;

    fn is_conformant(&self, param: &LweCiphertextListParameters<T>) -> bool {
        param
            .lwe_ciphertext_count_constraint
            .is_valid(self.lwe_ciphertext_count.0)
            && self.data.len()
                == lwe_compact_ciphertext_list_size(
                    self.lwe_size.to_lwe_dimension(),
                    self.lwe_ciphertext_count,
                )
            && check_encrypted_content_respects_mod(self, param.ct_modulus)
            && self.lwe_size == param.lwe_dim.to_lwe_size()
            && self.ciphertext_modulus == param.ct_modulus
    }
}

impl<Scalar: UnsignedInteger> LweCompactCiphertextListOwned<Scalar> {
    /// Allocate memory and create a new owned [`LweCompactCiphertextListOwned`].
    ///
    /// # Note
    ///
    /// This function allocates a vector of the appropriate size and wraps it in the appropriate
    /// type. If you want to encrypt data you need to use
    /// [`crate::core_crypto::algorithms::encrypt_lwe_compact_ciphertext_list_with_compact_public_key`]
    /// or its parallel variant
    /// [`crate::core_crypto::algorithms::par_encrypt_lwe_compact_ciphertext_list_with_compact_public_key`]
    /// using this list as output.
    ///
    /// See [`LweCompactCiphertextListOwned::from_container`] for usage.
    pub fn new(
        fill_with: Scalar,
        lwe_size: LweSize,
        lwe_ciphertext_count: LweCiphertextCount,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        Self::from_container(
            vec![
                fill_with;
                lwe_compact_ciphertext_list_size(lwe_size.to_lwe_dimension(), lwe_ciphertext_count)
            ],
            lwe_size,
            lwe_ciphertext_count,
            ciphertext_modulus,
        )
    }
}
