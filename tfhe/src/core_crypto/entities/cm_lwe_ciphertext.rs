//! Module containing the definition of the [`CmLweCiphertext`].

use crate::conformance::ParameterSetConformant;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::prelude::misc::check_encrypted_content_respects_mod;

use super::lwe_ciphertext::{LweBodyList, LweCiphertext, LweCiphertextOwned, LweMask};

/// A [`CRS LWE ciphertext`](`CmLweCiphertext`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CmLweCiphertext<C: Container>
where
    C::Element: UnsignedInteger,
{
    data: C,
    lwe_dimension: LweDimension,
    ciphertext_modulus: CiphertextModulus<C::Element>,
}

impl<T: UnsignedInteger, C: Container<Element = T>> AsRef<[T]> for CmLweCiphertext<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T: UnsignedInteger, C: ContainerMut<Element = T>> AsMut<[T]> for CmLweCiphertext<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

// This accessor is used to create invalid objects and test the conformance functions
// But these functions should not be used in other contexts, hence the `#[cfg(test)]`
#[cfg(test)]
#[allow(dead_code)]
impl<C: Container> CmLweCiphertext<C>
where
    C::Element: UnsignedInteger,
{
    pub(crate) fn get_mut_ciphertext_modulus(&mut self) -> &mut CiphertextModulus<C::Element> {
        &mut self.ciphertext_modulus
    }
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> CmLweCiphertext<C> {
    /// Create an [`CmLweCiphertext`] from an existing container.
    ///
    /// # Note
    ///
    /// This function only wraps a container in the appropriate type. If you want to encrypt data
    /// you need to use [`crate::core_crypto::algorithms::encrypt_lwe_ciphertext`] using this
    /// ciphertext as output.
    ///
    /// This docstring exhibits [`CmLweCiphertext`] primitives usage.
    ///
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for CmLweCiphertext creation
    /// let lwe_dimension = LweDimension(600);
    /// let cm_dimension = CmDimension(2);
    /// let ciphertext_modulus = CiphertextModulus::new_native();
    ///
    /// // Create a new CmLweCiphertext
    /// let mut lwe = CmLweCiphertext::new(0u64, lwe_dimension, cm_dimension, ciphertext_modulus);
    ///
    /// assert_eq!(lwe.lwe_dimension(), lwe_dimension);
    /// assert_eq!(lwe.get_mask().lwe_dimension(), lwe_dimension);
    /// assert_eq!(lwe.get_mut_mask().lwe_dimension(), lwe_dimension);
    /// assert_eq!(lwe.cm_dimension(), cm_dimension);
    /// assert_eq!(lwe.ciphertext_modulus(), ciphertext_modulus);
    ///
    /// // Demonstrate how to recover the allocated container
    /// let underlying_container: Vec<u64> = lwe.into_container();
    ///
    /// // Recreate a ciphertext using from_container
    /// let mut lwe =
    ///     CmLweCiphertext::from_container(underlying_container, lwe_dimension, ciphertext_modulus);
    ///
    /// assert_eq!(lwe.lwe_dimension(), lwe_dimension);
    /// assert_eq!(lwe.get_mask().lwe_dimension(), lwe_dimension);
    /// assert_eq!(lwe.get_mut_mask().lwe_dimension(), lwe_dimension);
    /// assert_eq!(lwe.cm_dimension(), cm_dimension);
    /// assert_eq!(lwe.ciphertext_modulus(), ciphertext_modulus);
    /// ```
    pub fn from_container(
        container: C,
        lwe_dimension: LweDimension,
        ciphertext_modulus: CiphertextModulus<C::Element>,
    ) -> Self {
        assert!(
            container.container_len() > 0,
            "Got an empty container to create an CmLweCiphertext"
        );
        Self {
            data: container,
            ciphertext_modulus,
            lwe_dimension,
        }
    }

    /// Return the [`LweDimension`] of the [`CmLweCiphertext`].
    ///
    /// See [`CmLweCiphertext::from_container`] for usage.
    pub fn lwe_dimension(&self) -> LweDimension {
        self.lwe_dimension
    }

    /// Return the [`CmDimension`] of the [`CmLweCiphertext`].
    ///
    /// See [`CmLweCiphertext::from_container`] for usage.
    pub fn cm_dimension(&self) -> CmDimension {
        CmDimension(self.data.container_len() - self.lwe_dimension.0)
    }

    /// Return immutable views to the [`LweMask`] and [`LweBodyList`] of an [`CmLweCiphertext`].
    pub fn get_mask_and_bodies(&self) -> (LweMask<&[Scalar]>, LweBodyList<&[Scalar]>) {
        let (mask, bodies) = self.data.as_ref().split_at(self.lwe_dimension.0);

        let ciphertext_modulus = self.ciphertext_modulus();
        (
            LweMask::from_container(mask, ciphertext_modulus),
            LweBodyList::from_container(bodies, ciphertext_modulus),
        )
    }

    /// Return an immutable view to the [`LweBodyList`] of an [`CmLweCiphertext`].
    pub fn get_bodies(&self) -> LweBodyList<&[Scalar]> {
        self.get_mask_and_bodies().1
    }

    /// Return an immutable view to the [`LweMask`] of an [`CmLweCiphertext`].
    ///
    /// See [`CmLweCiphertext::from_container`] for usage.
    pub fn get_mask(&self) -> LweMask<&[Scalar]> {
        self.get_mask_and_bodies().0
    }

    /// Return a view of the [`CmLweCiphertext`]. This is useful if an algorithm takes a view by
    /// value.
    pub fn as_view(&self) -> CmLweCiphertextView<'_, Scalar> {
        CmLweCiphertextView::from_container(
            self.as_ref(),
            self.lwe_dimension,
            self.ciphertext_modulus(),
        )
    }

    /// Consume the entity and return its underlying container.
    ///
    /// See [`CmLweCiphertext::from_container`] for usage.
    pub fn into_container(self) -> C {
        self.data
    }

    /// Return the [`CiphertextModulus`] of the [`CmLweCiphertext`].
    ///
    /// See [`CmLweCiphertext::from_container`] for usage.
    pub fn ciphertext_modulus(&self) -> CiphertextModulus<C::Element> {
        self.ciphertext_modulus
    }

    pub fn extract_lwe_ciphertext(&self, index: usize) -> LweCiphertextOwned<Scalar> {
        let mut extracted_lwe = self.get_mask().data().to_vec();

        extracted_lwe.push(self.get_bodies().data()[index]);

        LweCiphertext::from_container(extracted_lwe, self.ciphertext_modulus)
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> CmLweCiphertext<C> {
    /// Mutable variant of [`CmLweCiphertext::get_mut_mask_and_bodies`].
    pub fn get_mut_mask_and_bodies(
        &mut self,
    ) -> (LweMask<&mut [Scalar]>, LweBodyList<&mut [Scalar]>) {
        let ciphertext_modulus = self.ciphertext_modulus();
        let (mask, bodies) = self.data.as_mut().split_at(self.lwe_dimension.0);

        (
            LweMask::from_container(mask, ciphertext_modulus),
            LweBodyList::from_container(bodies, ciphertext_modulus),
        )
    }

    /// Mutable variant of [`CmLweCiphertext::get_mut_bodies`].
    pub fn get_mut_bodies(&mut self) -> LweBodyList<&mut [Scalar]> {
        self.get_mut_mask_and_bodies().1
    }

    /// Mutable variant of [`CmLweCiphertext::get_mask`].
    ///
    /// See [`CmLweCiphertext::from_container`] for usage.
    pub fn get_mut_mask(&mut self) -> LweMask<&mut [Scalar]> {
        self.get_mut_mask_and_bodies().0
    }

    /// Mutable variant of [`CmLweCiphertext::as_view`].
    pub fn as_mut_view(&mut self) -> CmLweCiphertextMutView<'_, Scalar> {
        let ciphertext_modulus = self.ciphertext_modulus();
        let lwe_dimension = self.lwe_dimension;

        CmLweCiphertextMutView::from_container(self.as_mut(), lwe_dimension, ciphertext_modulus)
    }
}

/// An [`CmLweCiphertext`] owning the memory for its own storage.
pub type CmLweCiphertextOwned<Scalar> = CmLweCiphertext<Vec<Scalar>>;
/// An [`CmLweCiphertext`] immutably borrowing memory for its own storage.
pub type CmLweCiphertextView<'data, Scalar> = CmLweCiphertext<&'data [Scalar]>;
/// An [`CmLweCiphertext`] mutably borrowing memory for its own storage.
pub type CmLweCiphertextMutView<'data, Scalar> = CmLweCiphertext<&'data mut [Scalar]>;

/// Structure to store the expected properties of a ciphertext
/// Can be used on a server to check if client inputs are well formed
/// before running a computation on them
#[derive(Copy, Clone)]
pub struct CmLweCiphertextParameters<T: UnsignedInteger> {
    pub lwe_dim: LweDimension,
    pub ct_modulus: CiphertextModulus<T>,
}

impl<C: Container> ParameterSetConformant for CmLweCiphertext<C>
where
    C::Element: UnsignedInteger,
{
    type ParameterSet = CmLweCiphertextParameters<C::Element>;

    fn is_conformant(&self, lwe_ct_parameters: &CmLweCiphertextParameters<C::Element>) -> bool {
        check_encrypted_content_respects_mod(self, lwe_ct_parameters.ct_modulus)
            && self.lwe_dimension() == lwe_ct_parameters.lwe_dim
            && self.ciphertext_modulus() == lwe_ct_parameters.ct_modulus
    }
}

impl<Scalar: UnsignedInteger> CmLweCiphertextOwned<Scalar> {
    /// Allocate memory and create a new owned [`CmLweCiphertext`].
    ///
    /// # Note
    ///
    /// This function allocates a vector of the appropriate size and wraps it in the appropriate
    /// type. If you want to encrypt data you need to use
    /// [`crate::core_crypto::algorithms::encrypt_lwe_ciphertext`] using this ciphertext as
    /// output.
    ///
    /// See [`CmLweCiphertext::from_container`] for usage.
    pub fn new(
        fill_with: Scalar,
        lwe_dimension: LweDimension,
        cm_dimension: CmDimension,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        Self::from_container(
            vec![fill_with; lwe_dimension.0 + cm_dimension.0],
            lwe_dimension,
            ciphertext_modulus,
        )
    }
}

/// Metadata used in the [`CreateFrom`] implementation to create [`CmLweCiphertext`] entities.
#[derive(Clone, Copy)]
pub struct CmLweCiphertextCreationMetadata<Scalar: UnsignedInteger> {
    pub lwe_dimension: LweDimension,
    pub ciphertext_modulus: CiphertextModulus<Scalar>,
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> CreateFrom<C> for CmLweCiphertext<C> {
    type Metadata = CmLweCiphertextCreationMetadata<C::Element>;

    #[inline]
    fn create_from(from: C, meta: Self::Metadata) -> Self {
        let CmLweCiphertextCreationMetadata {
            lwe_dimension,
            ciphertext_modulus,
        } = meta;
        Self::from_container(from, lwe_dimension, ciphertext_modulus)
    }
}
