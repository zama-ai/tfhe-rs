//! Module containing the definition of the CmGlweCiphertext.

use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// Return the number of elements in a [`CmGlweCiphertext`] given a [`GlweDimension`] and
/// [`PolynomialSize`].
pub fn cm_glwe_ciphertext_size(
    glwe_dimension: GlweDimension,
    cm_dimension: CmDimension,
    polynomial_size: PolynomialSize,
) -> usize {
    (glwe_dimension.0 + cm_dimension.0) * polynomial_size.0
}

/// Return the number of elements in a [`GlweMask`] given a [`GlweDimension`] and
/// [`PolynomialSize`].
pub fn cm_glwe_ciphertext_mask_size(
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
) -> usize {
    glwe_dimension
        .to_equivalent_lwe_dimension(polynomial_size)
        .0
}

/// Return the number of mask samples used during encryption of a [`CmGlweCiphertext`] given a
/// [`GlweDimension`] and [`PolynomialSize`].
pub fn cm_glwe_ciphertext_encryption_mask_sample_count(
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
) -> EncryptionMaskSampleCount {
    EncryptionMaskSampleCount(cm_glwe_ciphertext_mask_size(
        glwe_dimension,
        polynomial_size,
    ))
}

/// Return the number of noise samples required to encrypt a [`CmGlweCiphertext`] given a
/// [`PolynomialSize`].
pub fn cm_glwe_ciphertext_encryption_noise_sample_count(
    cm_dimension: CmDimension,
    polynomial_size: PolynomialSize,
) -> EncryptionNoiseSampleCount {
    EncryptionNoiseSampleCount(cm_dimension.0 * polynomial_size.0)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
// Versionize
// #[versionize(CmGlweCiphertextVersions)]
pub struct CmGlweCiphertext<C: Container>
where
    C::Element: UnsignedInteger,
{
    data: C,
    glwe_dimension: GlweDimension,
    cm_dimension: CmDimension,
    polynomial_size: PolynomialSize,
    ciphertext_modulus: CiphertextModulus<C::Element>,
}

impl<T: UnsignedInteger, C: Container<Element = T>> AsRef<[T]> for CmGlweCiphertext<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T: UnsignedInteger, C: ContainerMut<Element = T>> AsMut<[T]> for CmGlweCiphertext<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> CmGlweCiphertext<C> {
    /// Create a [`CmGlweCiphertext`] from an existing container.
    ///
    /// # Note
    ///
    /// This function only wraps a container in the appropriate type. If you want to encrypt data
    /// you need to use [`crate::core_crypto::algorithms::encrypt_glwe_ciphertext`] using this
    /// ciphertext as output.
    ///
    /// This docstring exhibits [`CmGlweCiphertext`] primitives usage.
    ///
    /// ```rust
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for CmGlweCiphertext creation
    /// let glwe_dimension = GlweDimension(2);
    /// let cm_dimension = CmDimension(2);
    /// let polynomial_size = PolynomialSize(1024);
    /// let ciphertext_modulus = CiphertextModulus::new_native();
    ///
    /// // Create a new CmGlweCiphertext
    /// let mut glwe = CmGlweCiphertext::new(
    ///     0u64,
    ///     glwe_dimension,
    ///     cm_dimension,
    ///     polynomial_size,
    ///     ciphertext_modulus,
    /// );
    ///
    /// assert_eq!(glwe.glwe_dimension(), glwe_dimension);
    /// assert_eq!(glwe.cm_dimension(), cm_dimension);
    /// assert_eq!(glwe.polynomial_size(), polynomial_size);
    /// assert_eq!(glwe.ciphertext_modulus(), ciphertext_modulus);
    /// assert_eq!(glwe.get_bodies().polynomial_size(), polynomial_size);
    /// assert_eq!(glwe.get_mut_bodies().polynomial_size(), polynomial_size);
    /// assert_eq!(glwe.get_bodies().ciphertext_modulus(), ciphertext_modulus);
    /// assert_eq!(
    ///     glwe.get_mut_bodies().ciphertext_modulus(),
    ///     ciphertext_modulus
    /// );
    /// assert_eq!(glwe.get_mask().glwe_dimension(), glwe_dimension);
    /// assert_eq!(glwe.get_mut_mask().glwe_dimension(), glwe_dimension);
    /// assert_eq!(glwe.get_mask().polynomial_size(), polynomial_size);
    /// assert_eq!(glwe.get_mut_mask().polynomial_size(), polynomial_size);
    /// assert_eq!(glwe.get_mask().ciphertext_modulus(), ciphertext_modulus);
    /// assert_eq!(glwe.get_mut_mask().ciphertext_modulus(), ciphertext_modulus);
    ///
    /// // Demonstrate how to recover the allocated container
    /// let underlying_container: Vec<u64> = glwe.into_container();
    ///
    /// // Recreate a ciphertext using from_container
    /// let mut glwe = CmGlweCiphertext::from_container(
    ///     underlying_container,
    ///     glwe_dimension,
    ///     cm_dimension,
    ///     polynomial_size,
    ///     ciphertext_modulus,
    /// );
    ///
    /// assert_eq!(glwe.glwe_dimension(), glwe_dimension);
    /// assert_eq!(glwe.cm_dimension(), cm_dimension);
    /// assert_eq!(glwe.polynomial_size(), polynomial_size);
    /// assert_eq!(glwe.ciphertext_modulus(), ciphertext_modulus);
    /// assert_eq!(glwe.get_bodies().polynomial_size(), polynomial_size);
    /// assert_eq!(glwe.get_mut_bodies().polynomial_size(), polynomial_size);
    /// assert_eq!(glwe.get_bodies().ciphertext_modulus(), ciphertext_modulus);
    /// assert_eq!(
    ///     glwe.get_mut_bodies().ciphertext_modulus(),
    ///     ciphertext_modulus
    /// );
    /// assert_eq!(glwe.get_mask().glwe_dimension(), glwe_dimension);
    /// assert_eq!(glwe.get_mut_mask().glwe_dimension(), glwe_dimension);
    /// assert_eq!(glwe.get_mask().polynomial_size(), polynomial_size);
    /// assert_eq!(glwe.get_mut_mask().polynomial_size(), polynomial_size);
    /// assert_eq!(glwe.get_mask().ciphertext_modulus(), ciphertext_modulus);
    /// assert_eq!(glwe.get_mut_mask().ciphertext_modulus(), ciphertext_modulus);
    /// ```
    pub fn from_container(
        container: C,
        glwe_dimension: GlweDimension,
        cm_dimension: CmDimension,
        polynomial_size: PolynomialSize,
        ciphertext_modulus: CiphertextModulus<C::Element>,
    ) -> Self {
        assert_eq!(
            container.container_len(),
            (glwe_dimension.0 + cm_dimension.0) * polynomial_size.0
        );

        Self {
            data: container,
            glwe_dimension,
            cm_dimension,
            polynomial_size,
            ciphertext_modulus,
        }
    }

    /// Return the [`GlweDimension`] of the [`CmGlweCiphertext`].
    ///
    /// See [`CmGlweCiphertext::from_container`] for usage.
    pub fn glwe_dimension(&self) -> GlweDimension {
        self.glwe_dimension
    }

    pub fn cm_dimension(&self) -> CmDimension {
        self.cm_dimension
    }

    /// Return the [`PolynomialSize`] of the [`CmGlweCiphertext`].
    ///
    /// See [`CmGlweCiphertext::from_container`] for usage.
    pub fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    /// Return the [`CiphertextModulus`] of the [`CmGlweCiphertext`].
    ///
    /// See [`CmGlweCiphertext::from_container`] for usage.
    pub fn ciphertext_modulus(&self) -> CiphertextModulus<C::Element> {
        self.ciphertext_modulus
    }

    /// Return immutable views to the [`GlweMask`] and [`GlweBody`] of a [`CmGlweCiphertext`].
    pub fn get_mask_and_bodies(&self) -> (GlweMask<&[Scalar]>, GlweBodyList<&[Scalar]>) {
        let (mask, bodies) = self.data.as_ref().split_at(cm_glwe_ciphertext_mask_size(
            self.glwe_dimension(),
            self.polynomial_size,
        ));

        (
            GlweMask::from_container(mask, self.polynomial_size, self.ciphertext_modulus),
            GlweBodyList::from_container(bodies, self.polynomial_size, self.ciphertext_modulus),
        )
    }

    /// Return an immutable view to the [`GlweBody`] of a [`CmGlweCiphertext`].
    ///
    /// See [`CmGlweCiphertext::from_container`] for usage.
    pub fn get_bodies(&self) -> GlweBodyList<&[Scalar]> {
        let bodies = &self.data.as_ref()
            [cm_glwe_ciphertext_mask_size(self.glwe_dimension(), self.polynomial_size)..];

        GlweBodyList::from_container(bodies, self.polynomial_size, self.ciphertext_modulus)
    }

    /// Return an immutable view to the [`GlweMask`] of a [`CmGlweCiphertext`].
    ///
    /// See [`CmGlweCiphertext::from_container`] for usage.
    pub fn get_mask(&self) -> GlweMask<&[Scalar]> {
        GlweMask::from_container(
            &self.as_ref()
                [0..cm_glwe_ciphertext_mask_size(self.glwe_dimension(), self.polynomial_size)],
            self.polynomial_size,
            self.ciphertext_modulus,
        )
    }

    /// Interpret the [`CmGlweCiphertext`] as a [`PolynomialList`].
    pub fn as_polynomial_list(&self) -> PolynomialList<&'_ [Scalar]> {
        PolynomialList::from_container(self.as_ref(), self.polynomial_size)
    }

    /// Return a view of the [`CmGlweCiphertext`]. This is useful if an algorithm takes a view by
    /// value.
    pub fn as_view(&self) -> CmGlweCiphertext<&'_ [Scalar]> {
        CmGlweCiphertext {
            data: self.data.as_ref(),
            glwe_dimension: self.glwe_dimension,
            polynomial_size: self.polynomial_size,
            cm_dimension: self.cm_dimension,
            ciphertext_modulus: self.ciphertext_modulus,
        }
    }

    /// Consume the entity and return its underlying container.
    ///
    /// See [`CmGlweCiphertext::from_container`] for usage.
    pub fn into_container(self) -> C {
        self.data
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> CmGlweCiphertext<C> {
    pub fn get_mut_mask_and_bodies(
        &mut self,
    ) -> (GlweMask<&mut [Scalar]>, GlweBodyList<&mut [Scalar]>) {
        let glwe_dimension = self.glwe_dimension();
        let polynomial_size = self.polynomial_size();
        let ciphertext_modulus = self.ciphertext_modulus();

        let (mask, bodies) = self
            .data
            .as_mut()
            .split_at_mut(cm_glwe_ciphertext_mask_size(
                glwe_dimension,
                polynomial_size,
            ));

        (
            GlweMask::from_container(mask, polynomial_size, ciphertext_modulus),
            GlweBodyList::from_container(bodies, polynomial_size, ciphertext_modulus),
        )
    }

    /// See [`CmGlweCiphertext::from_container`] for usage.
    pub fn get_mut_bodies(&mut self) -> GlweBodyList<&mut [Scalar]> {
        let glwe_dimension = self.glwe_dimension();
        let polynomial_size = self.polynomial_size();
        let ciphertext_modulus = self.ciphertext_modulus();

        let bodies = &mut self.data.as_mut()
            [cm_glwe_ciphertext_mask_size(glwe_dimension, polynomial_size)..];

        GlweBodyList::from_container(bodies, polynomial_size, ciphertext_modulus)
    }

    /// Mutable variant of [`CmGlweCiphertext::get_mask`].
    ///
    /// See [`CmGlweCiphertext::from_container`] for usage.
    pub fn get_mut_mask(&mut self) -> GlweMask<&mut [Scalar]> {
        let polynomial_size = self.polynomial_size();
        let glwe_dimension = self.glwe_dimension();
        let ciphertext_modulus = self.ciphertext_modulus();

        GlweMask::from_container(
            &mut self.as_mut()[0..cm_glwe_ciphertext_mask_size(glwe_dimension, polynomial_size)],
            polynomial_size,
            ciphertext_modulus,
        )
    }

    /// Mutable variant of [`CmGlweCiphertext::as_polynomial_list`].
    pub fn as_mut_polynomial_list(&mut self) -> PolynomialList<&'_ mut [Scalar]> {
        let polynomial_size = self.polynomial_size;
        PolynomialList::from_container(self.as_mut(), polynomial_size)
    }

    /// Mutable variant of [`CmGlweCiphertext::as_view`].
    pub fn as_mut_view(&mut self) -> CmGlweCiphertext<&'_ mut [Scalar]> {
        CmGlweCiphertext {
            data: self.data.as_mut(),
            glwe_dimension: self.glwe_dimension,
            cm_dimension: self.cm_dimension,
            polynomial_size: self.polynomial_size,
            ciphertext_modulus: self.ciphertext_modulus,
        }
    }
}

/// A [`CmGlweCiphertext`] owning the memory for its own storage.
pub type CmGlweCiphertextOwned<Scalar> = CmGlweCiphertext<Vec<Scalar>>;
/// A [`CmGlweCiphertext`] immutably borrowing memory for its own storage.
pub type CmGlweCiphertextView<'data, Scalar> = CmGlweCiphertext<&'data [Scalar]>;
/// A [`CmGlweCiphertext`] mutably borrowing memory for its own storage.
pub type CmGlweCiphertextMutView<'data, Scalar> = CmGlweCiphertext<&'data mut [Scalar]>;

impl<Scalar: UnsignedInteger> CmGlweCiphertextOwned<Scalar> {
    /// Allocate memory and create a new owned [`CmGlweCiphertext`].
    ///
    /// # Note
    ///
    /// This function allocates a vector of the appropriate size and wraps it in the appropriate
    /// type. If you want to encrypt data you need to use
    /// [`crate::core_crypto::algorithms::encrypt_glwe_ciphertext`] using this ciphertext as
    /// output.
    ///
    ///
    /// See [`CmGlweCiphertext::from_container`] for usage.
    pub fn new(
        fill_with: Scalar,
        glwe_dimension: GlweDimension,
        cm_dimension: CmDimension,
        polynomial_size: PolynomialSize,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        Self::from_container(
            vec![fill_with; cm_glwe_ciphertext_size(glwe_dimension, cm_dimension, polynomial_size)],
            glwe_dimension,
            cm_dimension,
            polynomial_size,
            ciphertext_modulus,
        )
    }
}

/// Metadata used in the [`CreateFrom`] implementation to create [`CmGlweCiphertext`] entities.
#[derive(Clone, Copy)]
pub struct CmGlweCiphertextCreationMetadata<Scalar: UnsignedInteger> {
    pub glwe_dimension: GlweDimension,
    pub cm_dimension: CmDimension,
    pub polynomial_size: PolynomialSize,
    pub ciphertext_modulus: CiphertextModulus<Scalar>,
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> CreateFrom<C>
    for CmGlweCiphertext<C>
{
    type Metadata = CmGlweCiphertextCreationMetadata<Scalar>;

    #[inline]
    fn create_from(from: C, meta: Self::Metadata) -> Self {
        let CmGlweCiphertextCreationMetadata {
            glwe_dimension,
            cm_dimension,
            polynomial_size,
            ciphertext_modulus,
        } = meta;
        Self::from_container(
            from,
            glwe_dimension,
            cm_dimension,
            polynomial_size,
            ciphertext_modulus,
        )
    }
}
