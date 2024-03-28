//! Module containing the definition of the PseudoGgswCiphertext.

use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// A [`PseudoGgswCiphertext`] is similar to a [`GgswCiphertext`], the main difference resides in
/// the fact that the level matrix is not square, having one less column of [`GlweCiphertext`].
/// During an external product with a [`GlweCiphertext`] only its mask is used for polynomial
/// multiplications, in contrast with an external product with a [`GgswCiphertext`] where the body
/// of the [`GlweCiphertext`] is multiplied as well.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PseudoGgswCiphertext<C: Container>
where
    C::Element: UnsignedInteger,
{
    data: C,
    glwe_size_in: GlweSize,
    glwe_size_out: GlweSize,
    polynomial_size: PolynomialSize,
    decomp_base_log: DecompositionBaseLog,
    ciphertext_modulus: CiphertextModulus<C::Element>,
}

impl<T: UnsignedInteger, C: Container<Element = T>> AsRef<[T]> for PseudoGgswCiphertext<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T: UnsignedInteger, C: ContainerMut<Element = T>> AsMut<[T]> for PseudoGgswCiphertext<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

/// Return the number of elements in a [`PseudoGgswCiphertext`] given a [`GlweSize`],
/// [`PolynomialSize`] and [`DecompositionLevelCount`].
pub fn pseudo_ggsw_ciphertext_size(
    glwe_size_in: GlweSize,
    glwe_size_out: GlweSize,
    polynomial_size: PolynomialSize,
    decomp_level_count: DecompositionLevelCount,
) -> usize {
    decomp_level_count.0
        * pseudo_ggsw_level_matrix_size(glwe_size_in, glwe_size_out, polynomial_size)
}

/// Return the number of elements in a [`GgswLevelMatrix`] given a [`GlweSize`] and
/// [`PolynomialSize`].
pub fn pseudo_ggsw_level_matrix_size(
    glwe_size_in: GlweSize,
    glwe_size_out: GlweSize,
    polynomial_size: PolynomialSize,
) -> usize {
    glwe_size_in.to_glwe_dimension().0 * glwe_size_out.0 * polynomial_size.0
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> PseudoGgswCiphertext<C> {
    /// Create a [`PseudoGgswCiphertext`] from an existing container.
    ///
    /// # Note
    ///
    /// This function only wraps a container in the appropriate type. If you want to encrypt data
    /// you need to use [`crate::core_crypto::algorithms::encrypt_constant_ggsw_ciphertext`] or its
    /// parallel counterpart
    /// [`crate::core_crypto::algorithms::par_encrypt_constant_ggsw_ciphertext`] using
    /// this ciphertext as output.
    ///
    /// This docstring exhibits [`PseudoGgswCiphertext`] primitives usage.
    ///
    /// ```
    /// use tfhe::core_crypto::experimental::prelude::*;
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for PseudoGgswCiphertext creation
    /// let glwe_size_in = GlweSize(2);
    /// let glwe_size_out = GlweSize(3);
    /// let polynomial_size = PolynomialSize(1024);
    /// let decomp_base_log = DecompositionBaseLog(8);
    /// let decomp_level_count = DecompositionLevelCount(3);
    /// let ciphertext_modulus = CiphertextModulus::new_native();
    ///
    /// // Create a new PseudoGgswCiphertext
    /// let ggsw = PseudoGgswCiphertext::new(
    ///     0u64,
    ///     glwe_size_in,
    ///     glwe_size_out,
    ///     polynomial_size,
    ///     decomp_base_log,
    ///     decomp_level_count,
    ///     ciphertext_modulus,
    /// );
    ///
    /// assert_eq!(ggsw.glwe_size_in(), glwe_size_in);
    /// assert_eq!(ggsw.glwe_size_out(), glwe_size_out);
    /// assert_eq!(ggsw.polynomial_size(), polynomial_size);
    /// assert_eq!(ggsw.decomposition_base_log(), decomp_base_log);
    /// assert_eq!(ggsw.decomposition_level_count(), decomp_level_count);
    /// assert_eq!(ggsw.ciphertext_modulus(), ciphertext_modulus);
    /// assert_eq!(
    ///     ggsw.pseudo_ggsw_level_matrix_size(),
    ///     pseudo_ggsw_level_matrix_size(glwe_size_in, glwe_size_out, polynomial_size)
    /// );
    ///
    /// // Demonstrate how to recover the allocated container
    /// let underlying_container: Vec<u64> = ggsw.into_container();
    ///
    /// // Recreate a ciphertext using from_container
    /// let ggsw = PseudoGgswCiphertext::from_container(
    ///     underlying_container,
    ///     glwe_size_in,
    ///     glwe_size_out,
    ///     polynomial_size,
    ///     decomp_base_log,
    ///     ciphertext_modulus,
    /// );
    ///
    /// assert_eq!(ggsw.glwe_size_in(), glwe_size_in);
    /// assert_eq!(ggsw.glwe_size_out(), glwe_size_out);
    /// assert_eq!(ggsw.polynomial_size(), polynomial_size);
    /// assert_eq!(ggsw.decomposition_base_log(), decomp_base_log);
    /// assert_eq!(ggsw.decomposition_level_count(), decomp_level_count);
    /// assert_eq!(ggsw.ciphertext_modulus(), ciphertext_modulus);
    /// assert_eq!(
    ///     ggsw.pseudo_ggsw_level_matrix_size(),
    ///     pseudo_ggsw_level_matrix_size(glwe_size_in, glwe_size_out, polynomial_size)
    /// );
    /// ```
    pub fn from_container(
        container: C,
        glwe_size_in: GlweSize,
        glwe_size_out: GlweSize,
        polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
        ciphertext_modulus: CiphertextModulus<C::Element>,
    ) -> Self {
        assert!(
            container.container_len() > 0,
            "Got an empty container to create a PseudoGgswCiphertext"
        );
        assert!(
            container.container_len()
                % (glwe_size_in.to_glwe_dimension().0 * glwe_size_out.0 * polynomial_size.0)
                == 0,
            "The provided container length is not valid. \
        It needs to be dividable by glwe_dimension_in * glwe_size_out * polynomial_size: {}. \
        Got container length: {} and glwe_dimension_in: {:?}, glwe_size_out: \
        {glwe_size_out:?}\
        polynomial_size: {polynomial_size:?}.",
            glwe_size_in.0 * glwe_size_out.0 * polynomial_size.0,
            container.container_len(),
            glwe_size_in.to_glwe_dimension()
        );

        Self {
            data: container,
            glwe_size_in,
            glwe_size_out,
            polynomial_size,
            decomp_base_log,
            ciphertext_modulus,
        }
    }

    /// Return the [`PolynomialSize`] of the [`PseudoGgswCiphertext`].
    ///
    /// See [`PseudoGgswCiphertext::from_container`] for usage.
    pub fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    /// Return the [`GlweSize`] of the [`PseudoGgswCiphertext`].
    ///
    /// See [`PseudoGgswCiphertext::from_container`] for usage.
    pub fn glwe_size_in(&self) -> GlweSize {
        self.glwe_size_in
    }

    /// Return the [`GlweSize`] of the [`PseudoGgswCiphertext`].
    ///
    /// See [`PseudoGgswCiphertext::from_container`] for usage.
    pub fn glwe_size_out(&self) -> GlweSize {
        self.glwe_size_out
    }

    /// Return the [`DecompositionBaseLog`] of the [`PseudoGgswCiphertext`].
    ///
    /// See [`PseudoGgswCiphertext::from_container`] for usage.
    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.decomp_base_log
    }

    /// Return the [`DecompositionLevelCount`] of the [`PseudoGgswCiphertext`].
    ///
    /// See [`PseudoGgswCiphertext::from_container`] for usage.
    pub fn decomposition_level_count(&self) -> DecompositionLevelCount {
        DecompositionLevelCount(self.data.container_len() / self.pseudo_ggsw_level_matrix_size())
    }

    /// Return the [`CiphertextModulus`] of the [`PseudoGgswCiphertext`].
    ///
    /// See [`PseudoGgswCiphertext::from_container`] for usage.
    pub fn ciphertext_modulus(&self) -> CiphertextModulus<C::Element> {
        self.ciphertext_modulus
    }

    /// Return the size in number of elements of a single [`GgswLevelMatrix`] of the current
    /// [`PseudoGgswCiphertext`].
    ///
    /// See [`PseudoGgswCiphertext::from_container`] for usage.
    pub fn pseudo_ggsw_level_matrix_size(&self) -> usize {
        // GlweSize GlweCiphertext(glwe_size, polynomial_size) per level
        pseudo_ggsw_level_matrix_size(self.glwe_size_in, self.glwe_size_out, self.polynomial_size)
    }

    /// Interpret the [`PseudoGgswCiphertext`] as a [`PolynomialList`].
    pub fn as_polynomial_list(&self) -> PolynomialListView<'_, Scalar> {
        PolynomialListView::from_container(self.as_ref(), self.polynomial_size)
    }

    /// Interpret the [`PseudoGgswCiphertext`] as a [`GlweCiphertextList`].
    pub fn as_glwe_list(&self) -> GlweCiphertextListView<'_, Scalar> {
        GlweCiphertextListView::from_container(
            self.as_ref(),
            self.glwe_size_out,
            self.polynomial_size,
            self.ciphertext_modulus,
        )
    }

    /// Return a view of the [`PseudoGgswCiphertext`]. This is useful if an algorithm takes a view
    /// by value.
    pub fn as_view(&self) -> PseudoGgswCiphertextView<'_, Scalar> {
        PseudoGgswCiphertextView::from_container(
            self.as_ref(),
            self.glwe_size_in(),
            self.glwe_size_out(),
            self.polynomial_size(),
            self.decomposition_base_log(),
            self.ciphertext_modulus(),
        )
    }

    /// Consume the entity and return its underlying container.
    ///
    /// See [`PseudoGgswCiphertext::from_container`] for usage.
    pub fn into_container(self) -> C {
        self.data
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> PseudoGgswCiphertext<C> {
    /// Mutable variant of [`PseudoGgswCiphertext::as_polynomial_list`].
    pub fn as_mut_polynomial_list(&mut self) -> PolynomialListMutView<'_, Scalar> {
        let polynomial_size = self.polynomial_size;
        PolynomialListMutView::from_container(self.as_mut(), polynomial_size)
    }

    /// Mutable variant of [`PseudoGgswCiphertext::as_glwe_list`].
    pub fn as_mut_glwe_list(&mut self) -> GlweCiphertextListMutView<'_, Scalar> {
        let polynomial_size = self.polynomial_size;
        let glwe_size_out = self.glwe_size_out;
        let ciphertext_modulus = self.ciphertext_modulus;
        GlweCiphertextListMutView::from_container(
            self.as_mut(),
            glwe_size_out,
            polynomial_size,
            ciphertext_modulus,
        )
    }

    /// Mutable variant of [`PseudoGgswCiphertext::as_view`].
    pub fn as_mut_view(&mut self) -> PseudoGgswCiphertextMutView<'_, Scalar> {
        let glwe_size_in = self.glwe_size_in();
        let glwe_size_out = self.glwe_size_out();
        let polynomial_size = self.polynomial_size();
        let decomp_base_log = self.decomposition_base_log();
        let ciphertext_modulus = self.ciphertext_modulus;
        PseudoGgswCiphertextMutView::from_container(
            self.as_mut(),
            glwe_size_in,
            glwe_size_out,
            polynomial_size,
            decomp_base_log,
            ciphertext_modulus,
        )
    }
}

/// A [`PseudoGgswCiphertext`] owning the memory for its own storage.
pub type PseudoGgswCiphertextOwned<Scalar> = PseudoGgswCiphertext<Vec<Scalar>>;
/// A [`PseudoGgswCiphertext`] immutably borrowing memory for its own storage.
pub type PseudoGgswCiphertextView<'data, Scalar> = PseudoGgswCiphertext<&'data [Scalar]>;
/// A [`PseudoGgswCiphertext`] immutably borrowing memory for its own storage.
pub type PseudoGgswCiphertextMutView<'data, Scalar> = PseudoGgswCiphertext<&'data mut [Scalar]>;

impl<Scalar: UnsignedInteger> PseudoGgswCiphertextOwned<Scalar> {
    /// Allocate memory and create a new owned [`PseudoGgswCiphertext`].
    ///
    /// # Note
    ///
    /// This function allocates a vector of the appropriate size and wraps it in the appropriate
    /// type. If you want to encrypt data you need to use
    /// [`crate::core_crypto::algorithms::encrypt_constant_ggsw_ciphertext`] or its parallel
    /// counterpart [`crate::core_crypto::algorithms::par_encrypt_constant_ggsw_ciphertext`]
    /// using this ciphertext as output.
    ///
    /// See [`PseudoGgswCiphertext::from_container`] for usage.
    pub fn new(
        fill_with: Scalar,
        glwe_size_in: GlweSize,
        glwe_size_out: GlweSize,
        polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        Self::from_container(
            vec![
                fill_with;
                pseudo_ggsw_ciphertext_size(
                    glwe_size_in,
                    glwe_size_out,
                    polynomial_size,
                    decomp_level_count
                )
            ],
            glwe_size_in,
            glwe_size_out,
            polynomial_size,
            decomp_base_log,
            ciphertext_modulus,
        )
    }
}

/// Metadata used in the [`CreateFrom`] implementation to create [`PseudoGgswCiphertext`] entities.
#[derive(Clone, Copy)]
pub struct PseudoGgswCiphertextCreationMetadata<Scalar: UnsignedInteger>(
    pub GlweSize,
    pub GlweSize,
    pub PolynomialSize,
    pub DecompositionBaseLog,
    pub CiphertextModulus<Scalar>,
);

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> CreateFrom<C>
    for PseudoGgswCiphertext<C>
{
    type Metadata = PseudoGgswCiphertextCreationMetadata<Scalar>;

    #[inline]
    fn create_from(from: C, meta: Self::Metadata) -> Self {
        let PseudoGgswCiphertextCreationMetadata(
            glwe_size_in,
            glwe_size_out,
            polynomial_size,
            decomp_base_log,
            ciphertext_modulus,
        ) = meta;
        Self::from_container(
            from,
            glwe_size_in,
            glwe_size_out,
            polynomial_size,
            decomp_base_log,
            ciphertext_modulus,
        )
    }
}

/// A convenience structure to more easily write iterators on a [`PseudoGgswCiphertext`] levels.
pub struct PseudoGgswLevelMatrix<C: Container>
where
    C::Element: UnsignedInteger,
{
    data: C,
    glwe_size_in: GlweSize,
    glwe_size_out: GlweSize,
    polynomial_size: PolynomialSize,
    ciphertext_modulus: CiphertextModulus<C::Element>,
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> PseudoGgswLevelMatrix<C> {
    /// Create a [`GgswLevelMatrix`] from an existing container.
    ///
    /// # Note
    ///
    /// This docstring exhibits [`GgswLevelMatrix`] primitives usage.
    ///
    /// ```
    /// use tfhe::core_crypto::experimental::prelude::*;
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for GgswLevelMatrix creation
    /// let glwe_size_in = GlweSize(3);
    /// let glwe_size_out = GlweSize(2);
    /// let polynomial_size = PolynomialSize(1024);
    /// let ciphertext_modulus = CiphertextModulus::new_native();
    ///
    /// let container =
    ///     vec![0u64; pseudo_ggsw_level_matrix_size(glwe_size_in, glwe_size_out, polynomial_size)];
    ///
    /// // Create a new GgswLevelMatrix
    /// let ggsw_level_matrix = PseudoGgswLevelMatrix::from_container(
    ///     container,
    ///     glwe_size_in,
    ///     glwe_size_out,
    ///     polynomial_size,
    ///     ciphertext_modulus,
    /// );
    ///
    /// assert_eq!(ggsw_level_matrix.glwe_size_in(), glwe_size_in);
    /// assert_eq!(ggsw_level_matrix.glwe_size_out(), glwe_size_out);
    /// assert_eq!(ggsw_level_matrix.polynomial_size(), polynomial_size);
    /// assert_eq!(ggsw_level_matrix.ciphertext_modulus(), ciphertext_modulus);
    /// ```
    pub fn from_container(
        container: C,
        glwe_size_in: GlweSize,
        glwe_size_out: GlweSize,
        polynomial_size: PolynomialSize,
        ciphertext_modulus: CiphertextModulus<C::Element>,
    ) -> Self {
        assert!(
            container.container_len()
                == pseudo_ggsw_level_matrix_size(glwe_size_in, glwe_size_out, polynomial_size),
            "The provided container length is not valid. \
            Expected length of {} (glwe_size * glwe_size * polynomial_size), got {}",
            pseudo_ggsw_level_matrix_size(glwe_size_in, glwe_size_out, polynomial_size),
            container.container_len(),
        );

        Self {
            data: container,
            glwe_size_in,
            glwe_size_out,
            polynomial_size,
            ciphertext_modulus,
        }
    }

    /// Return the [`GlweSize`] of the [`GgswLevelMatrix`].
    ///
    /// See [`GgswLevelMatrix::from_container`] for usage.
    pub fn glwe_size_in(&self) -> GlweSize {
        self.glwe_size_in
    }

    pub fn glwe_size_out(&self) -> GlweSize {
        self.glwe_size_out
    }

    /// Return the [`PolynomialSize`] of the [`GgswLevelMatrix`].
    ///
    /// See [`GgswLevelMatrix::from_container`] for usage.
    pub fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    /// Return the [`CiphertextModulus`] of the [`GgswLevelMatrix`].
    ///
    /// See [`GgswLevelMatrix::from_container`] for usage.
    pub fn ciphertext_modulus(&self) -> CiphertextModulus<C::Element> {
        self.ciphertext_modulus
    }

    /// Interpret the [`GgswLevelMatrix`] as a [`GlweCiphertextList`].
    pub fn as_glwe_list(&self) -> GlweCiphertextListView<'_, C::Element> {
        GlweCiphertextListView::from_container(
            self.data.as_ref(),
            self.glwe_size_out,
            self.polynomial_size,
            self.ciphertext_modulus,
        )
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> PseudoGgswLevelMatrix<C> {
    /// Mutable variant of [`GgswLevelMatrix::as_glwe_list`]
    pub fn as_mut_glwe_list(&mut self) -> GlweCiphertextListMutView<'_, C::Element> {
        GlweCiphertextListMutView::from_container(
            self.data.as_mut(),
            self.glwe_size_out,
            self.polynomial_size,
            self.ciphertext_modulus,
        )
    }
}

/// Metadata used in the [`CreateFrom`] implementation to create [`GgswLevelMatrix`] entities.
#[derive(Clone, Copy)]
pub struct PseudoGgswLevelMatrixCreationMetadata<Scalar: UnsignedInteger>(
    pub GlweSize,
    pub GlweSize,
    pub PolynomialSize,
    pub CiphertextModulus<Scalar>,
);

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> CreateFrom<C>
    for PseudoGgswLevelMatrix<C>
{
    type Metadata = PseudoGgswLevelMatrixCreationMetadata<C::Element>;

    #[inline]
    fn create_from(from: C, meta: Self::Metadata) -> Self {
        let PseudoGgswLevelMatrixCreationMetadata(
            glwe_size_in,
            glwe_size_out,
            polynomial_size,
            ciphertext_modulus,
        ) = meta;
        Self::from_container(
            from,
            glwe_size_in,
            glwe_size_out,
            polynomial_size,
            ciphertext_modulus,
        )
    }
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> ContiguousEntityContainer
    for PseudoGgswCiphertext<C>
{
    type Element = C::Element;

    type EntityViewMetadata = PseudoGgswLevelMatrixCreationMetadata<Self::Element>;

    type EntityView<'this> = PseudoGgswLevelMatrix<&'this [Self::Element]>
    where
        Self: 'this;

    type SelfViewMetadata = ();

    type SelfView<'this> = DummyCreateFrom
    where
        Self: 'this;

    fn get_entity_view_creation_metadata(&self) -> Self::EntityViewMetadata {
        PseudoGgswLevelMatrixCreationMetadata(
            self.glwe_size_in,
            self.glwe_size_out,
            self.polynomial_size,
            self.ciphertext_modulus,
        )
    }

    fn get_entity_view_pod_size(&self) -> usize {
        self.pseudo_ggsw_level_matrix_size()
    }

    /// Unimplemented for [`PseudoGgswCiphertext`]. At the moment it does not make sense to
    /// return "sub" PseudoGgswCiphertext.
    fn get_self_view_creation_metadata(&self) -> Self::SelfViewMetadata {
        unimplemented!(
            "This function is not supported for PseudoGgswCiphertext. \
        At the moment it does not make sense to return 'sub' PseudoGgswCiphertext."
        )
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> ContiguousEntityContainerMut
    for PseudoGgswCiphertext<C>
{
    type EntityMutView<'this> = PseudoGgswLevelMatrix<&'this mut [Self::Element]>
    where
        Self: 'this;

    type SelfMutView<'this> = DummyCreateFrom
    where
        Self: 'this;
}
