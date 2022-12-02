use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::specification::parameters::*;

pub struct GgswCiphertext<C: Container> {
    data: C,
    polynomial_size: PolynomialSize,
    glwe_size: GlweSize,
    decomp_base_log: DecompositionBaseLog,
}

impl<T, C: Container<Element = T>> AsRef<[T]> for GgswCiphertext<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T, C: ContainerMut<Element = T>> AsMut<[T]> for GgswCiphertext<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

pub fn ggsw_ciphertext_size(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    decomp_level_count: DecompositionLevelCount,
) -> usize {
    decomp_level_count.0 * ggsw_level_matrix_size(glwe_size, polynomial_size)
}

pub fn ggsw_level_matrix_size(glwe_size: GlweSize, polynomial_size: PolynomialSize) -> usize {
    glwe_size.0 * glwe_size.0 * polynomial_size.0
}

impl<Scalar, C: Container<Element = Scalar>> GgswCiphertext<C> {
    pub fn from_container(
        container: C,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
    ) -> Self {
        assert!(
            container.container_len() > 0,
            "Got an empty container to create a GgswCiphertextBase"
        );
        assert!(
            container.container_len() % (glwe_size.0 * glwe_size.0 * polynomial_size.0) == 0,
            "The provided container length is not valid. \
        It needs to be dividable by glwe_size * glwe_size * polynomial_size: {}. \
        Got container length: {} and glwe_size: {glwe_size:?}, \
        polynomial_size: {polynomial_size:?}.",
            glwe_size.0 * glwe_size.0 * polynomial_size.0,
            container.container_len()
        );

        GgswCiphertext {
            data: container,
            polynomial_size,
            glwe_size,
            decomp_base_log,
        }
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    pub fn glwe_size(&self) -> GlweSize {
        self.glwe_size
    }

    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.decomp_base_log
    }

    pub fn decomposition_level_count(&self) -> DecompositionLevelCount {
        DecompositionLevelCount(self.data.container_len() / self.ggsw_level_matrix_size())
    }

    pub fn ggsw_level_matrix_size(&self) -> usize {
        // GlweSize GlweCiphertext(glwe_size, polynomial_size) per level
        ggsw_level_matrix_size(self.glwe_size, self.polynomial_size)
    }

    pub fn as_polynomial_list(&self) -> PolynomialListView<'_, Scalar> {
        PolynomialListView::from_container(self.as_ref(), self.polynomial_size)
    }

    pub fn as_glwe_list(&self) -> GlweCiphertextListView<'_, Scalar> {
        GlweCiphertextListView::from_container(self.as_ref(), self.polynomial_size, self.glwe_size)
    }

    pub fn as_view(&self) -> GgswCiphertextView<'_, Scalar> {
        GgswCiphertextView::from_container(
            self.as_ref(),
            self.glwe_size(),
            self.polynomial_size(),
            self.decomposition_base_log(),
        )
    }

    pub fn into_container(self) -> C {
        self.data
    }
}

impl<Scalar, C: ContainerMut<Element = Scalar>> GgswCiphertext<C> {
    pub fn as_mut_polynomial_list(&mut self) -> PolynomialListMutView<'_, Scalar> {
        let polynomial_size = self.polynomial_size;
        PolynomialListMutView::from_container(self.as_mut(), polynomial_size)
    }

    pub fn as_mut_glwe_list(&mut self) -> GlweCiphertextListMutView<'_, Scalar> {
        let polynomial_size = self.polynomial_size;
        let glwe_size = self.glwe_size;
        GlweCiphertextListMutView::from_container(self.as_mut(), polynomial_size, glwe_size)
    }

    pub fn as_mut_view(&mut self) -> GgswCiphertextMutView<'_, Scalar> {
        let glwe_size = self.glwe_size();
        let polynomial_size = self.polynomial_size();
        let decomp_base_log = self.decomposition_base_log();
        GgswCiphertextMutView::from_container(
            self.as_mut(),
            glwe_size,
            polynomial_size,
            decomp_base_log,
        )
    }
}

pub type GgswCiphertextOwned<Scalar> = GgswCiphertext<Vec<Scalar>>;
pub type GgswCiphertextView<'data, Scalar> = GgswCiphertext<&'data [Scalar]>;
pub type GgswCiphertextMutView<'data, Scalar> = GgswCiphertext<&'data mut [Scalar]>;

impl<Scalar: Copy> GgswCiphertextOwned<Scalar> {
    pub fn new(
        fill_with: Scalar,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
    ) -> GgswCiphertextOwned<Scalar> {
        GgswCiphertextOwned::from_container(
            vec![fill_with; ggsw_ciphertext_size(glwe_size, polynomial_size, decomp_level_count)],
            glwe_size,
            polynomial_size,
            decomp_base_log,
        )
    }
}

#[derive(Clone, Copy)]
pub struct GgswCiphertextCreationMetadata(
    pub GlweSize,
    pub PolynomialSize,
    pub DecompositionBaseLog,
);

impl<C: Container> CreateFrom<C> for GgswCiphertext<C> {
    type Metadata = GgswCiphertextCreationMetadata;

    #[inline]
    fn create_from(from: C, meta: Self::Metadata) -> GgswCiphertext<C> {
        let GgswCiphertextCreationMetadata(glwe_size, polynomial_size, decomp_base_log) = meta;
        GgswCiphertext::from_container(from, glwe_size, polynomial_size, decomp_base_log)
    }
}

pub struct GgswLevelMatrix<C: Container> {
    data: C,
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
}

impl<C: Container> GgswLevelMatrix<C> {
    pub fn glwe_size(&self) -> GlweSize {
        self.glwe_size
    }
    pub fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    pub fn from_container(
        container: C,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
    ) -> GgswLevelMatrix<C> {
        assert!(
            container.container_len() == ggsw_level_matrix_size(glwe_size, polynomial_size),
            "The provided container length is not valid. \
            Expected length of {} (glwe_size * glwe_size * polynomial_size), got {}",
            ggsw_level_matrix_size(glwe_size, polynomial_size),
            container.container_len(),
        );

        GgswLevelMatrix {
            data: container,
            glwe_size,
            polynomial_size,
        }
    }

    pub fn as_glwe_list(&self) -> GlweCiphertextListView<'_, C::Element> {
        GlweCiphertextListView::from_container(
            self.data.as_ref(),
            self.polynomial_size,
            self.glwe_size,
        )
    }
}

impl<C: ContainerMut> GgswLevelMatrix<C> {
    pub fn as_mut_glwe_list(&mut self) -> GlweCiphertextListMutView<'_, C::Element> {
        GlweCiphertextListMutView::from_container(
            self.data.as_mut(),
            self.polynomial_size,
            self.glwe_size,
        )
    }
}

#[derive(Clone, Copy)]
pub struct GgswLevelMatrixCreationMetadata(pub GlweSize, pub PolynomialSize);

impl<C: Container> CreateFrom<C> for GgswLevelMatrix<C> {
    type Metadata = GgswLevelMatrixCreationMetadata;

    #[inline]
    fn create_from(from: C, meta: Self::Metadata) -> GgswLevelMatrix<C> {
        let GgswLevelMatrixCreationMetadata(glwe_size, polynomial_size) = meta;
        GgswLevelMatrix::from_container(from, glwe_size, polynomial_size)
    }
}

impl<C: Container> ContiguousEntityContainer for GgswCiphertext<C> {
    type Element = C::Element;

    type EntityViewMetadata = GgswLevelMatrixCreationMetadata;

    type EntityView<'this> = GgswLevelMatrix<&'this [Self::Element]>
    where
        Self: 'this;

    type SelfViewMetadata = ();

    type SelfView<'this> = DummyCreateFrom
    where
        Self: 'this;

    fn get_entity_view_creation_metadata(&self) -> Self::EntityViewMetadata {
        GgswLevelMatrixCreationMetadata(self.glwe_size, self.polynomial_size)
    }

    fn get_entity_view_pod_size(&self) -> usize {
        self.ggsw_level_matrix_size()
    }

    /// Unimplement for [`GgswCiphertextBase`]. At the moment it does not make sense to
    /// return "sub" GgswCiphertext.
    fn get_self_view_creation_metadata(&self) -> Self::SelfViewMetadata {
        unimplemented!(
            "This function is not supported for GgswCiphertext. \
        At the moment it does not make sense to return 'sub' GgswCiphertext."
        )
    }
}

impl<C: ContainerMut> ContiguousEntityContainerMut for GgswCiphertext<C> {
    type EntityMutView<'this> = GgswLevelMatrix<&'this mut [Self::Element]>
    where
        Self: 'this;

    type SelfMutView<'this> = DummyCreateFrom
    where
        Self: 'this;
}
