use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::specification::parameters::*;

pub struct GgswCiphertextList<C: Container> {
    data: C,
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
}

impl<T, C: Container<Element = T>> AsRef<[T]> for GgswCiphertextList<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T, C: ContainerMut<Element = T>> AsMut<[T]> for GgswCiphertextList<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

impl<Scalar, C: Container<Element = Scalar>> GgswCiphertextList<C> {
    pub fn from_container(
        container: C,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
    ) -> GgswCiphertextList<C> {
        assert!(
            container.container_len()
                % (decomp_level_count.0 * glwe_size.0 * glwe_size.0 * polynomial_size.0)
                == 0,
            "The provided container length is not valid. \
        It needs to be dividable by decomp_level_count * glwe_size * glwe_size * polynomial_size: \
        {}.Got container length: {} and decomp_level_count: {decomp_level_count:?},  \
        glwe_size: {glwe_size:?}, polynomial_size: {polynomial_size:?}",
            decomp_level_count.0 * glwe_size.0 * glwe_size.0 * polynomial_size.0,
            container.container_len()
        );

        GgswCiphertextList {
            data: container,
            glwe_size,
            polynomial_size,
            decomp_base_log,
            decomp_level_count,
        }
    }

    pub fn glwe_size(&self) -> GlweSize {
        self.glwe_size
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.decomp_base_log
    }

    pub fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.decomp_level_count
    }

    pub fn ggsw_ciphertext_count(&self) -> GgswCiphertextCount {
        GgswCiphertextCount(
            self.data.container_len()
                / ggsw_ciphertext_size(
                    self.glwe_size,
                    self.polynomial_size,
                    self.decomp_level_count,
                ),
        )
    }

    pub fn into_container(self) -> C {
        self.data
    }
}

pub type GgswCiphertextListOwned<Scalar> = GgswCiphertextList<Vec<Scalar>>;
pub type GgswCiphertextListView<'data, Scalar> = GgswCiphertextList<&'data [Scalar]>;
pub type GgswCiphertextListMutView<'data, Scalar> = GgswCiphertextList<&'data mut [Scalar]>;

impl<Scalar: Copy> GgswCiphertextListOwned<Scalar> {
    pub fn new(
        fill_with: Scalar,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        ciphertext_count: GgswCiphertextCount,
    ) -> GgswCiphertextListOwned<Scalar> {
        GgswCiphertextList::from_container(
            vec![
                fill_with;
                ciphertext_count.0
                    * ggsw_ciphertext_size(glwe_size, polynomial_size, decomp_level_count)
            ],
            glwe_size,
            polynomial_size,
            decomp_base_log,
            decomp_level_count,
        )
    }
}

#[derive(Clone, Copy)]
pub struct GgswCiphertextListCreationMetadata(
    pub GlweSize,
    pub PolynomialSize,
    pub DecompositionBaseLog,
    pub DecompositionLevelCount,
);

impl<C: Container> CreateFrom<C> for GgswCiphertextList<C> {
    type Metadata = GgswCiphertextListCreationMetadata;

    #[inline]
    fn create_from(from: C, meta: Self::Metadata) -> GgswCiphertextList<C> {
        let GgswCiphertextListCreationMetadata(
            glwe_size,
            polynomial_size,
            decomp_base_log,
            decomp_level_count,
        ) = meta;
        GgswCiphertextList::from_container(
            from,
            glwe_size,
            polynomial_size,
            decomp_base_log,
            decomp_level_count,
        )
    }
}

impl<C: Container> ContiguousEntityContainer for GgswCiphertextList<C> {
    type Element = C::Element;

    type EntityViewMetadata = GgswCiphertextCreationMetadata;

    type EntityView<'this> = GgswCiphertextView<'this, Self::Element>
    where
        Self: 'this;

    type SelfViewMetadata = GgswCiphertextListCreationMetadata;

    type SelfView<'this> = GgswCiphertextListView<'this, Self::Element>
    where
        Self: 'this;

    fn get_entity_view_creation_metadata(&self) -> GgswCiphertextCreationMetadata {
        GgswCiphertextCreationMetadata(self.glwe_size, self.polynomial_size, self.decomp_base_log)
    }

    fn get_entity_view_pod_size(&self) -> usize {
        ggsw_ciphertext_size(
            self.glwe_size,
            self.polynomial_size,
            self.decomp_level_count,
        )
    }

    fn get_self_view_creation_metadata(&self) -> Self::SelfViewMetadata {
        GgswCiphertextListCreationMetadata(
            self.glwe_size,
            self.polynomial_size,
            self.decomp_base_log,
            self.decomp_level_count,
        )
    }
}

impl<C: ContainerMut> ContiguousEntityContainerMut for GgswCiphertextList<C> {
    type EntityMutView<'this> = GgswCiphertextMutView<'this, Self::Element>
    where
        Self: 'this;

    type SelfMutView<'this> = GgswCiphertextListMutView<'this, Self::Element>
    where
        Self: 'this;
}
