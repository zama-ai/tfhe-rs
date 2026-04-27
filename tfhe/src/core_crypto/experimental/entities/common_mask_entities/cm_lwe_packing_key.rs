//! Module containing the definition of the [`CmLwePackingKey`].

use super::cm_lwe_packing_key_part::{
    cm_lwe_packing_key_part_size, CmLwePackingKeyPartCreationMetadata, CmLwePackingKeyPartMutView,
    CmLwePackingKeyPartView,
};
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::experimental::entities::*;
use crate::core_crypto::experimental::prelude::*;

/// A packing key that converts `d = output_cm_dimension` independent LWE ciphertexts into a
/// single CM-LWE ciphertext.
///
/// For each input index `i`, the i-th [`CmLwePackingKeyPart`] key-switches
/// `lwe(m_i)` into `cm_lwe(0, ..., 0, m_i, 0, ..., 0)` where `m_i` is placed at position `i`.
/// Summing all `d` results yields `cm_lwe(m_0, m_1, ..., m_{d-1})`.
///
/// Memory layout (`d` = `output_cm_dimension`, `n` = `input_lwe_dimension`,
/// `L` = `decomp_level_count`, `k` = `output_lwe_dimension`):
/// `key_part[0] | key_part[1] | ... | key_part[d-1]`, each of size `n * L * (k + d)`.
/// Total size: `d * n * L * (k + d)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CmLwePackingKey<C: Container>
where
    C::Element: UnsignedInteger,
{
    data: C,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    input_lwe_dimension: LweDimension,
    output_lwe_dimension: LweDimension,
    output_cm_dimension: CmDimension,
    ciphertext_modulus: CiphertextModulus<C::Element>,
}

impl<T: UnsignedInteger, C: Container<Element = T>> AsRef<[T]> for CmLwePackingKey<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T: UnsignedInteger, C: ContainerMut<Element = T>> AsMut<[T]> for CmLwePackingKey<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

pub fn cm_lwe_packing_key_size(
    decomp_level_count: DecompositionLevelCount,
    input_lwe_dimension: LweDimension,
    output_lwe_dimension: LweDimension,
    output_cm_dimension: CmDimension,
) -> usize {
    output_cm_dimension.0
        * cm_lwe_packing_key_part_size(
            decomp_level_count,
            input_lwe_dimension,
            output_lwe_dimension,
            output_cm_dimension,
        )
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> CmLwePackingKey<C> {
    pub fn from_container(
        container: C,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        input_lwe_dimension: LweDimension,
        output_lwe_dimension: LweDimension,
        output_cm_dimension: CmDimension,
        ciphertext_modulus: CiphertextModulus<C::Element>,
    ) -> Self {
        let expected_len = cm_lwe_packing_key_size(
            decomp_level_count,
            input_lwe_dimension,
            output_lwe_dimension,
            output_cm_dimension,
        );
        assert_eq!(
            container.container_len(),
            expected_len,
            "The provided container length is not valid. \
        Expected decomp_level_count * (output_lwe_dimension + output_cm_dimension) * output_cm_dimension * input_lwe_dimension: {}. \
        Got container length: {} and decomp_level_count: {decomp_level_count:?}, \
        output_lwe_dimension + output_cm_dimension: {}, input_lwe_dimension: {input_lwe_dimension:?}.",
            expected_len,
            container.container_len(),
            output_lwe_dimension.0 + output_cm_dimension.0,
        );

        Self {
            data: container,
            decomp_base_log,
            decomp_level_count,
            input_lwe_dimension,
            output_lwe_dimension,
            output_cm_dimension,
            ciphertext_modulus,
        }
    }

    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.decomp_base_log
    }

    pub fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.decomp_level_count
    }

    pub fn input_key_lwe_dimension(&self) -> LweDimension {
        self.input_lwe_dimension
    }

    pub fn output_lwe_dimension(&self) -> LweDimension {
        self.output_lwe_dimension
    }

    pub fn output_cm_dimension(&self) -> CmDimension {
        self.output_cm_dimension
    }

    pub fn key_part_size(&self) -> usize {
        let Self {
            decomp_level_count,
            input_lwe_dimension,
            output_lwe_dimension,
            output_cm_dimension,
            ..
        } = *self;
        cm_lwe_packing_key_part_size(
            decomp_level_count,
            input_lwe_dimension,
            output_lwe_dimension,
            output_cm_dimension,
        )
    }

    pub fn as_view(&self) -> CmLwePackingKeyView<'_, Scalar> {
        let Self {
            data: _,
            decomp_base_log,
            decomp_level_count,
            input_lwe_dimension,
            output_lwe_dimension,
            output_cm_dimension,
            ciphertext_modulus,
        } = *self;
        CmLwePackingKey::from_container(
            self.as_ref(),
            decomp_base_log,
            decomp_level_count,
            input_lwe_dimension,
            output_lwe_dimension,
            output_cm_dimension,
            ciphertext_modulus,
        )
    }

    pub fn into_container(self) -> C {
        self.data
    }

    pub fn as_cm_lwe_ciphertext_list(&self) -> CmLweCiphertextListView<'_, Scalar> {
        CmLweCiphertextListView::from_container(
            self.as_ref(),
            self.output_lwe_dimension(),
            self.output_cm_dimension,
            self.ciphertext_modulus(),
        )
    }

    pub fn ciphertext_modulus(&self) -> CiphertextModulus<C::Element> {
        self.ciphertext_modulus
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> CmLwePackingKey<C> {
    pub fn as_mut_view(&mut self) -> CmLwePackingKeyMutView<'_, Scalar> {
        let Self {
            data: _,
            decomp_base_log,
            decomp_level_count,
            input_lwe_dimension,
            output_lwe_dimension,
            output_cm_dimension,
            ciphertext_modulus,
        } = *self;
        CmLwePackingKey::from_container(
            self.as_mut(),
            decomp_base_log,
            decomp_level_count,
            input_lwe_dimension,
            output_lwe_dimension,
            output_cm_dimension,
            ciphertext_modulus,
        )
    }

    pub fn as_mut_cm_lwe_ciphertext_list(&mut self) -> CmLweCiphertextListMutView<'_, Scalar> {
        let Self {
            output_lwe_dimension,
            output_cm_dimension,
            ciphertext_modulus,
            ..
        } = *self;
        CmLweCiphertextListMutView::from_container(
            self.as_mut(),
            output_lwe_dimension,
            output_cm_dimension,
            ciphertext_modulus,
        )
    }
}

pub type CmLwePackingKeyOwned<Scalar> = CmLwePackingKey<Vec<Scalar>>;

pub type CmLwePackingKeyView<'data, Scalar> = CmLwePackingKey<&'data [Scalar]>;

pub type CmLwePackingKeyMutView<'data, Scalar> = CmLwePackingKey<&'data mut [Scalar]>;

impl<Scalar: UnsignedInteger> CmLwePackingKeyOwned<Scalar> {
    pub fn new(
        fill_with: Scalar,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        input_key_lwe_dimension: LweDimension,
        output_lwe_dimension: LweDimension,
        output_cm_dimension: CmDimension,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        let expected_len = cm_lwe_packing_key_size(
            decomp_level_count,
            input_key_lwe_dimension,
            output_lwe_dimension,
            output_cm_dimension,
        );
        Self::from_container(
            vec![fill_with; expected_len],
            decomp_base_log,
            decomp_level_count,
            input_key_lwe_dimension,
            output_lwe_dimension,
            output_cm_dimension,
            ciphertext_modulus,
        )
    }
}

#[derive(Clone, Copy)]
pub struct CmLwePackingKeyCreationMetadata<Scalar: UnsignedInteger> {
    pub decomp_base_log: DecompositionBaseLog,
    pub decomp_level_count: DecompositionLevelCount,
    pub input_lwe_dimension: LweDimension,
    pub output_lwe_dimension: LweDimension,
    pub output_cm_dimension: CmDimension,
    pub ciphertext_modulus: CiphertextModulus<Scalar>,
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> CreateFrom<C> for CmLwePackingKey<C> {
    type Metadata = CmLwePackingKeyCreationMetadata<Scalar>;

    #[inline]
    fn create_from(from: C, meta: Self::Metadata) -> Self {
        let CmLwePackingKeyCreationMetadata {
            decomp_base_log,
            decomp_level_count,
            input_lwe_dimension,
            output_lwe_dimension,
            output_cm_dimension,
            ciphertext_modulus,
        } = meta;
        Self::from_container(
            from,
            decomp_base_log,
            decomp_level_count,
            input_lwe_dimension,
            output_lwe_dimension,
            output_cm_dimension,
            ciphertext_modulus,
        )
    }
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> ContiguousEntityContainer
    for CmLwePackingKey<C>
{
    type Element = C::Element;

    type EntityViewMetadata = CmLwePackingKeyPartCreationMetadata<Self::Element>;

    type EntityView<'this>
        = CmLwePackingKeyPartView<'this, Self::Element>
    where
        Self: 'this;

    type SelfViewMetadata = CmLwePackingKeyCreationMetadata<Self::Element>;

    type SelfView<'this>
        = CmLwePackingKeyView<'this, Self::Element>
    where
        Self: 'this;

    fn get_entity_view_creation_metadata(&self) -> Self::EntityViewMetadata {
        let Self {
            data: _,
            decomp_base_log,
            decomp_level_count,
            input_lwe_dimension,
            output_lwe_dimension,
            output_cm_dimension,
            ciphertext_modulus,
        } = *self;
        CmLwePackingKeyPartCreationMetadata {
            decomp_base_log,
            decomp_level_count,
            input_lwe_dimension,
            output_lwe_dimension,
            output_cm_dimension,
            ciphertext_modulus,
        }
    }

    fn get_entity_view_pod_size(&self) -> usize {
        self.key_part_size()
    }

    fn get_self_view_creation_metadata(&self) -> Self::SelfViewMetadata {
        let Self {
            data: _,
            decomp_base_log,
            decomp_level_count,
            input_lwe_dimension,
            output_lwe_dimension,
            output_cm_dimension,
            ciphertext_modulus,
        } = *self;
        CmLwePackingKeyCreationMetadata {
            decomp_base_log,
            decomp_level_count,
            input_lwe_dimension,
            output_lwe_dimension,
            output_cm_dimension,
            ciphertext_modulus,
        }
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> ContiguousEntityContainerMut
    for CmLwePackingKey<C>
{
    type EntityMutView<'this>
        = CmLwePackingKeyPartMutView<'this, Self::Element>
    where
        Self: 'this;

    type SelfMutView<'this>
        = CmLwePackingKeyMutView<'this, Self::Element>
    where
        Self: 'this;
}
