//! Module containing the definition of the [`CmLwePackingKeyPart`].

use super::cm_lwe_ciphertext_list::{
    CmLweCiphertextListCreationMetadata, CmLweCiphertextListMutView, CmLweCiphertextListView,
};
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::experimental::prelude::CmDimension;

/// The i-th part of a [`CmLwePackingKey`](super::cm_lwe_packing_key::CmLwePackingKey): a keyswitch
/// key that converts `lwe(m_i)` into `cm_lwe(0, ..., 0, m_i, 0, ..., 0)` where `m_i` is at position
/// `i`.
///
/// Concretely it key-switches each of the `n = input_lwe_dimension` mask elements of the input
/// ciphertext into a CM-LWE ciphertext. Each mask element contributes `L` CM-LWE ciphertexts
/// (one per decomposition level), each of size `k + d`.
///
/// Memory layout (`n` = `input_lwe_dimension`, `L` = `decomp_level_count`,
/// `k` = `output_lwe_dimension`, `d` = `output_cm_dimension`):
/// `block[0] | block[1] | ... | block[n-1]`, each of size `L * (k + d)`.
/// Total size: `n * L * (k + d)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CmLwePackingKeyPart<C: Container>
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

impl<T: UnsignedInteger, C: Container<Element = T>> AsRef<[T]> for CmLwePackingKeyPart<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T: UnsignedInteger, C: ContainerMut<Element = T>> AsMut<[T]> for CmLwePackingKeyPart<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

pub fn cm_lwe_packing_key_part_size(
    decomp_level_count: DecompositionLevelCount,
    input_lwe_dimension: LweDimension,
    output_lwe_dimension: LweDimension,
    output_cm_dimension: CmDimension,
) -> usize {
    input_lwe_dimension.0
        * cm_lwe_packing_key_part_input_key_element_encrypted_size(
            decomp_level_count,
            output_lwe_dimension,
            output_cm_dimension,
        )
}

pub fn cm_lwe_packing_key_part_input_key_element_encrypted_size(
    decomp_level_count: DecompositionLevelCount,
    output_lwe_dimension: LweDimension,
    output_cm_dimension: CmDimension,
) -> usize {
    // One ciphertext per level encrypted under the output key
    decomp_level_count.0 * (output_lwe_dimension.0 + output_cm_dimension.0)
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> CmLwePackingKeyPart<C> {
    pub fn from_container(
        container: C,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        input_lwe_dimension: LweDimension,
        output_lwe_dimension: LweDimension,
        output_cm_dimension: CmDimension,
        ciphertext_modulus: CiphertextModulus<C::Element>,
    ) -> Self {
        let expected_len = cm_lwe_packing_key_part_size(
            decomp_level_count,
            input_lwe_dimension,
            output_lwe_dimension,
            output_cm_dimension,
        );
        assert_eq!(
            container.container_len(),
            expected_len,
            "The provided container length is not valid. \
        Expected decomp_level_count * (output_lwe_dimension + output_cm_dimension) * input_lwe_dimension: {}. \
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

    pub fn input_key_element_encrypted_size(&self) -> usize {
        cm_lwe_packing_key_part_input_key_element_encrypted_size(
            self.decomp_level_count,
            self.output_lwe_dimension,
            self.output_cm_dimension,
        )
    }

    pub fn as_view(&self) -> CmLwePackingKeyPartView<'_, Scalar> {
        CmLwePackingKeyPart::from_container(
            self.as_ref(),
            self.decomp_base_log,
            self.decomp_level_count,
            self.input_lwe_dimension,
            self.output_lwe_dimension,
            self.output_cm_dimension,
            self.ciphertext_modulus,
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

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> CmLwePackingKeyPart<C> {
    pub fn as_mut_view(&mut self) -> CmLwePackingKeyPartMutView<'_, Scalar> {
        let Self {
            data: _,
            decomp_base_log,
            decomp_level_count,
            input_lwe_dimension,
            output_lwe_dimension,
            output_cm_dimension,
            ciphertext_modulus,
        } = *self;

        CmLwePackingKeyPart::from_container(
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

pub type CmLwePackingKeyPartOwned<Scalar> = CmLwePackingKeyPart<Vec<Scalar>>;

pub type CmLwePackingKeyPartView<'data, Scalar> = CmLwePackingKeyPart<&'data [Scalar]>;

pub type CmLwePackingKeyPartMutView<'data, Scalar> = CmLwePackingKeyPart<&'data mut [Scalar]>;

impl<Scalar: UnsignedInteger> CmLwePackingKeyPartOwned<Scalar> {
    pub fn new(
        fill_with: Scalar,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        input_key_lwe_dimension: LweDimension,
        output_lwe_dimension: LweDimension,
        output_cm_dimension: CmDimension,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        let expected_len = cm_lwe_packing_key_part_size(
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
pub struct CmLwePackingKeyPartCreationMetadata<Scalar: UnsignedInteger> {
    pub decomp_base_log: DecompositionBaseLog,
    pub decomp_level_count: DecompositionLevelCount,
    pub input_lwe_dimension: LweDimension,
    pub output_lwe_dimension: LweDimension,
    pub output_cm_dimension: CmDimension,
    pub ciphertext_modulus: CiphertextModulus<Scalar>,
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> CreateFrom<C>
    for CmLwePackingKeyPart<C>
{
    type Metadata = CmLwePackingKeyPartCreationMetadata<Scalar>;

    #[inline]
    fn create_from(from: C, meta: Self::Metadata) -> Self {
        let CmLwePackingKeyPartCreationMetadata {
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
    for CmLwePackingKeyPart<C>
{
    type Element = C::Element;

    type EntityViewMetadata = CmLweCiphertextListCreationMetadata<Self::Element>;

    type EntityView<'this>
        = CmLweCiphertextListView<'this, Self::Element>
    where
        Self: 'this;

    type SelfViewMetadata = CmLwePackingKeyPartCreationMetadata<Self::Element>;

    type SelfView<'this>
        = CmLwePackingKeyPartView<'this, Self::Element>
    where
        Self: 'this;

    fn get_entity_view_creation_metadata(&self) -> Self::EntityViewMetadata {
        CmLweCiphertextListCreationMetadata {
            lwe_dimension: self.output_lwe_dimension(),
            cm_dimension: self.output_cm_dimension,
            ciphertext_modulus: self.ciphertext_modulus(),
        }
    }

    fn get_entity_view_pod_size(&self) -> usize {
        self.input_key_element_encrypted_size()
    }

    fn get_self_view_creation_metadata(&self) -> Self::SelfViewMetadata {
        let Self {
            decomp_base_log,
            decomp_level_count,
            input_lwe_dimension,
            output_lwe_dimension,
            output_cm_dimension,
            ciphertext_modulus,
            ..
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
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> ContiguousEntityContainerMut
    for CmLwePackingKeyPart<C>
{
    type EntityMutView<'this>
        = CmLweCiphertextListMutView<'this, Self::Element>
    where
        Self: 'this;

    type SelfMutView<'this>
        = CmLwePackingKeyPartMutView<'this, Self::Element>
    where
        Self: 'this;
}
