//! Module containing the definition of the [`CmLweKeyswitchKey`].

use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::experimental::prelude::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CmLweKeyswitchKey<C: Container>
where
    C::Element: UnsignedInteger,
{
    data: C,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    input_lwe_dimension: LweDimension,
    output_lwe_dimension: LweDimension,
    cm_dimension: CmDimension,
    ciphertext_modulus: CiphertextModulus<C::Element>,
}

impl<T: UnsignedInteger, C: Container<Element = T>> AsRef<[T]> for CmLweKeyswitchKey<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T: UnsignedInteger, C: ContainerMut<Element = T>> AsMut<[T]> for CmLweKeyswitchKey<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

pub fn cm_lwe_keyswitch_key_input_key_element_size(
    decomp_level_count: DecompositionLevelCount,
    output_lwe_dimension: LweDimension,
    cm_dimension: CmDimension,
) -> usize {
    // One ciphertext per level encrypted under the output key
    decomp_level_count.0 * (output_lwe_dimension.0 + cm_dimension.0)
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> CmLweKeyswitchKey<C> {
    pub fn from_container(
        container: C,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        input_lwe_dimension: LweDimension,
        output_lwe_dimension: LweDimension,
        cm_dimension: CmDimension,
        ciphertext_modulus: CiphertextModulus<C::Element>,
    ) -> Self {
        assert!(
            container.container_len() > 0,
            "Got an empty container to create an CmLweKeyswitchKey"
        );
        let input_key_element_size = cm_lwe_keyswitch_key_input_key_element_size(
            decomp_level_count,
            output_lwe_dimension,
            cm_dimension,
        );
        assert!(
            container.container_len().is_multiple_of(input_key_element_size),
            "The provided container length is not valid. \
        It needs to be dividable by decomp_level_count * (output_lwe_dimension + cm_dimension): {}. \
        Got container length: {} and decomp_level_count: {decomp_level_count:?}, \
        output_lwe_dimension: {output_lwe_dimension:?}.",
            input_key_element_size,
            container.container_len()
        );

        Self {
            data: container,
            decomp_base_log,
            decomp_level_count,
            input_lwe_dimension,
            output_lwe_dimension,
            cm_dimension,
            ciphertext_modulus,
        }
    }

    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.decomp_base_log
    }

    pub fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.decomp_level_count
    }

    pub fn input_lwe_dimension(&self) -> LweDimension {
        self.input_lwe_dimension
    }

    pub fn output_lwe_dimension(&self) -> LweDimension {
        self.output_lwe_dimension
    }

    pub fn cm_dimension(&self) -> CmDimension {
        self.cm_dimension
    }

    pub fn input_key_element_encrypted_size(&self) -> usize {
        cm_lwe_keyswitch_key_input_key_element_size(
            self.decomp_level_count,
            self.output_lwe_dimension,
            self.cm_dimension,
        )
    }

    pub fn as_view(&self) -> CmLweKeyswitchKeyView<'_, Scalar> {
        CmLweKeyswitchKey::from_container(
            self.as_ref(),
            self.decomp_base_log,
            self.decomp_level_count,
            self.input_lwe_dimension,
            self.output_lwe_dimension,
            self.cm_dimension,
            self.ciphertext_modulus,
        )
    }

    pub fn into_container(self) -> C {
        self.data
    }

    pub fn as_cm_lwe_ciphertext_list(&self) -> CmLweCiphertextListView<'_, Scalar> {
        CmLweCiphertextListView::from_container(
            self.as_ref(),
            self.output_lwe_dimension,
            self.cm_dimension,
            self.ciphertext_modulus(),
        )
    }

    pub fn ciphertext_modulus(&self) -> CiphertextModulus<C::Element> {
        self.ciphertext_modulus
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> CmLweKeyswitchKey<C> {
    pub fn as_mut_view(&mut self) -> CmLweKeyswitchKeyMutView<'_, Scalar> {
        let decomp_base_log = self.decomp_base_log;
        let decomp_level_count = self.decomp_level_count;
        let input_lwe_dimension = self.input_lwe_dimension;
        let output_lwe_dimension = self.output_lwe_dimension;
        let cm_dimension = self.cm_dimension;
        let ciphertext_modulus = self.ciphertext_modulus;
        CmLweKeyswitchKey::from_container(
            self.as_mut(),
            decomp_base_log,
            decomp_level_count,
            input_lwe_dimension,
            output_lwe_dimension,
            cm_dimension,
            ciphertext_modulus,
        )
    }

    pub fn as_mut_cm_lwe_ciphertext_list(&mut self) -> CmLweCiphertextListMutView<'_, Scalar> {
        let output_lwe_dimension = self.output_lwe_dimension();
        let cm_dimension = self.cm_dimension;
        let ciphertext_modulus = self.ciphertext_modulus();
        CmLweCiphertextListMutView::from_container(
            self.as_mut(),
            output_lwe_dimension,
            cm_dimension,
            ciphertext_modulus,
        )
    }
}

pub type CmLweKeyswitchKeyOwned<Scalar> = CmLweKeyswitchKey<Vec<Scalar>>;

pub type CmLweKeyswitchKeyView<'data, Scalar> = CmLweKeyswitchKey<&'data [Scalar]>;

pub type CmLweKeyswitchKeyMutView<'data, Scalar> = CmLweKeyswitchKey<&'data mut [Scalar]>;

impl<Scalar: UnsignedInteger> CmLweKeyswitchKeyOwned<Scalar> {
    pub fn new(
        fill_with: Scalar,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        input_key_lwe_dimension: LweDimension,
        output_key_lwe_dimension: LweDimension,
        cm_dimension: CmDimension,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        Self::from_container(
            vec![
                fill_with;
                input_key_lwe_dimension.0
                    * cm_lwe_keyswitch_key_input_key_element_size(
                        decomp_level_count,
                        output_key_lwe_dimension,
                        cm_dimension,
                    )
            ],
            decomp_base_log,
            decomp_level_count,
            input_key_lwe_dimension,
            output_key_lwe_dimension,
            cm_dimension,
            ciphertext_modulus,
        )
    }
}

#[derive(Clone, Copy)]
pub struct CmLweKeyswitchKeyCreationMetadata<Scalar: UnsignedInteger> {
    pub decomp_base_log: DecompositionBaseLog,
    pub decomp_level_count: DecompositionLevelCount,
    pub input_lwe_dimension: LweDimension,
    pub output_lwe_dimension: LweDimension,
    pub cm_dimension: CmDimension,
    pub ciphertext_modulus: CiphertextModulus<Scalar>,
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> CreateFrom<C>
    for CmLweKeyswitchKey<C>
{
    type Metadata = CmLweKeyswitchKeyCreationMetadata<Scalar>;

    #[inline]
    fn create_from(from: C, meta: Self::Metadata) -> Self {
        let CmLweKeyswitchKeyCreationMetadata {
            decomp_base_log,
            decomp_level_count,
            output_lwe_dimension,
            ciphertext_modulus,
            input_lwe_dimension,
            cm_dimension,
        } = meta;
        Self::from_container(
            from,
            decomp_base_log,
            decomp_level_count,
            input_lwe_dimension,
            output_lwe_dimension,
            cm_dimension,
            ciphertext_modulus,
        )
    }
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> ContiguousEntityContainer
    for CmLweKeyswitchKey<C>
{
    type Element = C::Element;

    type EntityViewMetadata = CmLweCiphertextListCreationMetadata<Self::Element>;

    type EntityView<'this>
        = CmLweCiphertextListView<'this, Self::Element>
    where
        Self: 'this;

    type SelfViewMetadata = CmLweKeyswitchKeyCreationMetadata<Self::Element>;

    type SelfView<'this>
        = CmLweKeyswitchKeyView<'this, Self::Element>
    where
        Self: 'this;

    fn get_entity_view_creation_metadata(&self) -> Self::EntityViewMetadata {
        CmLweCiphertextListCreationMetadata {
            ciphertext_modulus: self.ciphertext_modulus(),
            lwe_dimension: self.output_lwe_dimension,
            cm_dimension: self.cm_dimension,
        }
    }

    fn get_entity_view_pod_size(&self) -> usize {
        self.input_key_element_encrypted_size()
    }

    fn get_self_view_creation_metadata(&self) -> Self::SelfViewMetadata {
        CmLweKeyswitchKeyCreationMetadata {
            decomp_base_log: self.decomposition_base_log(),
            decomp_level_count: self.decomposition_level_count(),
            output_lwe_dimension: self.output_lwe_dimension,
            input_lwe_dimension: self.input_lwe_dimension,
            cm_dimension: self.cm_dimension,
            ciphertext_modulus: self.ciphertext_modulus(),
        }
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> ContiguousEntityContainerMut
    for CmLweKeyswitchKey<C>
{
    type EntityMutView<'this>
        = CmLweCiphertextListMutView<'this, Self::Element>
    where
        Self: 'this;

    type SelfMutView<'this>
        = CmLweKeyswitchKeyMutView<'this, Self::Element>
    where
        Self: 'this;
}
