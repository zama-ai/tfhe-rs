use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LweKeyswitchKey<C: Container> {
    data: C,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    output_lwe_size: LweSize,
}

impl<T, C: Container<Element = T>> AsRef<[T]> for LweKeyswitchKey<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T, C: ContainerMut<Element = T>> AsMut<[T]> for LweKeyswitchKey<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

pub fn lwe_keyswitch_key_input_key_element_encrypted_size(
    decomp_level_count: DecompositionLevelCount,
    output_lwe_size: LweSize,
) -> usize {
    // One ciphertext per level encrypted under the output key
    decomp_level_count.0 * output_lwe_size.0
}

impl<Scalar, C: Container<Element = Scalar>> LweKeyswitchKey<C> {
    pub fn from_container(
        container: C,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        output_lwe_size: LweSize,
    ) -> Self {
        assert!(
            container.container_len() > 0,
            "Got an empty container to create an LweKeyswitchKey"
        );
        assert!(
            container.container_len() % (decomp_level_count.0 * output_lwe_size.0) == 0,
            "The provided container length is not valid. \
        It needs to be dividable by decomp_level_count * output_lwe_size: {}. \
        Got container length: {} and decomp_level_count: {decomp_level_count:?}, \
        output_lwe_size: {output_lwe_size:?}.",
            decomp_level_count.0 * output_lwe_size.0,
            container.container_len()
        );

        LweKeyswitchKey {
            data: container,
            decomp_base_log,
            decomp_level_count,
            output_lwe_size,
        }
    }

    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.decomp_base_log
    }

    pub fn decomposition_levels_count(&self) -> DecompositionLevelCount {
        self.decomp_level_count
    }

    pub fn input_key_lwe_dimension(&self) -> LweDimension {
        LweDimension(self.data.container_len() / self.input_key_element_encrypted_size())
    }

    pub fn output_key_lwe_dimension(&self) -> LweDimension {
        self.output_lwe_size.to_lwe_dimension()
    }

    pub fn output_lwe_size(&self) -> LweSize {
        self.output_lwe_size
    }

    pub fn input_key_element_encrypted_size(&self) -> usize {
        lwe_keyswitch_key_input_key_element_encrypted_size(
            self.decomp_level_count,
            self.output_lwe_size,
        )
    }

    pub fn as_view(&self) -> LweKeyswitchKey<&'_ [Scalar]> {
        LweKeyswitchKey::from_container(
            self.as_ref(),
            self.decomp_base_log,
            self.decomp_level_count,
            self.output_lwe_size,
        )
    }

    /// Consume the entity and return its underlying container.
    pub fn into_container(self) -> C {
        self.data
    }
}

impl<Scalar, C: ContainerMut<Element = Scalar>> LweKeyswitchKey<C> {
    pub fn as_mut_view(&mut self) -> LweKeyswitchKey<&'_ mut [Scalar]> {
        let decomp_base_log = self.decomp_base_log;
        let decomp_level_count = self.decomp_level_count;
        let output_lwe_size = self.output_lwe_size;
        LweKeyswitchKey::from_container(
            self.as_mut(),
            decomp_base_log,
            decomp_level_count,
            output_lwe_size,
        )
    }
}

pub type LweKeyswitchKeyOwned<Scalar> = LweKeyswitchKey<Vec<Scalar>>;

impl<Scalar: Copy> LweKeyswitchKeyOwned<Scalar> {
    pub fn new(
        fill_with: Scalar,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        input_key_lwe_dimension: LweDimension,
        output_key_lwe_dimension: LweDimension,
    ) -> LweKeyswitchKeyOwned<Scalar> {
        LweKeyswitchKeyOwned::from_container(
            vec![
                fill_with;
                input_key_lwe_dimension.0
                    * lwe_keyswitch_key_input_key_element_encrypted_size(
                        decomp_level_count,
                        output_key_lwe_dimension.to_lwe_size()
                    )
            ],
            decomp_base_log,
            decomp_level_count,
            output_key_lwe_dimension.to_lwe_size(),
        )
    }
}

impl<C: Container> ContiguousEntityContainer for LweKeyswitchKey<C> {
    type Element = C::Element;

    type EntityViewMetadata = LweCiphertextListCreationMetadata;

    type EntityView<'this> = LweCiphertextListView<'this, Self::Element>
    where
        Self: 'this;

    type SelfViewMetadata = ();

    // At the moment it does not make sense to return "sub" keyswitch keys. So we use a dummy
    // placeholder type here.
    type SelfView<'this> = DummyCreateFrom
    where
        Self: 'this;

    fn get_entity_view_creation_metadata(&self) -> LweCiphertextListCreationMetadata {
        LweCiphertextListCreationMetadata(self.output_lwe_size())
    }

    fn get_entity_view_pod_size(&self) -> usize {
        self.input_key_element_encrypted_size()
    }

    /// Unimplemented for [`LweKeyswitchKey`]. At the moment it does not make sense to
    /// return "sub" keyswitch keys.
    fn get_self_view_creation_metadata(&self) {
        unimplemented!(
            "This function is not supported for LweKeyswitchKey. \
        At the moment it does not make sense to return 'sub' keyswitch keys."
        )
    }
}

impl<C: ContainerMut> ContiguousEntityContainerMut for LweKeyswitchKey<C> {
    type EntityMutView<'this> = LweCiphertextListMutView<'this, Self::Element>
    where
        Self: 'this;

    // At the moment it does not make sense to return "sub" keyswitch keys. So we use a dummy
    // placeholder type here.
    type SelfMutView<'this> = DummyCreateFrom
    where
        Self: 'this;
}
