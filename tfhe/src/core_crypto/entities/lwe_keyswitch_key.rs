use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::specification::parameters::*;

#[derive(Clone, Debug, PartialEq)]
pub struct LweKeyswitchKeyBase<C: Container> {
    data: C,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    output_lwe_size: LweSize,
}

impl<T, C: Container<Element = T>> AsRef<[T]> for LweKeyswitchKeyBase<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T, C: ContainerMut<Element = T>> AsMut<[T]> for LweKeyswitchKeyBase<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

pub fn lwe_keyswitch_key_input_key_element_encrypted_size(
    decomp_level_count: DecompositionLevelCount,
    output_lwe_size: LweSize,
) -> usize {
    decomp_level_count.0 * output_lwe_size.0
}

impl<Scalar, C: Container<Element = Scalar>> LweKeyswitchKeyBase<C> {
    pub fn from_container(
        container: C,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        output_lwe_size: LweSize,
    ) -> Self {
        assert!(
            container.container_len() > 0,
            "Got an empty container to create an LweSecretKey"
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

        LweKeyswitchKeyBase {
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
        // One ciphertext per level encrypted under the output key
        lwe_keyswitch_key_input_key_element_encrypted_size(
            self.decomp_level_count,
            self.output_lwe_size,
        )
    }

    pub fn as_view(&self) -> LweKeyswitchKeyBase<&'_ [Scalar]> {
        LweKeyswitchKeyBase::from_container(
            self.as_ref(),
            self.decomp_base_log,
            self.decomp_level_count,
            self.output_lwe_size,
        )
    }

    pub fn into_container(self) -> C {
        self.data
    }
}

impl<Scalar, C: ContainerMut<Element = Scalar>> LweKeyswitchKeyBase<C> {
    pub fn as_mut_view(&mut self) -> LweKeyswitchKeyBase<&'_ mut [Scalar]> {
        let decomp_base_log = self.decomp_base_log;
        let decomp_level_count = self.decomp_level_count;
        let output_lwe_size = self.output_lwe_size;
        LweKeyswitchKeyBase::from_container(
            self.as_mut(),
            decomp_base_log,
            decomp_level_count,
            output_lwe_size,
        )
    }
}

pub type LweKeyswitchKey<Scalar> = LweKeyswitchKeyBase<Vec<Scalar>>;

impl<Scalar: Copy> LweKeyswitchKey<Scalar> {
    pub fn new(
        fill_with: Scalar,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        input_key_lwe_dimension: LweDimension,
        output_key_lwe_dimension: LweDimension,
    ) -> LweKeyswitchKey<Scalar> {
        LweKeyswitchKey::from_container(
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

impl<C: Container> ContiguousEntityContainer for LweKeyswitchKeyBase<C> {
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

    /// Unimplement for [`LweKeyswitchKeyBase`]. At the moment it does not make sense to
    /// return "sub" keyswitch keys.
    fn get_self_view_creation_metadata(&self) {
        unimplemented!(
            "This function is not supported for LweKeyswitchKey. \
        At the moment it does not make sense to return 'sub' keyswitch keys."
        )
    }
}

impl<C: ContainerMut> ContiguousEntityContainerMut for LweKeyswitchKeyBase<C> {
    type EntityMutView<'this> = LweCiphertextListMutView<'this, Self::Element>
    where
        Self: 'this;

    // At the moment it does not make sense to return "sub" keyswitch keys. So we use a dummy
    // placeholder type here.
    type SelfMutView<'this> = DummyCreateFrom
    where
        Self: 'this;
}

// TODO REFACTOR
// Remove the back and forth conversions
impl From<LweKeyswitchKey<u64>> for crate::core_crypto::prelude::LweKeyswitchKey64 {
    fn from(new_lwe_keyswitch_key: LweKeyswitchKey<u64>) -> Self {
        use crate::core_crypto::commons::crypto::lwe::LweKeyswitchKey as PrivateLweKeyswitchKey;
        use crate::core_crypto::prelude::LweKeyswitchKey64;
        LweKeyswitchKey64(PrivateLweKeyswitchKey::from_container(
            new_lwe_keyswitch_key.data,
            new_lwe_keyswitch_key.decomp_base_log,
            new_lwe_keyswitch_key.decomp_level_count,
            new_lwe_keyswitch_key.output_lwe_size.to_lwe_dimension(),
        ))
    }
}

impl From<crate::core_crypto::prelude::LweKeyswitchKey64> for LweKeyswitchKey<u64> {
    fn from(old_lwe_keyswitch_key: crate::core_crypto::prelude::LweKeyswitchKey64) -> Self {
        use crate::core_crypto::commons::math::tensor::IntoTensor;
        let decomp_base_log = old_lwe_keyswitch_key.0.decomposition_base_log();
        let decomp_level_count = old_lwe_keyswitch_key.0.decomposition_levels_count();
        let output_lwe_size = old_lwe_keyswitch_key.0.after_key_size().to_lwe_size();
        LweKeyswitchKey::<u64>::from_container(
            old_lwe_keyswitch_key.0.into_tensor().into_container(),
            decomp_base_log,
            decomp_level_count,
            output_lwe_size,
        )
    }
}
