use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LwePrivateFunctionalPackingKeyswitchKey<C: Container> {
    data: C,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    output_glwe_size: GlweSize,
    output_polynomial_size: PolynomialSize,
}

impl<T, C: Container<Element = T>> AsRef<[T]> for LwePrivateFunctionalPackingKeyswitchKey<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T, C: ContainerMut<Element = T>> AsMut<[T]> for LwePrivateFunctionalPackingKeyswitchKey<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

pub fn lwe_pfpksk_input_key_element_encrypted_size(
    decomp_level_count: DecompositionLevelCount,
    output_glwe_size: GlweSize,
    output_polynomial_size: PolynomialSize,
) -> usize {
    // One ciphertext per level encrypted under the output key
    decomp_level_count.0 * output_glwe_size.0 * output_polynomial_size.0
}

pub fn lwe_pfpksk_size(
    input_lwe_size: LweSize,
    decomp_level_count: DecompositionLevelCount,
    output_glwe_size: GlweSize,
    output_polynomial_size: PolynomialSize,
) -> usize {
    input_lwe_size.0
        * lwe_pfpksk_input_key_element_encrypted_size(
            decomp_level_count,
            output_glwe_size,
            output_polynomial_size,
        )
}

impl<Scalar, C: Container<Element = Scalar>> LwePrivateFunctionalPackingKeyswitchKey<C> {
    pub fn from_container(
        container: C,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        output_glwe_size: GlweSize,
        output_polynomial_size: PolynomialSize,
    ) -> LwePrivateFunctionalPackingKeyswitchKey<C> {
        assert!(
            container.container_len() > 0,
            "Got an empty container to create an LweKeyswitchKey"
        );
        assert!(
            container.container_len()
                % lwe_pfpksk_input_key_element_encrypted_size(
                    decomp_level_count,
                    output_glwe_size,
                    output_polynomial_size
                )
                == 0,
            "The provided container length is not valid. \
        It needs to be dividable by decomp_level_count * output_glwe_size * output_polynomial_size:\
         {}. Got container length: {} and decomp_level_count: {decomp_level_count:?}, \
        output_glwe_size: {output_glwe_size:?}, output_polynomial_size: \
        {output_polynomial_size:?}.",
            lwe_pfpksk_input_key_element_encrypted_size(
                decomp_level_count,
                output_glwe_size,
                output_polynomial_size
            ),
            container.container_len()
        );

        LwePrivateFunctionalPackingKeyswitchKey {
            data: container,
            decomp_base_log,
            decomp_level_count,
            output_glwe_size,
            output_polynomial_size,
        }
    }

    pub fn output_glwe_key_dimension(&self) -> GlweDimension {
        self.output_glwe_size.to_glwe_dimension()
    }

    pub fn output_glwe_size(&self) -> GlweSize {
        self.output_glwe_size
    }

    pub fn output_polynomial_size(&self) -> PolynomialSize {
        self.output_polynomial_size
    }

    pub fn input_lwe_key_dimension(&self) -> LweDimension {
        LweDimension(self.data.container_len() / self.input_key_element_encrypted_size() - 1)
    }

    pub fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.decomp_level_count
    }

    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.decomp_base_log
    }

    pub fn input_key_element_encrypted_size(&self) -> usize {
        lwe_pfpksk_input_key_element_encrypted_size(
            self.decomp_level_count,
            self.output_glwe_size,
            self.output_polynomial_size,
        )
    }

    pub fn as_view(&self) -> LwePrivateFunctionalPackingKeyswitchKey<&'_ [Scalar]> {
        LwePrivateFunctionalPackingKeyswitchKey::from_container(
            self.as_ref(),
            self.decomp_base_log,
            self.decomp_level_count,
            self.output_glwe_size,
            self.output_polynomial_size,
        )
    }

    /// Consume the entity and return its underlying container.
    pub fn into_container(self) -> C {
        self.data
    }
}

impl<Scalar, C: ContainerMut<Element = Scalar>> LwePrivateFunctionalPackingKeyswitchKey<C> {
    pub fn as_mut_view(&mut self) -> LwePrivateFunctionalPackingKeyswitchKey<&'_ mut [Scalar]> {
        let decomp_base_log = self.decomp_base_log;
        let decomp_level_count = self.decomp_level_count;
        let output_glwe_size = self.output_glwe_size;
        let output_polynomial_size = self.output_polynomial_size;

        LwePrivateFunctionalPackingKeyswitchKey::from_container(
            self.as_mut(),
            decomp_base_log,
            decomp_level_count,
            output_glwe_size,
            output_polynomial_size,
        )
    }
}

pub type LwePrivateFunctionalPackingKeyswitchKeyOwned<Scalar> =
    LwePrivateFunctionalPackingKeyswitchKey<Vec<Scalar>>;

impl<Scalar: Copy> LwePrivateFunctionalPackingKeyswitchKeyOwned<Scalar> {
    pub fn new(
        fill_with: Scalar,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        input_key_lwe_dimension: LweDimension,
        output_glwe_size: GlweSize,
        output_polynomial_size: PolynomialSize,
    ) -> LwePrivateFunctionalPackingKeyswitchKeyOwned<Scalar> {
        LwePrivateFunctionalPackingKeyswitchKeyOwned::from_container(
            vec![
                fill_with;
                lwe_pfpksk_size(
                    input_key_lwe_dimension.to_lwe_size(),
                    decomp_level_count,
                    output_glwe_size,
                    output_polynomial_size
                )
            ],
            decomp_base_log,
            decomp_level_count,
            output_glwe_size,
            output_polynomial_size,
        )
    }
}

impl<C: Container> ContiguousEntityContainer for LwePrivateFunctionalPackingKeyswitchKey<C> {
    type Element = C::Element;

    type EntityViewMetadata = GlweCiphertextListCreationMetadata;

    type EntityView<'this> = GlweCiphertextListView<'this, Self::Element>
    where
        Self: 'this;

    type SelfViewMetadata = ();

    // At the moment it does not make sense to return "sub" packing keyswitch keys. So we use a
    // dummy placeholder type here.
    type SelfView<'this> = DummyCreateFrom
    where
        Self: 'this;

    fn get_entity_view_creation_metadata(&self) -> Self::EntityViewMetadata {
        GlweCiphertextListCreationMetadata(self.output_glwe_size, self.output_polynomial_size)
    }

    fn get_entity_view_pod_size(&self) -> usize {
        self.input_key_element_encrypted_size()
    }

    /// Unimplemented for [`LwePrivateFunctionalPackingKeyswitchKey`]. At the moment it does not
    /// make sense to return "sub" packing keyswitch keys.
    fn get_self_view_creation_metadata(&self) -> Self::SelfViewMetadata {
        unimplemented!(
            "This function is not supported for LwePrivateFunctionalPackingKeyswitchKey. \
        At the moment it does not make sense to return 'sub' packing keyswitch keys."
        )
    }
}

impl<C: ContainerMut> ContiguousEntityContainerMut for LwePrivateFunctionalPackingKeyswitchKey<C> {
    type EntityMutView<'this> = GlweCiphertextListMutView<'this, Self::Element>
    where
        Self: 'this;

    // At the moment it does not make sense to return "sub" packing keyswitch keys. So we use a
    // dummy placeholder type here.
    type SelfMutView<'this> = DummyCreateFrom
    where
        Self: 'this;
}

#[derive(Clone, Copy)]
pub struct LwePrivateFunctionalPackingKeyswitchKeyCreationMetadata(
    pub DecompositionBaseLog,
    pub DecompositionLevelCount,
    pub GlweSize,
    pub PolynomialSize,
);

impl<C: Container> CreateFrom<C> for LwePrivateFunctionalPackingKeyswitchKey<C> {
    type Metadata = LwePrivateFunctionalPackingKeyswitchKeyCreationMetadata;

    #[inline]
    fn create_from(from: C, meta: Self::Metadata) -> LwePrivateFunctionalPackingKeyswitchKey<C> {
        let LwePrivateFunctionalPackingKeyswitchKeyCreationMetadata(
            decomp_base_log,
            decomp_level_count,
            output_glwe_size,
            output_polynomial_size,
        ) = meta;
        LwePrivateFunctionalPackingKeyswitchKey::from_container(
            from,
            decomp_base_log,
            decomp_level_count,
            output_glwe_size,
            output_polynomial_size,
        )
    }
}
