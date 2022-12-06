use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LwePrivateFunctionalPackingKeyswitchKeyList<C: Container> {
    data: C,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    input_lwe_size: LweSize,
    output_glwe_size: GlweSize,
    output_polynomial_size: PolynomialSize,
}

impl<T, C: Container<Element = T>> AsRef<[T]> for LwePrivateFunctionalPackingKeyswitchKeyList<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T, C: ContainerMut<Element = T>> AsMut<[T]>
    for LwePrivateFunctionalPackingKeyswitchKeyList<C>
{
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
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

impl<Scalar, C: Container<Element = Scalar>> LwePrivateFunctionalPackingKeyswitchKeyList<C> {
    pub fn from_container(
        container: C,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        input_lwe_size: LweSize,
        output_glwe_size: GlweSize,
        output_polynomial_size: PolynomialSize,
    ) -> LwePrivateFunctionalPackingKeyswitchKeyList<C> {
        assert!(
            container.container_len()
                % lwe_pfpksk_size(
                    input_lwe_size,
                    decomp_level_count,
                    output_glwe_size,
                    output_polynomial_size
                )
                == 0,
            "The provided container length is not valid. \
        It needs to be dividable by input_lwe_size * decomp_level_count * output_glwe_size * \
        output_polynomial_size: {}. Got container length: {} and input_lwe_size: {input_lwe_size:?}\
         decomp_level_count: {decomp_level_count:?},  output_glwe_size: {output_glwe_size:?}, \
        output_polynomial_size: {output_polynomial_size:?}.",
            lwe_pfpksk_size(
                input_lwe_size,
                decomp_level_count,
                output_glwe_size,
                output_polynomial_size
            ),
            container.container_len()
        );

        LwePrivateFunctionalPackingKeyswitchKeyList {
            data: container,
            decomp_base_log,
            decomp_level_count,
            input_lwe_size,
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
        self.input_lwe_size.to_lwe_dimension()
    }

    pub fn input_lwe_size(&self) -> LweSize {
        self.input_lwe_size
    }

    pub fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.decomp_level_count
    }

    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.decomp_base_log
    }

    pub fn lwe_pfpksk_size(&self) -> usize {
        lwe_pfpksk_size(
            self.input_lwe_size,
            self.decomp_level_count,
            self.output_glwe_size,
            self.output_polynomial_size,
        )
    }

    pub fn lwe_pfpksk_count(&self) -> FunctionalPackingKeyswitchKeyCount {
        FunctionalPackingKeyswitchKeyCount(self.as_ref().container_len() / self.lwe_pfpksk_size())
    }

    pub fn as_view(&self) -> LwePrivateFunctionalPackingKeyswitchKeyList<&'_ [Scalar]> {
        LwePrivateFunctionalPackingKeyswitchKeyList::from_container(
            self.as_ref(),
            self.decomp_base_log,
            self.decomp_level_count,
            self.input_lwe_size,
            self.output_glwe_size,
            self.output_polynomial_size,
        )
    }

    pub fn into_container(self) -> C {
        self.data
    }
}

impl<Scalar, C: ContainerMut<Element = Scalar>> LwePrivateFunctionalPackingKeyswitchKeyList<C> {
    pub fn as_mut_view(&mut self) -> LwePrivateFunctionalPackingKeyswitchKeyList<&'_ mut [Scalar]> {
        let decomp_base_log = self.decomp_base_log;
        let decomp_level_count = self.decomp_level_count;
        let input_lwe_size = self.input_lwe_size;
        let output_glwe_size = self.output_glwe_size;
        let output_polynomial_size = self.output_polynomial_size;

        LwePrivateFunctionalPackingKeyswitchKeyList::from_container(
            self.as_mut(),
            decomp_base_log,
            decomp_level_count,
            input_lwe_size,
            output_glwe_size,
            output_polynomial_size,
        )
    }
}

pub type LwePrivateFunctionalPackingKeyswitchKeyListOwned<Scalar> =
    LwePrivateFunctionalPackingKeyswitchKeyList<Vec<Scalar>>;

impl<Scalar: Copy> LwePrivateFunctionalPackingKeyswitchKeyListOwned<Scalar> {
    pub fn new(
        fill_with: Scalar,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        input_key_lwe_dimension: LweDimension,
        output_glwe_size: GlweSize,
        output_polynomial_size: PolynomialSize,
        pfpksk_count: FunctionalPackingKeyswitchKeyCount,
    ) -> LwePrivateFunctionalPackingKeyswitchKeyListOwned<Scalar> {
        LwePrivateFunctionalPackingKeyswitchKeyListOwned::from_container(
            vec![
                fill_with;
                pfpksk_count.0
                    * lwe_pfpksk_size(
                        input_key_lwe_dimension.to_lwe_size(),
                        decomp_level_count,
                        output_glwe_size,
                        output_polynomial_size
                    )
            ],
            decomp_base_log,
            decomp_level_count,
            input_key_lwe_dimension.to_lwe_size(),
            output_glwe_size,
            output_polynomial_size,
        )
    }
}

#[derive(Clone, Copy)]
pub struct LwePrivateFunctionalPackingKeyswitchKeyListCreationMetadata(
    pub DecompositionBaseLog,
    pub DecompositionLevelCount,
    pub LweSize,
    pub GlweSize,
    pub PolynomialSize,
);

impl<C: Container> CreateFrom<C> for LwePrivateFunctionalPackingKeyswitchKeyList<C> {
    type Metadata = LwePrivateFunctionalPackingKeyswitchKeyListCreationMetadata;

    fn create_from(from: C, meta: Self::Metadata) -> Self {
        let LwePrivateFunctionalPackingKeyswitchKeyListCreationMetadata(
            decomp_base_log,
            decomp_level_count,
            input_lwe_size,
            output_glwe_size,
            output_polynomial_size,
        ) = meta;
        LwePrivateFunctionalPackingKeyswitchKeyList::from_container(
            from,
            decomp_base_log,
            decomp_level_count,
            input_lwe_size,
            output_glwe_size,
            output_polynomial_size,
        )
    }
}

impl<C: Container> ContiguousEntityContainer for LwePrivateFunctionalPackingKeyswitchKeyList<C> {
    type Element = C::Element;

    type EntityViewMetadata = LwePrivateFunctionalPackingKeyswitchKeyCreationMetadata;

    type EntityView<'this> = LwePrivateFunctionalPackingKeyswitchKey<&'this [Self::Element]>
    where
        Self: 'this;

    type SelfViewMetadata = LwePrivateFunctionalPackingKeyswitchKeyListCreationMetadata;

    type SelfView<'this> = LwePrivateFunctionalPackingKeyswitchKeyList<&'this [Self::Element]>
    where
        Self: 'this;

    fn get_entity_view_creation_metadata(&self) -> Self::EntityViewMetadata {
        LwePrivateFunctionalPackingKeyswitchKeyCreationMetadata(
            self.decomposition_base_log(),
            self.decomposition_level_count(),
            self.output_glwe_size(),
            self.output_polynomial_size(),
        )
    }

    fn get_entity_view_pod_size(&self) -> usize {
        self.lwe_pfpksk_size()
    }

    fn get_self_view_creation_metadata(&self) -> Self::SelfViewMetadata {
        LwePrivateFunctionalPackingKeyswitchKeyListCreationMetadata(
            self.decomposition_base_log(),
            self.decomposition_level_count(),
            self.input_lwe_size(),
            self.output_glwe_size(),
            self.output_polynomial_size(),
        )
    }
}

impl<C: ContainerMut> ContiguousEntityContainerMut
    for LwePrivateFunctionalPackingKeyswitchKeyList<C>
{
    type EntityMutView<'this> = LwePrivateFunctionalPackingKeyswitchKey<&'this mut [Self::Element]>
    where
        Self: 'this;

    type SelfMutView<'this> = LwePrivateFunctionalPackingKeyswitchKeyList<&'this mut [Self::Element]>
    where
        Self: 'this;
}
