use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::specification::parameters::*;

#[derive(Clone, Copy, Debug)]
pub struct LwePrivateFunctionalPackingKeyswitchKeyListBase<C: Container> {
    data: C,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    input_lwe_size: LweSize,
    output_glwe_size: GlweSize,
    output_polynomial_size: PolynomialSize,
}

impl<T, C: Container<Element = T>> AsRef<[T]>
    for LwePrivateFunctionalPackingKeyswitchKeyListBase<C>
{
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T, C: ContainerMut<Element = T>> AsMut<[T]>
    for LwePrivateFunctionalPackingKeyswitchKeyListBase<C>
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

impl<Scalar, C: Container<Element = Scalar>> LwePrivateFunctionalPackingKeyswitchKeyListBase<C> {
    pub fn from_container(
        container: C,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        input_lwe_size: LweSize,
        output_glwe_size: GlweSize,
        output_polynomial_size: PolynomialSize,
    ) -> LwePrivateFunctionalPackingKeyswitchKeyListBase<C> {
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

        LwePrivateFunctionalPackingKeyswitchKeyListBase {
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

    pub fn as_view(&self) -> LwePrivateFunctionalPackingKeyswitchKeyListBase<&'_ [Scalar]> {
        LwePrivateFunctionalPackingKeyswitchKeyListBase::from_container(
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

impl<Scalar, C: ContainerMut<Element = Scalar>> LwePrivateFunctionalPackingKeyswitchKeyListBase<C> {
    pub fn as_mut_view(
        &mut self,
    ) -> LwePrivateFunctionalPackingKeyswitchKeyListBase<&'_ mut [Scalar]> {
        let decomp_base_log = self.decomp_base_log;
        let decomp_level_count = self.decomp_level_count;
        let input_lwe_size = self.input_lwe_size;
        let output_glwe_size = self.output_glwe_size;
        let output_polynomial_size = self.output_polynomial_size;

        LwePrivateFunctionalPackingKeyswitchKeyListBase::from_container(
            self.as_mut(),
            decomp_base_log,
            decomp_level_count,
            input_lwe_size,
            output_glwe_size,
            output_polynomial_size,
        )
    }
}

pub type LwePrivateFunctionalPackingKeyswitchKeyList<Scalar> =
    LwePrivateFunctionalPackingKeyswitchKeyListBase<Vec<Scalar>>;

impl<Scalar: Copy> LwePrivateFunctionalPackingKeyswitchKeyList<Scalar> {
    pub fn new(
        fill_with: Scalar,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        input_key_lwe_dimension: LweDimension,
        output_glwe_size: GlweSize,
        output_polynomial_size: PolynomialSize,
        pfpksk_count: FunctionalPackingKeyswitchKeyCount,
    ) -> LwePrivateFunctionalPackingKeyswitchKeyList<Scalar> {
        LwePrivateFunctionalPackingKeyswitchKeyList::from_container(
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

impl<C: Container> CreateFrom<C> for LwePrivateFunctionalPackingKeyswitchKeyListBase<C> {
    type Metadata = LwePrivateFunctionalPackingKeyswitchKeyListCreationMetadata;

    fn create_from(from: C, meta: Self::Metadata) -> Self {
        let LwePrivateFunctionalPackingKeyswitchKeyListCreationMetadata(
            decomp_base_log,
            decomp_level_count,
            input_lwe_size,
            output_glwe_size,
            output_polynomial_size,
        ) = meta;
        LwePrivateFunctionalPackingKeyswitchKeyListBase::from_container(
            from,
            decomp_base_log,
            decomp_level_count,
            input_lwe_size,
            output_glwe_size,
            output_polynomial_size,
        )
    }
}

impl<C: Container> ContiguousEntityContainer
    for LwePrivateFunctionalPackingKeyswitchKeyListBase<C>
{
    type Element = C::Element;

    type EntityViewMetadata = LwePrivateFunctionalPackingKeyswitchKeyCreationMetadata;

    type EntityView<'this> = LwePrivateFunctionalPackingKeyswitchKeyBase<&'this [Self::Element]>
    where
        Self: 'this;

    type SelfViewMetadata = LwePrivateFunctionalPackingKeyswitchKeyListCreationMetadata;

    type SelfView<'this> = LwePrivateFunctionalPackingKeyswitchKeyListBase<&'this [Self::Element]>
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
    for LwePrivateFunctionalPackingKeyswitchKeyListBase<C>
{
    type EntityMutView<'this> = LwePrivateFunctionalPackingKeyswitchKeyBase<&'this mut [Self::Element]>
    where
        Self: 'this;

    type SelfMutView<'this> = LwePrivateFunctionalPackingKeyswitchKeyListBase<&'this mut [Self::Element]>
    where
        Self: 'this;
}

// TODO REFACTOR
// Remove
impl From<LwePrivateFunctionalPackingKeyswitchKeyList<u64>>
    for crate::core_crypto::prelude::LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64
{
    fn from(new_key: LwePrivateFunctionalPackingKeyswitchKeyList<u64>) -> Self {
        use crate::core_crypto::commons::crypto::glwe::LwePrivateFunctionalPackingKeyswitchKeyList as PrivatePFPKSKList;
        use crate::core_crypto::prelude::LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64;

        let decomp_base_log = new_key.decomposition_base_log();
        let decomp_size = new_key.decomposition_level_count();
        let input_dimension = new_key.input_lwe_key_dimension();
        let output_glwe_dimension = new_key.output_glwe_key_dimension();
        let output_polynomial_size = new_key.output_polynomial_size();
        let fpksk_count = new_key.lwe_pfpksk_count();

        LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64(
            PrivatePFPKSKList::from_container(
                new_key.into_container(),
                decomp_base_log,
                decomp_size,
                input_dimension,
                output_glwe_dimension,
                output_polynomial_size,
                fpksk_count,
            ),
        )
    }
}

impl From<crate::core_crypto::prelude::LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64>
    for LwePrivateFunctionalPackingKeyswitchKeyList<u64>
{
    fn from(
        old_key: crate::core_crypto::prelude::LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64,
    ) -> Self {
        let decomp_base_log = old_key.0.decomposition_base_log();
        let decomp_size = old_key.0.decomposition_level_count();
        let input_dimension = old_key.0.input_lwe_key_dimension();
        let output_glwe_dimension = old_key.0.output_glwe_key_dimension();
        let output_polynomial_size = old_key.0.output_polynomial_size();

        LwePrivateFunctionalPackingKeyswitchKeyListBase::from_container(
            old_key.0.into_container(),
            decomp_base_log,
            decomp_size,
            input_dimension.to_lwe_size(),
            output_glwe_dimension.to_glwe_size(),
            output_polynomial_size,
        )
    }
}
