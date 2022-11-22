use crate::core_crypto::commons::traits::*;
use crate::core_crypto::specification::parameters::{LweDimension, LweSize};

pub struct LweBody<T>(pub T);
pub struct LweMask<C: Container> {
    data: C,
}

impl<C: Container> LweMask<C> {
    pub fn from_container(container: C) -> Self {
        LweMask { data: container }
    }

    pub fn lwe_dimension(&self) -> LweDimension {
        LweDimension(self.data.container_len())
    }
}

impl<T, C: Container<Element = T>> AsRef<[T]> for LweMask<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T, C: ContainerMut<Element = T>> AsMut<[T]> for LweMask<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct LweCiphertextBase<C: Container> {
    data: C,
}

impl<T, C: Container<Element = T>> AsRef<[T]> for LweCiphertextBase<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T, C: ContainerMut<Element = T>> AsMut<[T]> for LweCiphertextBase<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

impl<Scalar, C: Container<Element = Scalar>> LweCiphertextBase<C> {
    pub fn from_container(container: C) -> LweCiphertextBase<C> {
        assert!(
            container.container_len() > 0,
            "Got an empty container to create an LweCiphertext"
        );
        LweCiphertextBase { data: container }
    }

    pub fn lwe_size(&self) -> LweSize {
        LweSize(self.data.container_len())
    }

    pub fn get_mask_and_body(&self) -> (LweMask<&[Scalar]>, LweBody<&Scalar>) {
        let (body, mask) = self.data.as_ref().split_last().unwrap();

        (LweMask::from_container(mask), LweBody(body))
    }

    pub fn get_body(&self) -> LweBody<&Scalar> {
        let body = self.data.as_ref().last().unwrap();

        LweBody(body)
    }
}

impl<Scalar, C: ContainerMut<Element = Scalar>> LweCiphertextBase<C> {
    pub fn get_mut_mask_and_body(&mut self) -> (LweMask<&mut [Scalar]>, LweBody<&mut Scalar>) {
        let (body, mask) = self.data.as_mut().split_last_mut().unwrap();

        (LweMask::from_container(mask), LweBody(body))
    }

    pub fn get_mut_body(&mut self) -> LweBody<&mut Scalar> {
        let body = self.data.as_mut().last_mut().unwrap();

        LweBody(body)
    }
}

pub type LweCiphertext<Scalar> = LweCiphertextBase<Vec<Scalar>>;
pub type LweCiphertextView<'data, Scalar> = LweCiphertextBase<&'data [Scalar]>;
pub type LweCiphertextMutView<'data, Scalar> = LweCiphertextBase<&'data mut [Scalar]>;

impl<Scalar: Copy> LweCiphertext<Scalar> {
    pub fn new(fill_with: Scalar, lwe_size: LweSize) -> LweCiphertext<Scalar> {
        LweCiphertext::from_container(vec![fill_with; lwe_size.0])
    }
}

#[derive(Clone, Copy)]
pub struct LweCiphertextCreationMetadata();

impl<C: Container> CreateFrom<C> for LweCiphertextBase<C> {
    type Metadata = LweCiphertextCreationMetadata;

    #[inline]
    fn create_from(from: C, _: Self::Metadata) -> LweCiphertextBase<C> {
        LweCiphertextBase::from_container(from)
    }
}

// TODO REFACTOR remove compat layer
// Remove the back and forth conversions
impl From<LweCiphertext<u64>> for crate::core_crypto::prelude::LweCiphertext64 {
    fn from(new_lwe_ciphertext: LweCiphertext<u64>) -> Self {
        use crate::core_crypto::commons::crypto::lwe::LweCiphertext as PrivateLweCiphertext;
        use crate::core_crypto::prelude::LweCiphertext64;
        LweCiphertext64(PrivateLweCiphertext::from_container(
            new_lwe_ciphertext.data,
        ))
    }
}

impl From<crate::core_crypto::prelude::LweCiphertext64> for LweCiphertext<u64> {
    fn from(old_lwe_ciphertext: crate::core_crypto::prelude::LweCiphertext64) -> Self {
        LweCiphertext::<u64>::from_container(old_lwe_ciphertext.0.tensor.into_container())
    }
}

impl crate::core_crypto::prelude::LweCiphertext64 {
    pub fn as_refactor_ct_view(&self) -> LweCiphertextView<'_, u64> {
        LweCiphertextView::from_container(self.0.as_view().into_container())
    }

    pub fn as_refactor_ct_mut_view(&mut self) -> LweCiphertextMutView<'_, u64> {
        LweCiphertextMutView::from_container(self.0.as_mut_view().into_container())
    }
}

impl<C: Container<Element = u64>> LweCiphertextBase<C> {
    pub fn as_old_ct_view(&self) -> crate::core_crypto::prelude::LweCiphertextView64 {
        use crate::core_crypto::commons::crypto::lwe::LweCiphertext as PrivateLweCiphertext;
        use crate::core_crypto::prelude::LweCiphertextView64;
        LweCiphertextView64(PrivateLweCiphertext::from_container(self.data.as_ref()))
    }
}

impl<C: ContainerMut<Element = u64>> LweCiphertextBase<C> {
    pub fn as_old_ct_mut_view(&mut self) -> crate::core_crypto::prelude::LweCiphertextMutView64 {
        use crate::core_crypto::commons::crypto::lwe::LweCiphertext as PrivateLweCiphertext;
        use crate::core_crypto::prelude::LweCiphertextMutView64;
        LweCiphertextMutView64(PrivateLweCiphertext::from_container(self.data.as_mut()))
    }
}
