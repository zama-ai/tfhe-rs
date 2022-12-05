use crate::core_crypto::commons::traits::*;
use crate::core_crypto::specification::parameters::*;

#[derive(Clone, Debug)]
pub struct LweBody<T>(pub T);
#[derive(Clone, Debug)]
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

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct LweCiphertext<C: Container> {
    data: C,
}

impl<T, C: Container<Element = T>> AsRef<[T]> for LweCiphertext<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T, C: ContainerMut<Element = T>> AsMut<[T]> for LweCiphertext<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

impl<Scalar, C: Container<Element = Scalar>> LweCiphertext<C> {
    pub fn from_container(container: C) -> LweCiphertext<C> {
        assert!(
            container.container_len() > 0,
            "Got an empty container to create an LweCiphertext"
        );
        LweCiphertext { data: container }
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

    pub fn get_mask(&self) -> LweMask<&[Scalar]> {
        LweMask::from_container(&self.as_ref()[0..=self.lwe_size().to_lwe_dimension().0])
    }

    pub fn as_view(&self) -> LweCiphertextView<'_, Scalar> {
        LweCiphertextView::from_container(self.as_ref())
    }

    pub fn into_container(self) -> C {
        self.data
    }
}

impl<Scalar, C: ContainerMut<Element = Scalar>> LweCiphertext<C> {
    pub fn get_mut_mask_and_body(&mut self) -> (LweMask<&mut [Scalar]>, LweBody<&mut Scalar>) {
        let (body, mask) = self.data.as_mut().split_last_mut().unwrap();

        (LweMask::from_container(mask), LweBody(body))
    }

    pub fn get_mut_body(&mut self) -> LweBody<&mut Scalar> {
        let body = self.data.as_mut().last_mut().unwrap();

        LweBody(body)
    }

    pub fn get_mut_mask(&mut self) -> LweMask<&mut [Scalar]> {
        let lwe_dimension = self.lwe_size().to_lwe_dimension();
        LweMask::from_container(&mut self.as_mut()[0..=lwe_dimension.0])
    }

    pub fn as_mut_view(&mut self) -> LweCiphertextMutView<'_, Scalar> {
        LweCiphertextMutView::from_container(self.as_mut())
    }
}

pub type LweCiphertextOwned<Scalar> = LweCiphertext<Vec<Scalar>>;
pub type LweCiphertextView<'data, Scalar> = LweCiphertext<&'data [Scalar]>;
pub type LweCiphertextMutView<'data, Scalar> = LweCiphertext<&'data mut [Scalar]>;

impl<Scalar: Copy> LweCiphertextOwned<Scalar> {
    pub fn new(fill_with: Scalar, lwe_size: LweSize) -> LweCiphertextOwned<Scalar> {
        LweCiphertextOwned::from_container(vec![fill_with; lwe_size.0])
    }
}

#[derive(Clone, Copy)]
pub struct LweCiphertextCreationMetadata();

impl<C: Container> CreateFrom<C> for LweCiphertext<C> {
    type Metadata = LweCiphertextCreationMetadata;

    #[inline]
    fn create_from(from: C, _: Self::Metadata) -> LweCiphertext<C> {
        LweCiphertext::from_container(from)
    }
}
