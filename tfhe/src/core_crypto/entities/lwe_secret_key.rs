use crate::core_crypto::commons::parameters::LweDimension;
use crate::core_crypto::commons::traits::*;

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct LweSecretKey<C: Container> {
    data: C,
}

impl<T, C: Container<Element = T>> AsRef<[T]> for LweSecretKey<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T, C: ContainerMut<Element = T>> AsMut<[T]> for LweSecretKey<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

impl<Scalar, C: Container<Element = Scalar>> LweSecretKey<C> {
    pub fn from_container(container: C) -> Self {
        assert!(
            container.container_len() > 0,
            "Got an empty container to create an LweSecretKey"
        );
        LweSecretKey { data: container }
    }

    pub fn lwe_dimension(&self) -> LweDimension {
        LweDimension(self.data.container_len())
    }

    pub fn into_container(self) -> C {
        self.data
    }
}

pub type LweSecretKeyOwned<Scalar> = LweSecretKey<Vec<Scalar>>;

impl<Scalar> LweSecretKeyOwned<Scalar>
where
    Scalar: Copy,
{
    pub fn new(fill_with: Scalar, lwe_dimension: LweDimension) -> LweSecretKeyOwned<Scalar> {
        LweSecretKeyOwned::from_container(vec![fill_with; lwe_dimension.0])
    }
}
