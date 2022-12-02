use crate::core_crypto::commons::traits::*;
use crate::core_crypto::prelude::LweDimension;

#[derive(Clone, Debug, PartialEq)]
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

// TODO REFACTOR
// Remove the back and forth conversions
impl From<LweSecretKeyOwned<u64>> for crate::core_crypto::prelude::LweSecretKey64 {
    fn from(new_lwe_secret_key: LweSecretKeyOwned<u64>) -> Self {
        use crate::core_crypto::commons::crypto::secret::LweSecretKey as PrivateLweSecretKey;
        use crate::core_crypto::prelude::LweSecretKey64;
        LweSecretKey64(PrivateLweSecretKey::binary_from_container(
            new_lwe_secret_key.data,
        ))
    }
}

impl From<crate::core_crypto::prelude::LweSecretKey64> for LweSecretKeyOwned<u64> {
    fn from(old_lwe_secret_key: crate::core_crypto::prelude::LweSecretKey64) -> Self {
        LweSecretKeyOwned::<u64>::from_container(old_lwe_secret_key.0.tensor.into_container())
    }
}
