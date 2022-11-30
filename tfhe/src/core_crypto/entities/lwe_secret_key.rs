use crate::core_crypto::commons::traits::*;
use crate::core_crypto::prelude::LweDimension;

#[derive(Clone, Debug, PartialEq)]
pub struct LweSecretKeyBase<C: Container> {
    data: C,
}

impl<T, C: Container<Element = T>> AsRef<[T]> for LweSecretKeyBase<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T, C: ContainerMut<Element = T>> AsMut<[T]> for LweSecretKeyBase<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

impl<Scalar, C: Container<Element = Scalar>> LweSecretKeyBase<C> {
    pub fn from_container(container: C) -> Self {
        assert!(
            container.container_len() > 0,
            "Got an empty container to create an LweSecretKey"
        );
        LweSecretKeyBase { data: container }
    }

    pub fn lwe_dimension(&self) -> LweDimension {
        LweDimension(self.data.container_len())
    }

    pub fn into_container(self) -> C {
        self.data
    }
}

pub type LweSecretKey<Scalar> = LweSecretKeyBase<Vec<Scalar>>;

impl<Scalar> LweSecretKey<Scalar>
where
    Scalar: Copy,
{
    pub fn new(fill_with: Scalar, lwe_dimension: LweDimension) -> LweSecretKey<Scalar> {
        LweSecretKey::from_container(vec![fill_with; lwe_dimension.0])
    }
}

// TODO REFACTOR
// Remove the back and forth conversions
impl From<LweSecretKey<u64>> for crate::core_crypto::prelude::LweSecretKey64 {
    fn from(new_lwe_secret_key: LweSecretKey<u64>) -> Self {
        use crate::core_crypto::commons::crypto::secret::LweSecretKey as PrivateLweSecretKey;
        use crate::core_crypto::prelude::LweSecretKey64;
        LweSecretKey64(PrivateLweSecretKey::binary_from_container(
            new_lwe_secret_key.data,
        ))
    }
}

impl From<crate::core_crypto::prelude::LweSecretKey64> for LweSecretKey<u64> {
    fn from(old_lwe_secret_key: crate::core_crypto::prelude::LweSecretKey64) -> Self {
        LweSecretKey::<u64>::from_container(old_lwe_secret_key.0.tensor.into_container())
    }
}
