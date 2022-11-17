use crate::core_crypto::commons::traits::Container;
use crate::core_crypto::prelude::LweDimension;

pub struct LweSecretKeyBase<C: Container> {
    data: C,
}

impl<C: Container> LweSecretKeyBase<C> {
    pub fn from_container(container: C) -> Self {
        LweSecretKeyBase { data: container }
    }

    pub fn lwe_dimension(&self) -> LweDimension {
        LweDimension(self.data.container_len())
    }
}

pub type LweSecretKey<Scalar> = LweSecretKeyBase<Vec<Scalar>>;

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
