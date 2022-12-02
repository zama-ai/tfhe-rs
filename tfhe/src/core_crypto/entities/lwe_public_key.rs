use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::specification::parameters::*;

// An LwePublicKey is literally an LweCiphertextList, so we wrap an LweCiphertextList and use
// Deref to have access to all the primitives of the LweCiphertextList easily
#[derive(Clone, Debug, PartialEq)]
pub struct LwePublicKeyBase<C: Container> {
    lwe_list: LweCiphertextListBase<C>,
}

impl<C: Container> std::ops::Deref for LwePublicKeyBase<C> {
    type Target = LweCiphertextListBase<C>;

    fn deref(&self) -> &LweCiphertextListBase<C> {
        &self.lwe_list
    }
}

impl<C: ContainerMut> std::ops::DerefMut for LwePublicKeyBase<C> {
    fn deref_mut(&mut self) -> &mut LweCiphertextListBase<C> {
        &mut self.lwe_list
    }
}

impl<Scalar, C: Container<Element = Scalar>> LwePublicKeyBase<C> {
    pub fn from_container(container: C, lwe_size: LweSize) -> LwePublicKeyBase<C> {
        assert!(
            container.container_len() > 0,
            "Got an empty container to create an LwePublicKey"
        );
        LwePublicKeyBase {
            lwe_list: LweCiphertextListBase::from_container(container, lwe_size),
        }
    }

    pub fn zero_encryption_count(&self) -> LwePublicKeyZeroEncryptionCount {
        LwePublicKeyZeroEncryptionCount(self.lwe_ciphertext_count().0)
    }

    pub fn into_container(self) -> C {
        self.lwe_list.into_container()
    }

    pub fn as_view(&self) -> LwePublicKeyBase<&'_ [Scalar]> {
        LwePublicKeyBase::from_container(self.as_ref(), self.lwe_size())
    }
}

impl<Scalar, C: ContainerMut<Element = Scalar>> LwePublicKeyBase<C> {
    pub fn as_mut_view(&mut self) -> LwePublicKeyBase<&'_ mut [Scalar]> {
        let lwe_size = self.lwe_size();
        LwePublicKeyBase::from_container(self.as_mut(), lwe_size)
    }
}

pub type LwePublicKey<Scalar> = LwePublicKeyBase<Vec<Scalar>>;

impl<Scalar: Copy> LwePublicKey<Scalar> {
    pub fn new(
        fill_with: Scalar,
        lwe_size: LweSize,
        zero_encryption_count: LwePublicKeyZeroEncryptionCount,
    ) -> LwePublicKey<Scalar> {
        LwePublicKey::from_container(
            vec![fill_with; lwe_size.0 * zero_encryption_count.0],
            lwe_size,
        )
    }
}

impl From<LwePublicKey<u64>> for crate::core_crypto::prelude::LwePublicKey64 {
    fn from(new_key: LwePublicKey<u64>) -> Self {
        use crate::core_crypto::commons::crypto::lwe::LweList as ImpLwePublicKey;
        use crate::core_crypto::prelude::LwePublicKey64;

        let lwe_size = new_key.lwe_size();
        LwePublicKey64(ImpLwePublicKey::from_container(
            new_key.into_container(),
            lwe_size,
        ))
    }
}

impl From<crate::core_crypto::prelude::LwePublicKey64> for LwePublicKey<u64> {
    fn from(old_key: crate::core_crypto::prelude::LwePublicKey64) -> Self {
        let lwe_size = old_key.0.lwe_size();
        LwePublicKey::from_container(old_key.0.into_container(), lwe_size)
    }
}
