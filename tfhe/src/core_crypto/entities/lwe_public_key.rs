use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

// An LwePublicKey is literally an LweCiphertextList, so we wrap an LweCiphertextList and use
// Deref to have access to all the primitives of the LweCiphertextList easily
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LwePublicKey<C: Container> {
    lwe_list: LweCiphertextList<C>,
}

impl<C: Container> std::ops::Deref for LwePublicKey<C> {
    type Target = LweCiphertextList<C>;

    fn deref(&self) -> &LweCiphertextList<C> {
        &self.lwe_list
    }
}

impl<C: ContainerMut> std::ops::DerefMut for LwePublicKey<C> {
    fn deref_mut(&mut self) -> &mut LweCiphertextList<C> {
        &mut self.lwe_list
    }
}

impl<Scalar, C: Container<Element = Scalar>> LwePublicKey<C> {
    pub fn from_container(container: C, lwe_size: LweSize) -> LwePublicKey<C> {
        assert!(
            container.container_len() > 0,
            "Got an empty container to create an LwePublicKey"
        );
        LwePublicKey {
            lwe_list: LweCiphertextList::from_container(container, lwe_size),
        }
    }

    pub fn zero_encryption_count(&self) -> LwePublicKeyZeroEncryptionCount {
        LwePublicKeyZeroEncryptionCount(self.lwe_ciphertext_count().0)
    }

    /// Consume the entity and return its underlying container.
    pub fn into_container(self) -> C {
        self.lwe_list.into_container()
    }

    pub fn as_view(&self) -> LwePublicKey<&'_ [Scalar]> {
        LwePublicKey::from_container(self.as_ref(), self.lwe_size())
    }
}

impl<Scalar, C: ContainerMut<Element = Scalar>> LwePublicKey<C> {
    pub fn as_mut_view(&mut self) -> LwePublicKey<&'_ mut [Scalar]> {
        let lwe_size = self.lwe_size();
        LwePublicKey::from_container(self.as_mut(), lwe_size)
    }
}

pub type LwePublicKeyOwned<Scalar> = LwePublicKey<Vec<Scalar>>;

impl<Scalar: Copy> LwePublicKeyOwned<Scalar> {
    pub fn new(
        fill_with: Scalar,
        lwe_size: LweSize,
        zero_encryption_count: LwePublicKeyZeroEncryptionCount,
    ) -> LwePublicKeyOwned<Scalar> {
        LwePublicKeyOwned::from_container(
            vec![fill_with; lwe_size.0 * zero_encryption_count.0],
            lwe_size,
        )
    }
}
