use crate::core_crypto::commons::traits::Container;
use crate::shortint::client_key::secret_encryption_key::SecretEncryptionKey as ShortintSecretEncryptionKey;

#[derive(Clone)]
pub struct SecretEncryptionKey<KeyCont: Container<Element = u64>> {
    pub(crate) key: ShortintSecretEncryptionKey<KeyCont>,
}
