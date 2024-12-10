use crate::shortint::client_key::secret_encryption_key::SecretEncryptionKeyView as ShortintSecretEncryptionKey;

#[derive(Clone)]
pub struct SecretEncryptionKeyView<'key> {
    pub(crate) key: ShortintSecretEncryptionKey<'key>,
}
