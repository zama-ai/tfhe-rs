use crate::core_crypto::entities::LweSecretKey;
use crate::shortint::parameters::{CarryModulus, MessageModulus};

#[derive(Clone)]
pub struct SecretEncryptionKeyView<'key> {
    pub(crate) lwe_secret_key: LweSecretKey<&'key [u64]>,
    pub(crate) message_modulus: MessageModulus,
    pub(crate) carry_modulus: CarryModulus,
}

impl<'key> From<&'key Self> for SecretEncryptionKeyView<'key> {
    fn from(value: &'key Self) -> Self {
        Self {
            lwe_secret_key: value.lwe_secret_key.as_view(),
            message_modulus: value.message_modulus,
            carry_modulus: value.carry_modulus,
        }
    }
}
