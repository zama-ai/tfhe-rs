use crate::core_crypto::commons::traits::Container;
use crate::core_crypto::entities::LweSecretKey;
use crate::shortint::parameters::{CarryModulus, MessageModulus};

#[derive(Clone)]
pub struct SecretEncryptionKey<KeyCont: Container<Element = u64>> {
    pub(crate) lwe_secret_key: LweSecretKey<KeyCont>,
    pub(crate) message_modulus: MessageModulus,
    pub(crate) carry_modulus: CarryModulus,
}
