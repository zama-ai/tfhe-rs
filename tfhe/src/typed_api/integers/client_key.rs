use serde::{Deserialize, Serialize};

use crate::integer::{CrtCiphertext, CrtClientKey, RadixCiphertextBig, RadixClientKey, U256};
use crate::typed_api::integers::parameters::IntegerParameter;
use crate::typed_api::internal_traits::{DecryptionKey, EncryptionKey, FromParameters};

impl EncryptionKey<u64> for RadixClientKey {
    type Ciphertext = RadixCiphertextBig;

    fn encrypt(&self, value: u64) -> Self::Ciphertext {
        self.encrypt(value)
    }
}

impl EncryptionKey<U256> for RadixClientKey {
    type Ciphertext = RadixCiphertextBig;

    fn encrypt(&self, value: U256) -> Self::Ciphertext {
        self.as_ref().encrypt_radix(value, self.num_blocks())
    }
}

impl DecryptionKey<u64> for RadixClientKey {
    type Ciphertext = RadixCiphertextBig;

    fn decrypt(&self, ciphertext: &Self::Ciphertext) -> u64 {
        self.decrypt(ciphertext)
    }
}

impl DecryptionKey<U256> for RadixClientKey {
    type Ciphertext = RadixCiphertextBig;

    fn decrypt(&self, ciphertext: &Self::Ciphertext) -> U256 {
        let mut r = U256::default();
        self.as_ref().decrypt_radix_into(ciphertext, &mut r);
        r
    }
}

impl EncryptionKey<u64> for CrtClientKey {
    type Ciphertext = CrtCiphertext;

    fn encrypt(&self, value: u64) -> Self::Ciphertext {
        self.encrypt(value)
    }
}

impl DecryptionKey<u64> for CrtClientKey {
    type Ciphertext = CrtCiphertext;

    fn decrypt(&self, ciphertext: &Self::Ciphertext) -> u64 {
        self.decrypt(ciphertext)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenericIntegerClientKey<P: IntegerParameter> {
    pub(in crate::typed_api::integers) inner: P::InnerClientKey,
    pub(in crate::typed_api::integers) params: P,
}

impl<P> From<P> for GenericIntegerClientKey<P>
where
    P: IntegerParameter,
    P::InnerClientKey: FromParameters<P>,
{
    fn from(params: P) -> Self {
        let key = P::InnerClientKey::from_parameters(params.clone());
        Self { inner: key, params }
    }
}
