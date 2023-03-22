use crate::typed_api::integers::client_key::GenericIntegerClientKey;

use crate::integer::{CrtCiphertext, CrtClientKey, RadixCiphertext, RadixClientKey, U256};
use crate::typed_api::internal_traits::{EncryptionKey, ParameterType};
use serde::{Deserialize, Serialize};

use super::parameters::IntegerParameter;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RadixPublicKey {
    key: crate::integer::PublicKey,
    num_blocks: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CrtPublicKey {
    key: crate::integer::PublicKey,
    moduli: Vec<u64>,
}

pub trait IntegerPublicKey {
    type ClientKey;

    fn new(client_key: &Self::ClientKey) -> Self;
}

impl IntegerPublicKey for RadixPublicKey {
    type ClientKey = RadixClientKey;

    fn new(client_key: &Self::ClientKey) -> Self {
        Self {
            key: crate::integer::PublicKey::new(client_key.as_ref()),
            num_blocks: client_key.num_blocks(),
        }
    }
}

impl EncryptionKey<u64> for RadixPublicKey {
    type Ciphertext = RadixCiphertext;

    fn encrypt(&self, value: u64) -> Self::Ciphertext {
        self.key.encrypt_radix(value, self.num_blocks)
    }
}

impl EncryptionKey<U256> for RadixPublicKey {
    type Ciphertext = RadixCiphertext;

    fn encrypt(&self, value: U256) -> Self::Ciphertext {
        self.key.encrypt_radix(value, self.num_blocks)
    }
}

impl IntegerPublicKey for CrtPublicKey {
    type ClientKey = CrtClientKey;

    fn new(client_key: &Self::ClientKey) -> Self {
        Self {
            key: crate::integer::PublicKey::new(client_key.as_ref()),
            moduli: client_key.moduli().to_vec(),
        }
    }
}

impl EncryptionKey<u64> for CrtPublicKey {
    type Ciphertext = CrtCiphertext;

    fn encrypt(&self, value: u64) -> Self::Ciphertext {
        self.key.encrypt_crt(value, self.moduli.clone())
    }
}

#[cfg_attr(all(doc, not(doctest)), cfg(feature = "integer"))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenericIntegerPublicKey<P>
where
    P: IntegerParameter,
{
    pub(in crate::typed_api::integers) inner: P::InnerPublicKey,
    _marker: std::marker::PhantomData<P>,
}

impl<P> GenericIntegerPublicKey<P>
where
    P: IntegerParameter,
    <P as ParameterType>::InnerPublicKey: IntegerPublicKey<ClientKey = P::InnerClientKey>,
{
    pub fn new(client_key: &GenericIntegerClientKey<P>) -> Self {
        let key = <P as ParameterType>::InnerPublicKey::new(&client_key.inner);
        Self {
            inner: key,
            _marker: Default::default(),
        }
    }
}
