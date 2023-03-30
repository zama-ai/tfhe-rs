use crate::typed_api::integers::client_key::GenericIntegerClientKey;

use crate::integer::{CrtCiphertext, CrtClientKey, U256};
use crate::typed_api::integers::client_key::RadixClientKey;
use crate::typed_api::internal_traits::{EncryptionKey, ParameterType};
use serde::{Deserialize, Serialize};

use super::parameters::IntegerParameter;
use super::server_key::RadixCiphertextDyn;

#[derive(Clone, Debug, Serialize, Deserialize)]
enum PublicKeyDyn {
    Big(crate::integer::PublicKeyBig),
    Small(crate::integer::PublicKeySmall),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RadixPublicKey {
    key: PublicKeyDyn,
    num_blocks: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CrtPublicKey {
    key: crate::integer::PublicKeyBig,
    moduli: Vec<u64>,
}

pub trait IntegerPublicKey {
    type ClientKey;

    fn new(client_key: &Self::ClientKey) -> Self;
}

impl IntegerPublicKey for RadixPublicKey {
    type ClientKey = RadixClientKey;

    fn new(client_key: &Self::ClientKey) -> Self {
        let key = match client_key.pbs_order {
            crate::shortint::PBSOrder::KeyswitchBootstrap => {
                PublicKeyDyn::Big(crate::integer::PublicKeyBig::new(client_key.inner.as_ref()))
            }
            crate::shortint::PBSOrder::BootstrapKeyswitch => PublicKeyDyn::Small(
                crate::integer::PublicKeySmall::new(client_key.inner.as_ref()),
            ),
        };

        Self {
            key,
            num_blocks: client_key.inner.num_blocks(),
        }
    }
}

impl EncryptionKey<u64, RadixCiphertextDyn> for RadixPublicKey {
    fn encrypt(&self, value: u64) -> RadixCiphertextDyn {
        match &self.key {
            PublicKeyDyn::Big(key) => {
                RadixCiphertextDyn::Big(key.encrypt_radix(value, self.num_blocks))
            }
            PublicKeyDyn::Small(key) => {
                RadixCiphertextDyn::Small(key.encrypt_radix(value, self.num_blocks))
            }
        }
    }
}

impl EncryptionKey<U256, RadixCiphertextDyn> for RadixPublicKey {
    fn encrypt(&self, value: U256) -> RadixCiphertextDyn {
        match &self.key {
            PublicKeyDyn::Big(key) => {
                RadixCiphertextDyn::Big(key.encrypt_radix(value, self.num_blocks))
            }
            PublicKeyDyn::Small(key) => {
                RadixCiphertextDyn::Small(key.encrypt_radix(value, self.num_blocks))
            }
        }
    }
}

impl IntegerPublicKey for CrtPublicKey {
    type ClientKey = CrtClientKey;

    fn new(client_key: &Self::ClientKey) -> Self {
        Self {
            key: crate::integer::PublicKeyBig::new(client_key.as_ref()),
            moduli: client_key.moduli().to_vec(),
        }
    }
}

impl EncryptionKey<u64, CrtCiphertext> for CrtPublicKey {
    fn encrypt(&self, value: u64) -> CrtCiphertext {
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
