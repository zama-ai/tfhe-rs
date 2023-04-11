use crate::high_level_api::integers::client_key::GenericIntegerClientKey;

use crate::high_level_api::integers::client_key::RadixClientKey;
use crate::high_level_api::internal_traits::{EncryptionKey, ParameterType};
use crate::integer::{CrtCiphertext, CrtClientKey, U256};
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
    pub(in crate::high_level_api::integers) inner: P::InnerPublicKey,
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

pub(in crate::high_level_api::integers) mod compressed {
    use serde::{Deserialize, Serialize};

    use crate::high_level_api::integers::client_key::{GenericIntegerClientKey, RadixClientKey};
    use crate::high_level_api::integers::parameters::IntegerParameter;
    use crate::high_level_api::integers::server_key::RadixCiphertextDyn;
    use crate::high_level_api::internal_traits::EncryptionKey;
    use crate::integer::U256;

    use super::IntegerPublicKey;

    #[derive(Clone, Debug, Serialize, Deserialize)]
    enum CompressedPublicKeyDyn {
        Big(crate::integer::CompressedPublicKeyBig),
        Small(crate::integer::CompressedPublicKeySmall),
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct CompressedRadixPublicKey {
        key: CompressedPublicKeyDyn,
        num_blocks: usize,
    }

    impl IntegerPublicKey for CompressedRadixPublicKey {
        type ClientKey = RadixClientKey;

        fn new(client_key: &Self::ClientKey) -> Self {
            let key = match client_key.pbs_order {
                crate::shortint::PBSOrder::KeyswitchBootstrap => CompressedPublicKeyDyn::Big(
                    crate::integer::CompressedPublicKeyBig::new(client_key.inner.as_ref()),
                ),
                crate::shortint::PBSOrder::BootstrapKeyswitch => CompressedPublicKeyDyn::Small(
                    crate::integer::CompressedPublicKeySmall::new(client_key.inner.as_ref()),
                ),
            };

            Self {
                key,
                num_blocks: client_key.inner.num_blocks(),
            }
        }
    }

    impl EncryptionKey<U256, RadixCiphertextDyn> for CompressedRadixPublicKey {
        fn encrypt(&self, value: U256) -> RadixCiphertextDyn {
            match &self.key {
                CompressedPublicKeyDyn::Big(key) => {
                    RadixCiphertextDyn::Big(key.encrypt_radix(value, self.num_blocks))
                }
                CompressedPublicKeyDyn::Small(key) => {
                    RadixCiphertextDyn::Small(key.encrypt_radix(value, self.num_blocks))
                }
            }
        }
    }

    #[cfg_attr(all(doc, not(doctest)), cfg(feature = "integer"))]
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct GenericIntegerCompressedPublicKey<P>
    where
        P: IntegerParameter,
    {
        pub(in crate::high_level_api::integers) inner: CompressedRadixPublicKey,
        _marker: std::marker::PhantomData<P>,
    }

    impl<P> GenericIntegerCompressedPublicKey<P>
    where
        P: IntegerParameter<InnerClientKey = RadixClientKey>,
    {
        pub fn new(client_key: &GenericIntegerClientKey<P>) -> Self {
            let key = CompressedRadixPublicKey::new(&client_key.inner);
            Self {
                inner: key,
                _marker: Default::default(),
            }
        }
    }
}
