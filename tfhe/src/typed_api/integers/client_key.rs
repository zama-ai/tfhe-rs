use serde::{Deserialize, Serialize};

use crate::integer::{CrtCiphertext, CrtClientKey, U256};
use crate::typed_api::integers::parameters::{IntegerParameter, RadixParameters};
use crate::typed_api::internal_traits::{DecryptionKey, EncryptionKey, FromParameters};

use super::server_key::RadixCiphertextDyn;

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct RadixClientKey {
    pub(in crate::typed_api::integers) inner: crate::integer::RadixClientKey,
    // To know if we have to encrypt into a big or small ciphertext
    pub(in crate::typed_api::integers) pbs_order: crate::shortint::PBSOrder,
}

// This is needed by the impl EvaluationKey
impl AsRef<crate::integer::ClientKey> for RadixClientKey {
    fn as_ref(&self) -> &crate::integer::ClientKey {
        self.inner.as_ref()
    }
}

impl<P> FromParameters<P> for RadixClientKey
where
    P: Into<RadixParameters>,
{
    fn from_parameters(parameters: P) -> Self {
        let params = parameters.into();
        #[cfg(feature = "internal-keycache")]
        {
            use crate::integer::keycache::KEY_CACHE;
            let key = KEY_CACHE.get_from_params(params.block_parameters).0;
            let inner = crate::integer::RadixClientKey::from((key, params.num_block));
            Self {
                inner,
                pbs_order: params.pbs_order,
            }
        }
        #[cfg(not(feature = "internal-keycache"))]
        {
            let inner =
                crate::integer::RadixClientKey::new(params.block_parameters, params.num_block);
            Self {
                inner,
                pbs_order: params.pbs_order,
            }
        }
    }
}

impl EncryptionKey<u64, RadixCiphertextDyn> for RadixClientKey {
    fn encrypt(&self, value: u64) -> RadixCiphertextDyn {
        match self.pbs_order {
            crate::shortint::PBSOrder::KeyswitchBootstrap => {
                RadixCiphertextDyn::Big(self.inner.encrypt(value))
            }
            crate::shortint::PBSOrder::BootstrapKeyswitch => RadixCiphertextDyn::Small(
                self.inner
                    .as_ref()
                    .encrypt_radix_small(value, self.inner.num_blocks()),
            ),
        }
    }
}

impl EncryptionKey<U256, RadixCiphertextDyn> for RadixClientKey {
    fn encrypt(&self, value: U256) -> RadixCiphertextDyn {
        match self.pbs_order {
            crate::shortint::PBSOrder::KeyswitchBootstrap => RadixCiphertextDyn::Big(
                self.inner
                    .as_ref()
                    .encrypt_radix(value, self.inner.num_blocks()),
            ),
            crate::shortint::PBSOrder::BootstrapKeyswitch => RadixCiphertextDyn::Small(
                self.inner
                    .as_ref()
                    .encrypt_radix_small(value, self.inner.num_blocks()),
            ),
        }
    }
}

impl DecryptionKey<RadixCiphertextDyn, u64> for RadixClientKey {
    fn decrypt(&self, ciphertext: &RadixCiphertextDyn) -> u64 {
        match ciphertext {
            RadixCiphertextDyn::Big(ct) => self.inner.decrypt(ct),
            RadixCiphertextDyn::Small(ct) => self.inner.decrypt(ct),
        }
    }
}

impl DecryptionKey<RadixCiphertextDyn, U256> for RadixClientKey {
    fn decrypt(&self, ciphertext: &RadixCiphertextDyn) -> U256 {
        match ciphertext {
            RadixCiphertextDyn::Big(ct) => self.inner.decrypt(ct),
            RadixCiphertextDyn::Small(ct) => self.inner.decrypt(ct),
        }
    }
}

impl EncryptionKey<u64, CrtCiphertext> for CrtClientKey {
    fn encrypt(&self, value: u64) -> CrtCiphertext {
        self.encrypt(value)
    }
}

impl DecryptionKey<CrtCiphertext, u64> for CrtClientKey {
    fn decrypt(&self, ciphertext: &CrtCiphertext) -> u64 {
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
