use crate::integer::U256;
use crate::typed_api::integers::client_key::GenericIntegerClientKey;
use crate::typed_api::integers::parameters::IntegerParameter;
use crate::typed_api::integers::server_key::RadixCiphertextDyn;
use crate::typed_api::integers::types::base::GenericInteger;
use crate::typed_api::internal_traits::EncryptionKey;
use crate::typed_api::keys::RefKeyFromKeyChain;
use crate::typed_api::traits::FheTryEncrypt;
use crate::typed_api::ClientKey;

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub(in crate::typed_api::integers) enum CompressedRadixCiphertextDyn {
    Big(crate::integer::CompressedRadixCiphertextBig),
    Small(crate::integer::CompressedRadixCiphertextSmall),
}

impl From<CompressedRadixCiphertextDyn> for RadixCiphertextDyn {
    fn from(value: CompressedRadixCiphertextDyn) -> Self {
        match value {
            CompressedRadixCiphertextDyn::Big(ct) => RadixCiphertextDyn::Big(ct.into()),
            CompressedRadixCiphertextDyn::Small(ct) => RadixCiphertextDyn::Small(ct.into()),
        }
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct CompressedGenericInteger<P>
where
    P: IntegerParameter,
{
    pub(in crate::typed_api::integers) ciphertext: CompressedRadixCiphertextDyn,
    pub(in crate::typed_api::integers) id: P::Id,
}

impl<P> CompressedGenericInteger<P>
where
    P: IntegerParameter,
{
    pub(in crate::typed_api::integers) fn new(
        inner: CompressedRadixCiphertextDyn,
        id: P::Id,
    ) -> Self {
        Self {
            ciphertext: inner,
            id,
        }
    }
}

impl<P> From<CompressedGenericInteger<P>> for GenericInteger<P>
where
    P: IntegerParameter<InnerCiphertext = RadixCiphertextDyn>,
{
    fn from(value: CompressedGenericInteger<P>) -> Self {
        let inner = value.ciphertext.into();
        Self::new(inner, value.id)
    }
}

impl EncryptionKey<U256, CompressedRadixCiphertextDyn>
    for crate::typed_api::integers::client_key::RadixClientKey
{
    fn encrypt(&self, value: U256) -> CompressedRadixCiphertextDyn {
        match self.pbs_order {
            crate::shortint::PBSOrder::KeyswitchBootstrap => CompressedRadixCiphertextDyn::Big(
                self.inner
                    .as_ref()
                    .encrypt_radix_compressed(value, self.inner.num_blocks()),
            ),
            crate::shortint::PBSOrder::BootstrapKeyswitch => CompressedRadixCiphertextDyn::Small(
                self.inner
                    .as_ref()
                    .encrypt_radix_compressed_small(value, self.inner.num_blocks()),
            ),
        }
    }
}

impl<P, T> FheTryEncrypt<T, ClientKey> for CompressedGenericInteger<P>
where
    T: Into<U256>,
    P: IntegerParameter,
    P::Id: Default + RefKeyFromKeyChain<Key = GenericIntegerClientKey<P>>,
    P::InnerClientKey: EncryptionKey<U256, CompressedRadixCiphertextDyn>,
{
    type Error = crate::typed_api::errors::Error;

    fn try_encrypt(value: T, key: &ClientKey) -> Result<Self, Self::Error> {
        let value = value.into();
        let id = P::Id::default();
        let key = id.ref_key(key)?;

        let inner = key.inner.encrypt(value);
        Ok(Self::new(inner, id))
    }
}
