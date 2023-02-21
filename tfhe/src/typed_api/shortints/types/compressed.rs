use crate::shortint::CompressedCiphertextBig as ShortintCompressedCiphertext;
use crate::typed_api::keys::RefKeyFromKeyChain;
use crate::typed_api::shortints::client_key::GenericShortIntClientKey;
use crate::typed_api::shortints::parameters::ShortIntegerParameter;
use crate::typed_api::shortints::GenericShortInt;
use crate::typed_api::traits::FheTryEncrypt;
use crate::typed_api::ClientKey;

pub struct CompressedGenericShortint<P>
where
    P: ShortIntegerParameter,
{
    pub(in crate::typed_api::shortints) ciphertext: ShortintCompressedCiphertext,
    pub(in crate::typed_api::shortints) id: P::Id,
}

impl<P> CompressedGenericShortint<P>
where
    P: ShortIntegerParameter,
{
    pub(crate) fn new(inner: ShortintCompressedCiphertext, id: P::Id) -> Self {
        Self {
            ciphertext: inner,
            id,
        }
    }
}

impl<P> From<CompressedGenericShortint<P>> for GenericShortInt<P>
where
    P: ShortIntegerParameter,
{
    fn from(value: CompressedGenericShortint<P>) -> Self {
        let inner = value.ciphertext.into();
        Self::new(inner, value.id)
    }
}

impl<P> FheTryEncrypt<u8, ClientKey> for CompressedGenericShortint<P>
where
    P: ShortIntegerParameter,
    P::Id: Default + RefKeyFromKeyChain<Key = GenericShortIntClientKey<P>>,
{
    type Error = crate::typed_api::errors::Error;

    fn try_encrypt(value: u8, key: &ClientKey) -> Result<Self, Self::Error> {
        let id = P::Id::default();
        let key = id.ref_key(key)?;

        let inner = key.key.encrypt_compressed(value as u64);
        Ok(Self::new(inner, id))
    }
}
