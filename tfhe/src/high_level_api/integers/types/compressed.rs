use crate::errors::{UninitializedClientKey, UnwrapResultExt};
use crate::high_level_api::integers::parameters::IntegerParameter;
use crate::high_level_api::integers::types::base::GenericInteger;
use crate::high_level_api::internal_traits::{EncryptionKey, TypeIdentifier};
use crate::high_level_api::traits::FheTryEncrypt;
use crate::high_level_api::ClientKey;

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct CompressedGenericInteger<P>
where
    P: IntegerParameter,
{
    pub(in crate::high_level_api::integers) ciphertext: P::InnerCompressedCiphertext,
    pub(in crate::high_level_api::integers) id: P::Id,
}

impl<P> CompressedGenericInteger<P>
where
    P: IntegerParameter,
{
    pub(in crate::high_level_api::integers) fn new(
        inner: P::InnerCompressedCiphertext,
        id: P::Id,
    ) -> Self {
        Self {
            ciphertext: inner,
            id,
        }
    }
}

impl<P> CompressedGenericInteger<P>
where
    P: IntegerParameter,
    P::InnerCompressedCiphertext: Into<P::InnerCiphertext>,
{
    pub fn decompress(self) -> GenericInteger<P> {
        let inner = self.ciphertext.into();
        GenericInteger::new(inner, self.id)
    }
}

impl<P> From<CompressedGenericInteger<P>> for GenericInteger<P>
where
    P: IntegerParameter,
    P::InnerCompressedCiphertext: Into<P::InnerCiphertext>,
{
    fn from(value: CompressedGenericInteger<P>) -> Self {
        let inner = value.ciphertext.into();
        Self::new(inner, value.id)
    }
}

impl<P, T> FheTryEncrypt<T, ClientKey> for CompressedGenericInteger<P>
where
    P: IntegerParameter,
    P::Id: Default + TypeIdentifier,
    crate::integer::ClientKey: EncryptionKey<(T, usize), P::InnerCompressedCiphertext>,
{
    type Error = crate::high_level_api::errors::Error;

    fn try_encrypt(value: T, key: &ClientKey) -> Result<Self, Self::Error> {
        let id = P::Id::default();
        let integer_client_key = key
            .integer_key
            .key
            .as_ref()
            .ok_or(UninitializedClientKey(id.type_variant()))
            .unwrap_display();
        let inner = <crate::integer::ClientKey as EncryptionKey<_, _>>::encrypt(
            integer_client_key,
            (value, P::num_blocks()),
        );
        Ok(Self::new(inner, id))
    }
}
