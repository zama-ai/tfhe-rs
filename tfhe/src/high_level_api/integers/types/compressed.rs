use crate::errors::{UninitializedClientKey, UnwrapResultExt};
use crate::high_level_api::integers::parameters::IntegerParameter;
use crate::high_level_api::integers::server_key::RadixCiphertextDyn;
use crate::high_level_api::integers::types::base::GenericInteger;
use crate::high_level_api::internal_traits::TypeIdentifier;
use crate::high_level_api::traits::FheTryEncrypt;
use crate::high_level_api::ClientKey;
use crate::integer::U256;

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub(in crate::high_level_api::integers) enum CompressedRadixCiphertextDyn {
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
    pub(in crate::high_level_api::integers) ciphertext: CompressedRadixCiphertextDyn,
    pub(in crate::high_level_api::integers) id: P::Id,
}

impl<P> CompressedGenericInteger<P>
where
    P: IntegerParameter,
{
    pub(in crate::high_level_api::integers) fn new(
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
    P: IntegerParameter,
{
    fn from(value: CompressedGenericInteger<P>) -> Self {
        let inner = value.ciphertext.into();
        Self::new(inner, value.id)
    }
}

impl<P, T> FheTryEncrypt<T, ClientKey> for CompressedGenericInteger<P>
where
    T: Into<U256>,
    P: IntegerParameter,
    P::Id: Default + TypeIdentifier,
{
    type Error = crate::high_level_api::errors::Error;

    fn try_encrypt(value: T, key: &ClientKey) -> Result<Self, Self::Error> {
        let value = value.into();
        let id = P::Id::default();
        let integer_client_key = key
            .integer_key
            .as_ref()
            .ok_or(UninitializedClientKey(id.type_variant()))
            .unwrap_display();
        let inner = match integer_client_key.encryption_type() {
            crate::shortint::EncryptionKeyChoice::Big => CompressedRadixCiphertextDyn::Big(
                integer_client_key
                    .key
                    .encrypt_radix_compressed(value, P::num_blocks()),
            ),
            crate::shortint::EncryptionKeyChoice::Small => CompressedRadixCiphertextDyn::Small(
                integer_client_key
                    .key
                    .encrypt_radix_compressed_small(value, P::num_blocks()),
            ),
        };
        Ok(Self::new(inner, id))
    }
}
