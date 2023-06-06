use crate::errors::{UninitializedPublicKey, UnwrapResultExt};
use crate::high_level_api::integers::parameters::IntegerParameter;
use crate::high_level_api::integers::server_key::RadixCiphertextDyn;
use crate::high_level_api::integers::types::base::GenericInteger;
use crate::high_level_api::internal_traits::TypeIdentifier;
use crate::high_level_api::traits::FheTryEncrypt;
use crate::integer::ciphertext::{CompactCiphertextListBig, CompactCiphertextListSmall};
use crate::CompactPublicKey;

#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub(in crate::high_level_api::integers) enum CompactCiphertextListDyn {
    Big(CompactCiphertextListBig),
    Small(CompactCiphertextListSmall),
}

#[cfg_attr(all(doc, not(doctest)), doc(cfg(feature = "integer")))]
#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct GenericCompactInteger<P: IntegerParameter> {
    pub(in crate::high_level_api::integers) list: CompactCiphertextListDyn,
    pub(in crate::high_level_api::integers) id: P::Id,
}

#[cfg_attr(all(doc, not(doctest)), doc(cfg(feature = "integer")))]
#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct GenericCompactIntegerList<P: IntegerParameter> {
    pub(in crate::high_level_api::integers) list: CompactCiphertextListDyn,
    pub(in crate::high_level_api::integers) id: P::Id,
}

impl<P> GenericCompactInteger<P>
where
    P: IntegerParameter,
{
    pub fn expand(&self) -> GenericInteger<P> {
        match &self.list {
            CompactCiphertextListDyn::Big(list) => {
                let expanded = RadixCiphertextDyn::Big(list.expand_one());
                GenericInteger::new(expanded, self.id)
            }
            CompactCiphertextListDyn::Small(list) => {
                let expanded = RadixCiphertextDyn::Small(list.expand_one());
                GenericInteger::new(expanded, self.id)
            }
        }
    }
}

impl<P> GenericCompactIntegerList<P>
where
    P: IntegerParameter,
{
    pub fn len(&self) -> usize {
        match &self.list {
            CompactCiphertextListDyn::Big(list) => list.ciphertext_count(),
            CompactCiphertextListDyn::Small(list) => list.ciphertext_count(),
        }
    }

    pub fn expand(&self) -> Vec<GenericInteger<P>> {
        match &self.list {
            CompactCiphertextListDyn::Big(list) => list
                .expand()
                .into_iter()
                .map(RadixCiphertextDyn::Big)
                .map(|ct| GenericInteger::new(ct, self.id))
                .collect::<Vec<_>>(),
            CompactCiphertextListDyn::Small(list) => list
                .expand()
                .into_iter()
                .map(RadixCiphertextDyn::Small)
                .map(|ct| GenericInteger::new(ct, self.id))
                .collect::<Vec<_>>(),
        }
    }
}

impl<P, T> FheTryEncrypt<T, CompactPublicKey> for GenericCompactInteger<P>
where
    T: crate::integer::block_decomposition::DecomposableInto<u64>,
    P: IntegerParameter,
    P::Id: Default + TypeIdentifier,
{
    type Error = crate::high_level_api::errors::Error;

    fn try_encrypt(value: T, key: &CompactPublicKey) -> Result<Self, Self::Error> {
        let id = P::Id::default();
        let ciphertext = key
            .integer_key
            .try_encrypt_compact(&[value], P::num_blocks())
            .ok_or(UninitializedPublicKey(id.type_variant()))
            .unwrap_display();
        Ok(Self {
            list: ciphertext,
            id,
        })
    }
}

impl<'a, P, T> FheTryEncrypt<&'a [T], CompactPublicKey> for GenericCompactIntegerList<P>
where
    T: crate::integer::block_decomposition::DecomposableInto<u64>,
    P: IntegerParameter,
    P::Id: Default + TypeIdentifier,
{
    type Error = crate::high_level_api::errors::Error;

    fn try_encrypt(values: &'a [T], key: &CompactPublicKey) -> Result<Self, Self::Error> {
        let id = P::Id::default();
        let ciphertext = key
            .integer_key
            .try_encrypt_compact(values, P::num_blocks())
            .ok_or(UninitializedPublicKey(id.type_variant()))
            .unwrap_display();
        Ok(Self {
            list: ciphertext,
            id,
        })
    }
}
