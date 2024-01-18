use crate::conformance::{ListSizeConstraint, ParameterSetConformant};
use crate::high_level_api::integers::{FheInt, FheIntId};
use crate::integer::ciphertext::CompactCiphertextList;
use crate::integer::parameters::{
    RadixCiphertextConformanceParams, RadixCompactCiphertextListConformanceParams,
};
use crate::named::Named;
use crate::prelude::FheTryEncrypt;
use crate::CompactPublicKey;

/// Compact [FheInt]
///
/// Meant to save in storage space / transfer.
///
/// - A Compact type must be expanded using [expand](Self::expand) before it can be used.
/// - It is not possible to 'compact' an existing [FheInt]. Compacting can only be achieved at
///   encryption time by a [CompactPublicKey]
///
/// # Example
///
/// ```
/// use tfhe::prelude::*;
/// use tfhe::{generate_keys, CompactFheInt32, CompactPublicKey, ConfigBuilder, FheInt32};
///
/// let (client_key, _) = generate_keys(ConfigBuilder::default());
/// let compact_public_key = CompactPublicKey::try_new(&client_key).unwrap();
///
/// let compact = CompactFheInt32::encrypt(i32::MIN, &compact_public_key);
///
/// let ciphertext = compact.expand();
/// let decrypted: i32 = ciphertext.decrypt(&client_key);
/// assert_eq!(decrypted, i32::MIN);
/// ```
#[cfg_attr(all(doc, not(doctest)), doc(cfg(feature = "integer")))]
#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct CompactFheInt<Id: FheIntId> {
    pub(in crate::high_level_api::integers) list: CompactCiphertextList,
    pub(in crate::high_level_api::integers) id: Id,
}

impl<Id> CompactFheInt<Id>
where
    Id: FheIntId,
{
    /// Expand to a [FheInt]
    ///
    /// See [CompactFheInt] example.
    pub fn expand(&self) -> FheInt<Id> {
        let ct = self.list.expand_one();
        FheInt::new(ct)
    }

    pub fn into_raw_parts(self) -> (CompactCiphertextList, Id) {
        let Self { list, id } = self;
        (list, id)
    }

    pub fn from_raw_parts(list: CompactCiphertextList, id: Id) -> Self {
        Self { list, id }
    }
}

impl<Id, T> FheTryEncrypt<T, CompactPublicKey> for CompactFheInt<Id>
where
    T: crate::integer::block_decomposition::DecomposableInto<u64>,
    Id: FheIntId,
{
    type Error = crate::high_level_api::errors::Error;

    fn try_encrypt(value: T, key: &CompactPublicKey) -> Result<Self, Self::Error> {
        let id = Id::default();
        let ciphertext = key
            .key
            .try_encrypt_compact(&[value], Id::num_blocks(key.message_modulus()));
        Ok(Self {
            list: ciphertext,
            id,
        })
    }
}

impl<Id: FheIntId> Named for CompactFheInt<Id> {
    const NAME: &'static str = "high_level_api::CompactFheInt";
}

impl<Id: FheIntId> ParameterSetConformant for CompactFheInt<Id> {
    type ParameterSet = RadixCiphertextConformanceParams;
    fn is_conformant(&self, params: &RadixCiphertextConformanceParams) -> bool {
        let lsc = ListSizeConstraint::exact_size(1);

        let params = params.to_ct_list_conformance_parameters(lsc);
        self.list.is_conformant(&params)
    }
}

/// Compact list of [FheInt]
///
/// Meant to save in storage space / transfer.
///
/// - A Compact type must be expanded using [expand](Self::expand) before it can be used.
/// - It is not possible to 'compact' an existing [FheInt]. Compacting can only be achieved at
///   encryption time by a [CompactPublicKey]
///
/// # Example
///
/// ```
/// use tfhe::prelude::*;
/// use tfhe::{generate_keys, CompactFheInt32List, CompactPublicKey, ConfigBuilder, FheInt32};
///
/// let (client_key, _) = generate_keys(ConfigBuilder::default());
/// let compact_public_key = CompactPublicKey::try_new(&client_key).unwrap();
///
/// let clears = vec![i32::MAX, i32::MIN, 0, 1];
/// let compact = CompactFheInt32List::encrypt(&clears, &compact_public_key);
/// assert_eq!(compact.len(), clears.len());
///
/// let ciphertexts = compact.expand();
/// let decrypted: Vec<i32> = ciphertexts
///     .into_iter()
///     .map(|ciphertext| ciphertext.decrypt(&client_key))
///     .collect();
/// assert_eq!(decrypted, clears);
/// ```
#[cfg_attr(all(doc, not(doctest)), doc(cfg(feature = "integer")))]
#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct CompactFheIntList<Id: FheIntId> {
    pub(in crate::high_level_api::integers) list: CompactCiphertextList,
    pub(in crate::high_level_api::integers) id: Id,
}

impl<Id> CompactFheIntList<Id>
where
    Id: FheIntId,
{
    /// Returns the number of element in the compact list
    pub fn len(&self) -> usize {
        self.list.ciphertext_count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn into_raw_parts(self) -> (CompactCiphertextList, Id) {
        let Self { list, id } = self;
        (list, id)
    }

    pub fn from_raw_parts(list: CompactCiphertextList, id: Id) -> Self {
        Self { list, id }
    }

    /// Expand to a Vec<[FheInt]>
    ///
    /// See [CompactFheIntList] example.
    pub fn expand(&self) -> Vec<FheInt<Id>> {
        self.list
            .expand()
            .into_iter()
            .map(|ct| FheInt::new(ct))
            .collect::<Vec<_>>()
    }
}

impl<'a, Id, T> FheTryEncrypt<&'a [T], CompactPublicKey> for CompactFheIntList<Id>
where
    T: crate::integer::block_decomposition::DecomposableInto<u64>,
    Id: FheIntId,
{
    type Error = crate::high_level_api::errors::Error;

    fn try_encrypt(values: &'a [T], key: &CompactPublicKey) -> Result<Self, Self::Error> {
        let id = Id::default();
        let ciphertext = key
            .key
            .try_encrypt_compact(values, Id::num_blocks(key.message_modulus()));
        Ok(Self {
            list: ciphertext,
            id,
        })
    }
}

impl<Id: FheIntId> Named for CompactFheIntList<Id> {
    const NAME: &'static str = "high_level_api::CompactFheIntList";
}

impl<Id: FheIntId> ParameterSetConformant for CompactFheIntList<Id> {
    type ParameterSet = RadixCompactCiphertextListConformanceParams;
    fn is_conformant(&self, params: &RadixCompactCiphertextListConformanceParams) -> bool {
        self.list.is_conformant(params)
    }
}
