use crate::conformance::{ListSizeConstraint, ParameterSetConformant};
use crate::high_level_api::integers::signed::base::FheIntConformanceParams;
use crate::high_level_api::integers::{FheInt, FheIntId};
use crate::integer::ciphertext::CompactCiphertextList;
use crate::integer::parameters::RadixCompactCiphertextListConformanceParams;
use crate::named::Named;
use crate::prelude::FheTryEncrypt;
use crate::shortint::PBSParameters;
use crate::{CompactPublicKey, ServerKey};
use std::marker::PhantomData;

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
/// ```rust
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
        let ct = self
            .list
            .expand_one::<crate::integer::SignedRadixCiphertext>();
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
    type Error = crate::Error;

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
    type ParameterSet = FheIntConformanceParams<Id>;

    fn is_conformant(&self, params: &FheIntConformanceParams<Id>) -> bool {
        let params = params
            .params
            .to_ct_list_conformance_parameters(ListSizeConstraint::exact_size(1));
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
/// ```rust
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
            .expand::<crate::integer::SignedRadixCiphertext>()
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
    type Error = crate::Error;

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

pub struct CompactFheIntListConformanceParams<Id: FheIntId> {
    params: RadixCompactCiphertextListConformanceParams,
    _id: PhantomData<Id>,
}

impl<Id: FheIntId, P: Into<PBSParameters>> From<(P, ListSizeConstraint)>
    for CompactFheIntListConformanceParams<Id>
{
    fn from((params, len_constraint): (P, ListSizeConstraint)) -> Self {
        let params = params.into();
        Self {
            params: RadixCompactCiphertextListConformanceParams {
                shortint_params: params.to_shortint_conformance_param(),
                num_blocks_per_integer: Id::num_blocks(params.message_modulus()),
                num_integers_constraint: len_constraint,
            },
            _id: PhantomData,
        }
    }
}

impl<Id: FheIntId> From<(&ServerKey, ListSizeConstraint)>
    for CompactFheIntListConformanceParams<Id>
{
    fn from((sk, len_constraint): (&ServerKey, ListSizeConstraint)) -> Self {
        Self {
            params: RadixCompactCiphertextListConformanceParams {
                shortint_params: sk.key.pbs_key().key.conformance_params(),
                num_blocks_per_integer: Id::num_blocks(sk.key.pbs_key().message_modulus()),
                num_integers_constraint: len_constraint,
            },
            _id: PhantomData,
        }
    }
}

impl<Id: FheIntId> ParameterSetConformant for CompactFheIntList<Id> {
    type ParameterSet = CompactFheIntListConformanceParams<Id>;

    fn is_conformant(&self, params: &CompactFheIntListConformanceParams<Id>) -> bool {
        self.list.is_conformant(&params.params)
    }
}
