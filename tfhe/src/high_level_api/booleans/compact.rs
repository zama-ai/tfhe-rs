use tfhe_versionable::Versionize;

use super::FheBool;
use crate::backward_compatibility::booleans::{CompactFheBoolListVersions, CompactFheBoolVersions};
use crate::conformance::{ListSizeConstraint, ParameterSetConformant};
use crate::high_level_api::traits::FheTryEncrypt;
use crate::integer::ciphertext::CompactCiphertextList;
use crate::integer::parameters::RadixCompactCiphertextListConformanceParams;
use crate::integer::BooleanBlock;
use crate::named::Named;
use crate::shortint::ciphertext::Degree;
use crate::shortint::parameters::CiphertextConformanceParams;
use crate::shortint::PBSParameters;
use crate::{CompactPublicKey, FheBoolConformanceParams, ServerKey};

/// Compact [FheBool]
///
/// Meant to save in storage space / transfer.
///
/// - A Compact type must be expanded using [expand](Self::expand) before it can be used.
/// - It is not possible to 'compact' an existing [FheBool]. Compacting can only be achieved at
///   encryption time by a [CompactPublicKey]
///
/// # Example
///
/// ```rust
/// use tfhe::prelude::*;
/// use tfhe::{generate_keys, CompactFheBool, CompactPublicKey, ConfigBuilder, FheBool};
///
/// let (client_key, _) = generate_keys(ConfigBuilder::default());
/// let compact_public_key = CompactPublicKey::try_new(&client_key).unwrap();
///
/// let compact = CompactFheBool::encrypt(true, &compact_public_key);
///
/// let ciphertext = compact.expand();
/// let decrypted: bool = ciphertext.decrypt(&client_key);
/// assert_eq!(decrypted, true);
/// ```
#[cfg_attr(all(doc, not(doctest)), doc(cfg(feature = "integer")))]
#[derive(Clone, serde::Deserialize, serde::Serialize, Versionize)]
#[versionize(CompactFheBoolVersions)]
pub struct CompactFheBool {
    pub(in crate::high_level_api) list: CompactCiphertextList,
}

impl CompactFheBool {
    /// Expand to a [FheBool]
    ///
    /// See [CompactFheBool] example.
    pub fn expand(&self) -> FheBool {
        let ct: crate::integer::RadixCiphertext = self.list.expand_one();
        assert_eq!(ct.blocks.len(), 1);
        let mut block = BooleanBlock::new_unchecked(ct.blocks.into_iter().next().unwrap());
        block.0.degree = Degree::new(1);
        let mut ciphertext = FheBool::new(block);
        ciphertext.ciphertext.move_to_device_of_server_key_if_set();
        ciphertext
    }
}

impl FheTryEncrypt<bool, CompactPublicKey> for CompactFheBool {
    type Error = crate::Error;

    fn try_encrypt(value: bool, key: &CompactPublicKey) -> Result<Self, Self::Error> {
        let mut ciphertext = key.key.try_encrypt_compact(&[u8::from(value)], 1);
        ciphertext.ct_list.degree = Degree::new(1);
        Ok(Self { list: ciphertext })
    }
}

impl Named for CompactFheBool {
    const NAME: &'static str = "high_level_api::CompactFheBool";
}

impl ParameterSetConformant for CompactFheBool {
    type ParameterSet = FheBoolConformanceParams;

    fn is_conformant(&self, params: &FheBoolConformanceParams) -> bool {
        let params = RadixCompactCiphertextListConformanceParams {
            shortint_params: params.0,
            num_blocks_per_integer: 1,
            num_integers_constraint: ListSizeConstraint::exact_size(1),
        };
        self.list.is_conformant(&params)
    }
}

/// Compact list of [FheBool]
///
/// Meant to save in storage space / transfer.
///
/// - A Compact type must be expanded using [expand](Self::expand) before it can be used.
/// - It is not possible to 'compact' an existing [FheBool]. Compacting can only be achieved at
///   encryption time by a [CompactPublicKey]
///
/// # Example
///
/// ```rust
/// use tfhe::prelude::*;
/// use tfhe::{generate_keys, CompactFheBoolList, CompactPublicKey, ConfigBuilder};
///
/// let (client_key, _) = generate_keys(ConfigBuilder::default());
/// let compact_public_key = CompactPublicKey::try_new(&client_key).unwrap();
///
/// let clears = vec![false, true];
/// let compact = CompactFheBoolList::encrypt(&clears, &compact_public_key);
/// assert_eq!(compact.len(), clears.len());
///
/// let ciphertexts = compact.expand();
/// let decrypted: Vec<bool> = ciphertexts
///     .into_iter()
///     .map(|ciphertext| ciphertext.decrypt(&client_key))
///     .collect();
/// assert_eq!(decrypted, clears);
/// ```
#[cfg_attr(all(doc, not(doctest)), doc(cfg(feature = "integer")))]
#[derive(Clone, serde::Deserialize, serde::Serialize, Versionize)]
#[versionize(CompactFheBoolListVersions)]
pub struct CompactFheBoolList {
    list: CompactCiphertextList,
}

impl CompactFheBoolList {
    /// Returns the number of element in the compact list
    pub fn len(&self) -> usize {
        self.list.ciphertext_count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Expand to a Vec<[FheBool]>
    ///
    /// See [CompactFheBoolList] example.
    pub fn expand(&self) -> Vec<FheBool> {
        self.list
            .expand()
            .into_iter()
            .map(|ct: crate::integer::RadixCiphertext| {
                assert_eq!(ct.blocks.len(), 1);
                let mut block = BooleanBlock::new_unchecked(ct.blocks.into_iter().next().unwrap());
                block.0.degree = Degree::new(1);
                let mut ciphertext = FheBool::new(block);
                ciphertext.ciphertext.move_to_device_of_server_key_if_set();
                ciphertext
            })
            .collect::<Vec<_>>()
    }
}

impl<'a> FheTryEncrypt<&'a [bool], CompactPublicKey> for CompactFheBoolList {
    type Error = crate::Error;

    /// Encrypts a slice of bool
    ///
    /// See [CompactFheBoolList] example.
    fn try_encrypt(values: &'a [bool], key: &CompactPublicKey) -> Result<Self, Self::Error> {
        let mut ciphertext = key
            .key
            .key
            .encrypt_iter_radix_compact(values.iter().copied().map(|v| v as u8), 1);
        ciphertext.ct_list.degree = Degree::new(1);
        Ok(Self { list: ciphertext })
    }
}

impl Named for CompactFheBoolList {
    const NAME: &'static str = "high_level_api::CompactFheBoolList";
}

pub struct CompactFheBoolListConformanceParams {
    shortint_params: CiphertextConformanceParams,
    len_constraint: ListSizeConstraint,
}

impl CompactFheBoolListConformanceParams {
    fn new(
        mut shortint_params: CiphertextConformanceParams,
        len_constraint: ListSizeConstraint,
    ) -> Self {
        shortint_params.degree = Degree::new(1);
        Self {
            shortint_params,
            len_constraint,
        }
    }
}

impl<P> From<(P, ListSizeConstraint)> for CompactFheBoolListConformanceParams
where
    P: Into<PBSParameters>,
{
    fn from((params, len_constraint): (P, ListSizeConstraint)) -> Self {
        Self::new(
            params.into().to_shortint_conformance_param(),
            len_constraint,
        )
    }
}

impl From<(&ServerKey, ListSizeConstraint)> for CompactFheBoolListConformanceParams {
    fn from((sk, len_constraint): (&ServerKey, ListSizeConstraint)) -> Self {
        Self::new(sk.key.pbs_key().key.conformance_params(), len_constraint)
    }
}

impl ParameterSetConformant for CompactFheBoolList {
    type ParameterSet = CompactFheBoolListConformanceParams;

    fn is_conformant(&self, params: &CompactFheBoolListConformanceParams) -> bool {
        let params = RadixCompactCiphertextListConformanceParams {
            shortint_params: params.shortint_params,
            num_blocks_per_integer: 1,
            num_integers_constraint: params.len_constraint,
        };
        self.list.is_conformant(&params)
    }
}
