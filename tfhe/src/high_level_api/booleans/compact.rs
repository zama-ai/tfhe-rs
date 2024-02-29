use super::FheBool;
use crate::conformance::{ListSizeConstraint, ParameterSetConformant};
use crate::high_level_api::traits::FheTryEncrypt;
use crate::integer::ciphertext::CompactCiphertextList;
use crate::integer::parameters::{
    RadixCiphertextConformanceParams, RadixCompactCiphertextListConformanceParams,
};
use crate::integer::BooleanBlock;
use crate::named::Named;
use crate::shortint::ciphertext::Degree;
use crate::CompactPublicKey;

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
/// ```
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
#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct CompactFheBool {
    list: CompactCiphertextList,
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
    type Error = crate::high_level_api::errors::Error;

    fn try_encrypt(value: bool, key: &CompactPublicKey) -> Result<Self, Self::Error> {
        let ciphertext = key.key.try_encrypt_compact(&[u8::from(value)], 1);
        Ok(Self { list: ciphertext })
    }
}

impl Named for CompactFheBool {
    const NAME: &'static str = "high_level_api::CompactFheBool";
}

impl ParameterSetConformant for CompactFheBool {
    type ParameterSet = RadixCiphertextConformanceParams;

    fn is_conformant(&self, params: &RadixCiphertextConformanceParams) -> bool {
        let lsc = ListSizeConstraint::exact_size(1);

        let params = params.to_ct_list_conformance_parameters(lsc);
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
/// ```
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
#[derive(Clone, serde::Deserialize, serde::Serialize)]
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
    type Error = crate::high_level_api::errors::Error;

    /// Encrypts a slice of bool
    ///
    /// See [CompactFheBoolList] example.
    fn try_encrypt(values: &'a [bool], key: &CompactPublicKey) -> Result<Self, Self::Error> {
        let ciphertext = key
            .key
            .key
            .encrypt_iter_radix_compact(values.iter().copied().map(|v| v as u8), 1);
        Ok(Self { list: ciphertext })
    }
}

impl Named for CompactFheBoolList {
    const NAME: &'static str = "high_level_api::CompactFheBoolList";
}

impl ParameterSetConformant for CompactFheBoolList {
    type ParameterSet = RadixCompactCiphertextListConformanceParams;
    fn is_conformant(&self, params: &RadixCompactCiphertextListConformanceParams) -> bool {
        self.list.is_conformant(params)
    }
}
