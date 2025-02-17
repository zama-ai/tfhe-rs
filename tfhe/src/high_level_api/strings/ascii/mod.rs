mod comp;
mod contains;
mod find;
mod no_pattern;
mod replace;
mod strip;
mod trim;

pub use crate::high_level_api::backward_compatibility::strings::FheAsciiStringVersions;
use crate::high_level_api::details::MaybeCloned;
use crate::integer::ciphertext::{Compressible, DataKind, Expandable};
use crate::named::Named;
use crate::prelude::{FheDecrypt, FheTryEncrypt, Tagged};
use crate::strings::ciphertext::FheString;
use crate::{ClientKey, HlExpandable, Tag};
pub use no_pattern::{FheStringIsEmpty, FheStringLen};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use tfhe_versionable::{Unversionize, UnversionizeError, Versionize, VersionizeOwned};

pub enum EncryptableString<'a> {
    NoPadding(&'a str),
    WithPadding { str: &'a str, padding: u32 },
}

impl EncryptableString<'_> {
    fn str_and_padding(&self) -> (&str, Option<u32>) {
        match self {
            EncryptableString::NoPadding(str) => (str, None),
            EncryptableString::WithPadding { str, padding } => (str, Some(*padding)),
        }
    }
}

pub(crate) enum AsciiDevice {
    Cpu(FheString),
}

impl From<FheString> for AsciiDevice {
    fn from(value: FheString) -> Self {
        Self::Cpu(value)
    }
}

impl AsciiDevice {
    pub fn on_cpu(&self) -> MaybeCloned<'_, FheString> {
        match self {
            Self::Cpu(cpu_string) => MaybeCloned::Borrowed(cpu_string),
        }
    }
}

impl Clone for AsciiDevice {
    fn clone(&self) -> Self {
        match self {
            Self::Cpu(s) => Self::Cpu(s.clone()),
        }
    }
}

impl serde::Serialize for AsciiDevice {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.on_cpu().serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for AsciiDevice {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let deserialized = Self::Cpu(FheString::deserialize(deserializer)?);
        Ok(deserialized)
    }
}

// Only CPU data are serialized so we only versionize the CPU type.
#[derive(serde::Serialize, serde::Deserialize)]
#[cfg_attr(dylint_lib = "tfhe_lints", allow(serialize_without_versionize))]
pub(crate) struct AsciiDeviceVersionOwned(<FheString as VersionizeOwned>::VersionedOwned);

#[derive(Serialize, Deserialize)]
#[cfg_attr(dylint_lib = "tfhe_lints", allow(serialize_without_versionize))]
pub(crate) enum AsciiDeviceVersionedOwned {
    V0(AsciiDeviceVersionOwned),
}

impl Versionize for AsciiDevice {
    type Versioned<'vers> = AsciiDeviceVersionedOwned;

    fn versionize(&self) -> Self::Versioned<'_> {
        let data = self.on_cpu();
        let versioned = data.into_owned().versionize_owned();
        AsciiDeviceVersionedOwned::V0(AsciiDeviceVersionOwned(versioned))
    }
}

impl VersionizeOwned for AsciiDevice {
    type VersionedOwned = AsciiDeviceVersionedOwned;

    fn versionize_owned(self) -> Self::VersionedOwned {
        let cpu_data = self.on_cpu();
        AsciiDeviceVersionedOwned::V0(AsciiDeviceVersionOwned(
            cpu_data.into_owned().versionize_owned(),
        ))
    }
}

impl Unversionize for AsciiDevice {
    fn unversionize(versioned: Self::VersionedOwned) -> Result<Self, UnversionizeError> {
        match versioned {
            AsciiDeviceVersionedOwned::V0(v0) => {
                let unversioned = Self::Cpu(FheString::unversionize(v0.0)?);
                Ok(unversioned)
            }
        }
    }
}

#[derive(Serialize, Deserialize, Versionize, Clone)]
#[versionize(FheAsciiStringVersions)]
pub struct FheAsciiString {
    pub(crate) inner: AsciiDevice,
    pub(crate) tag: Tag,
}

impl Named for FheAsciiString {
    const NAME: &'static str = "high_level_api::FheAsciiString";
}

impl Tagged for FheAsciiString {
    fn tag(&self) -> &Tag {
        &self.tag
    }

    fn tag_mut(&mut self) -> &mut Tag {
        &mut self.tag
    }
}

impl FheAsciiString {
    pub(crate) fn new(inner: impl Into<AsciiDevice>, tag: Tag) -> Self {
        Self {
            inner: inner.into(),
            tag,
        }
    }

    /// Encrypts the string `str` and adds `padding` blocks of padding (encryption of zero)
    pub fn try_encrypt_with_padding(
        str: impl AsRef<str>,
        padding: u32,
        client_key: &ClientKey,
    ) -> crate::Result<Self> {
        Self::try_encrypt(
            EncryptableString::WithPadding {
                str: str.as_ref(),
                padding,
            },
            client_key,
        )
    }

    /// Encrypts the string `str` with a fixed size `size`
    ///
    /// * If the input str is shorter than size, it will be padded with encryptions of 0
    /// * If the input str is longer than size, it will be truncated
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::prelude::*;
    /// use tfhe::safe_serialization::safe_serialize;
    /// use tfhe::{
    ///     generate_keys, set_server_key, ConfigBuilder, FheAsciiString, FheStringIsEmpty,
    ///     FheStringLen,
    /// };
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// // The input string is shorter
    /// let string1 = FheAsciiString::try_encrypt_with_fixed_sized("tfhe", 5, &client_key).unwrap();
    /// match string1.len() {
    ///     FheStringLen::NoPadding(_) => {
    ///         panic!("Expected padding")
    ///     }
    ///     FheStringLen::Padding(len) => {
    ///         let len: u16 = len.decrypt(&client_key);
    ///         // The padding is not part of the len
    ///         assert_eq!(len, 4);
    ///     }
    /// }
    /// assert_eq!(string1.decrypt(&client_key), "tfhe".to_string());
    ///
    /// // The input string is longer
    /// let string2 = FheAsciiString::try_encrypt_with_fixed_sized("tfhe-rs", 5, &client_key).unwrap();
    /// match string2.len() {
    ///     FheStringLen::NoPadding(len) => {
    ///         assert_eq!(len, 5);
    ///     }
    ///     FheStringLen::Padding(len) => {
    ///         panic!("Unexpected padding");
    ///     }
    /// }
    /// assert_eq!(string2.decrypt(&client_key), "tfhe-".to_string());
    ///
    /// let mut buffer1 = vec![];
    /// safe_serialize(&string1, &mut buffer1, 1 << 30).unwrap();
    /// let mut buffer2 = vec![];
    /// safe_serialize(&string2, &mut buffer2, 1 << 30).unwrap();
    /// // But they have the same 'size'
    /// assert_eq!(buffer1.len(), buffer2.len())
    /// ```
    pub fn try_encrypt_with_fixed_sized(
        str: impl AsRef<str>,
        size: usize,
        client_key: &ClientKey,
    ) -> crate::Result<Self> {
        let str = str.as_ref();
        let (sliced, padding) = if str.len() >= size {
            (&str[..size], 0)
        } else {
            (str, (size - str.len()) as u32)
        };

        Self::try_encrypt(
            EncryptableString::WithPadding {
                str: sliced,
                padding,
            },
            client_key,
        )
    }
}

impl<'a> FheTryEncrypt<EncryptableString<'a>, ClientKey> for FheAsciiString {
    type Error = crate::Error;

    fn try_encrypt(value: EncryptableString<'a>, key: &ClientKey) -> Result<Self, Self::Error> {
        let (str, padding) = value.str_and_padding();
        if !str.is_ascii() || str.contains('\0') {
            return Err(crate::Error::new(
                "Input is not an ASCII string".to_string(),
            ));
        }

        let inner = crate::strings::ClientKey::new(&key.key.key).encrypt_ascii(str, padding);
        Ok(Self {
            inner: inner.into(),
            tag: key.tag.clone(),
        })
    }
}

impl FheTryEncrypt<&str, ClientKey> for FheAsciiString {
    type Error = crate::Error;

    fn try_encrypt(value: &str, key: &ClientKey) -> Result<Self, Self::Error> {
        Self::try_encrypt(EncryptableString::NoPadding(value), key)
    }
}

impl FheTryEncrypt<&String, ClientKey> for FheAsciiString {
    type Error = crate::Error;

    fn try_encrypt(value: &String, key: &ClientKey) -> Result<Self, Self::Error> {
        Self::try_encrypt(EncryptableString::NoPadding(value), key)
    }
}

impl FheDecrypt<String> for FheAsciiString {
    fn decrypt(&self, key: &ClientKey) -> String {
        crate::strings::ClientKey::new(&key.key.key).decrypt_ascii(&self.inner.on_cpu())
    }
}

impl Expandable for FheAsciiString {
    fn from_expanded_blocks(
        blocks: Vec<crate::shortint::Ciphertext>,
        kind: crate::integer::ciphertext::DataKind,
    ) -> crate::Result<Self> {
        FheString::from_expanded_blocks(blocks, kind)
            .map(|cpu_string| Self::new(cpu_string, Tag::default()))
    }
}

impl crate::HlCompactable for &crate::ClearString {}

#[cfg(feature = "gpu")]
impl crate::integer::gpu::ciphertext::compressed_ciphertext_list::CudaExpandable
    for FheAsciiString
{
    fn from_expanded_blocks(
        blocks: crate::integer::gpu::ciphertext::CudaRadixCiphertext,
        kind: DataKind,
    ) -> crate::Result<Self> {
        Err(crate::error!("GPU does not supports strings yet"))
    }
}

impl HlExpandable for FheAsciiString {}

impl crate::HlCompressible for FheAsciiString {
    fn compress_into(
        self,
        messages: &mut Vec<(
            crate::high_level_api::compressed_ciphertext_list::ToBeCompressed,
            DataKind,
        )>,
    ) {
        match self.inner {
            AsciiDevice::Cpu(fhe_string) => {
                let mut blocks = vec![];
                let data_kind = fhe_string.compress_into(&mut blocks);
                messages.push((
                    crate::high_level_api::compressed_ciphertext_list::ToBeCompressed::Cpu(blocks),
                    data_kind,
                ));
            }
        }
    }
}
