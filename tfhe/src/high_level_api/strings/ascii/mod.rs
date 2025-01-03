mod comp;
mod contains;
mod find;
mod no_pattern;
mod replace;
mod strip;
mod trim;

use crate::high_level_api::details::MaybeCloned;
use crate::prelude::{FheDecrypt, FheTryEncrypt, Tagged};
use crate::strings::ciphertext::FheString;
use crate::{ClientKey, Tag};
pub use no_pattern::{FheStringIsEmpty, FheStringLen};

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

pub struct FheAsciiString {
    pub(crate) inner: AsciiDevice,
    pub(crate) tag: Tag,
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
