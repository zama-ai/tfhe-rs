use crate::high_level_api::global_state::with_internal_keys;
use crate::high_level_api::keys::InternalServerKey;
use crate::high_level_api::re_randomization::ReRandomizationMetadata;
use crate::high_level_api::strings::ascii::FheAsciiString;
use crate::high_level_api::strings::traits::FheStringStrip;
use crate::high_level_api::FheBool;
use crate::strings::ciphertext::ClearString;

impl FheStringStrip<&Self> for FheAsciiString {
    /// If the pattern does match the start of the string, returns a new encrypted string
    /// with the specified pattern stripped from the start, and boolean set to `true`,
    /// indicating the equivalent of `Some(_)`
    ///
    /// If the pattern does not match the start of the string, returns the original encrypted
    /// string and a boolean set to `false`, indicating the equivalent of `None`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheAsciiString};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let string = FheAsciiString::try_encrypt("tfhe-rs", &client_key).unwrap();
    /// let pattern = FheAsciiString::try_encrypt("tfhe", &client_key).unwrap();
    /// let (stripped, is_stripped) = string.strip_prefix(&pattern);
    ///
    /// assert!(is_stripped.decrypt(&client_key));
    ///
    /// let dec = stripped.decrypt(&client_key);
    /// assert_eq!(&dec, "-rs");
    /// ```
    fn strip_prefix<'a>(&self, pat: &Self) -> (Self, FheBool) {
        with_internal_keys(|keys| match keys {
            InternalServerKey::Cpu(cpu_key) => {
                let (inner, block) = cpu_key
                    .string_key()
                    .strip_prefix(&self.inner.on_cpu(), (&*pat.inner.on_cpu()).into());
                (
                    Self::new(
                        inner,
                        cpu_key.tag.clone(),
                        ReRandomizationMetadata::default(),
                    ),
                    FheBool::new(
                        block,
                        cpu_key.tag.clone(),
                        ReRandomizationMetadata::default(),
                    ),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("gpu does not support strip_prefix");
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_) => {
                panic!("hpu does not support strings strip_prefix");
            }
        })
    }

    /// If the pattern does match the end of the string, returns a new encrypted string
    /// with the specified pattern stripped from the end, and boolean set to `true`,
    /// indicating the equivalent of `Some(_)`
    ///
    /// If the pattern does not match the end of the string, returns the original encrypted
    /// string and a boolean set to `false`, indicating the equivalent of `None`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheAsciiString};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let string = FheAsciiString::try_encrypt("tfhe-rs", &client_key).unwrap();
    /// let pattern = FheAsciiString::try_encrypt("tfhe", &client_key).unwrap();
    /// let (stripped, is_stripped) = string.strip_suffix(&pattern);
    ///
    /// assert!(!is_stripped.decrypt(&client_key));
    ///
    /// let dec = stripped.decrypt(&client_key);
    /// assert_eq!(&dec, "tfhe-rs");
    /// ```
    fn strip_suffix<'a>(&self, pat: &Self) -> (Self, FheBool) {
        with_internal_keys(|keys| match keys {
            InternalServerKey::Cpu(cpu_key) => {
                let (inner, block) = cpu_key
                    .string_key()
                    .strip_suffix(&self.inner.on_cpu(), (&*pat.inner.on_cpu()).into());
                (
                    Self::new(
                        inner,
                        cpu_key.tag.clone(),
                        ReRandomizationMetadata::default(),
                    ),
                    FheBool::new(
                        block,
                        cpu_key.tag.clone(),
                        ReRandomizationMetadata::default(),
                    ),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("gpu does not support strip_suffix");
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_) => {
                panic!("hpu does not support strings string_suffix");
            }
        })
    }
}

impl FheStringStrip<&ClearString> for FheAsciiString {
    /// If the pattern does match the start of the string, returns a new encrypted string
    /// with the specified pattern stripped from the start, and boolean set to `true`,
    /// indicating the equivalent of `Some(_)`
    ///
    /// If the pattern does not match the start of the string, returns the original encrypted
    /// string and a boolean set to `false`, indicating the equivalent of `None`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ClearString, ConfigBuilder, FheAsciiString};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let string = FheAsciiString::try_encrypt("tfhe-rs", &client_key).unwrap();
    /// let pattern = ClearString::new("tfhe".into());
    /// let (stripped, is_stripped) = string.strip_prefix(&pattern);
    ///
    /// assert!(is_stripped.decrypt(&client_key));
    ///
    /// let dec = stripped.decrypt(&client_key);
    /// assert_eq!(&dec, "-rs");
    /// ```
    fn strip_prefix<'a>(&self, pat: &ClearString) -> (Self, FheBool) {
        with_internal_keys(|keys| match keys {
            InternalServerKey::Cpu(cpu_key) => {
                let (inner, block) = cpu_key
                    .string_key()
                    .strip_prefix(&self.inner.on_cpu(), pat.into());
                (
                    Self::new(
                        inner,
                        cpu_key.tag.clone(),
                        ReRandomizationMetadata::default(),
                    ),
                    FheBool::new(
                        block,
                        cpu_key.tag.clone(),
                        ReRandomizationMetadata::default(),
                    ),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("gpu does not support strip_prefix");
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_) => {
                panic!("hpu does not support strings strip_prefix");
            }
        })
    }

    /// If the pattern does match the end of the string, returns a new encrypted string
    /// with the specified pattern stripped from the end, and boolean set to `true`,
    /// indicating the equivalent of `Some(_)`
    ///
    /// If the pattern does not match the end of the string, returns the original encrypted
    /// string and a boolean set to `false`, indicating the equivalent of `None`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ClearString, ConfigBuilder, FheAsciiString};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let string = FheAsciiString::try_encrypt("tfhe-rs", &client_key).unwrap();
    /// let pattern = ClearString::new("tfhe".into());
    /// let (stripped, is_stripped) = string.strip_suffix(&pattern);
    ///
    /// assert!(!is_stripped.decrypt(&client_key));
    ///
    /// let dec = stripped.decrypt(&client_key);
    /// assert_eq!(&dec, "tfhe-rs");
    /// ```
    fn strip_suffix<'a>(&self, pat: &ClearString) -> (Self, FheBool) {
        with_internal_keys(|keys| match keys {
            InternalServerKey::Cpu(cpu_key) => {
                let (inner, block) = cpu_key
                    .string_key()
                    .strip_suffix(&self.inner.on_cpu(), pat.into());
                (
                    Self::new(
                        inner,
                        cpu_key.tag.clone(),
                        ReRandomizationMetadata::default(),
                    ),
                    FheBool::new(
                        block,
                        cpu_key.tag.clone(),
                        ReRandomizationMetadata::default(),
                    ),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("gpu does not support strip_suffix");
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_) => {
                panic!("hpu does not support strings strip_suffix");
            }
        })
    }
}
