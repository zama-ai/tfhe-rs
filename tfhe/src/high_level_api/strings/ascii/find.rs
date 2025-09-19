use crate::high_level_api::global_state::with_internal_keys;
use crate::high_level_api::keys::InternalServerKey;
use crate::high_level_api::re_randomization::ReRandomizationMetadata;
use crate::high_level_api::strings::ascii::FheAsciiString;
use crate::high_level_api::strings::traits::FheStringFind;
use crate::strings::ciphertext::ClearString;
use crate::{FheBool, FheUint32};

impl FheStringFind<&Self> for FheAsciiString {
    /// find a substring inside a string
    ///
    /// Returns the index of the first character of this string that matches the pattern
    /// as well as a [FheBool] that encrypts `true` if the pattern was found.
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
    /// let string = FheAsciiString::try_encrypt("tfhe is an fhe scheme", &client_key).unwrap();
    /// let pattern = FheAsciiString::try_encrypt("fhe", &client_key).unwrap();
    /// let (position, found) = string.find(&pattern);
    ///
    /// assert!(found.decrypt(&client_key));
    /// let pos: u32 = position.decrypt(&client_key);
    /// assert_eq!(pos, 1);
    /// ```
    fn find(&self, pat: &Self) -> (FheUint32, FheBool) {
        with_internal_keys(|keys| match keys {
            InternalServerKey::Cpu(cpu_key) => {
                let (inner, block) = cpu_key
                    .string_key()
                    .find(&self.inner.on_cpu(), (&*pat.inner.on_cpu()).into());
                (
                    FheUint32::new(
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
                panic!("gpu does not support strings find");
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_) => {
                panic!("hpu does not support strings find");
            }
        })
    }

    /// find a substring inside a string
    ///
    /// Returns the index for the first character of the last match of the pattern in this string,
    /// as well as a [FheBool] that encrypts `true` if the pattern was found.
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
    /// let string = FheAsciiString::try_encrypt("tfhe is an fhe scheme", &client_key).unwrap();
    /// let pattern = FheAsciiString::try_encrypt("fhe", &client_key).unwrap();
    /// let (position, found) = string.rfind(&pattern);
    ///
    /// assert!(found.decrypt(&client_key));
    /// let pos: u32 = position.decrypt(&client_key);
    /// assert_eq!(pos, 11);
    /// ```
    fn rfind(&self, pat: &Self) -> (FheUint32, FheBool) {
        with_internal_keys(|keys| match keys {
            InternalServerKey::Cpu(cpu_key) => {
                let (inner, block) = cpu_key
                    .string_key()
                    .rfind(&self.inner.on_cpu(), (&*pat.inner.on_cpu()).into());
                (
                    FheUint32::new(
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
                panic!("gpu does not support strings rfind");
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_) => {
                panic!("hpu does not support strings rfind");
            }
        })
    }
}

impl FheStringFind<&ClearString> for FheAsciiString {
    /// find a substring inside a string
    ///
    /// Returns the index of the first character of this string that matches the pattern
    /// as well as a [FheBool] that encrypts `true` if the pattern was found.
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
    /// let string = FheAsciiString::try_encrypt("tfhe is an fhe scheme", &client_key).unwrap();
    /// let pattern = ClearString::new("fhe".into());
    /// let (position, found) = string.find(&pattern);
    ///
    /// assert!(found.decrypt(&client_key));
    /// let pos: u32 = position.decrypt(&client_key);
    /// assert_eq!(pos, 1);
    /// ```
    fn find(&self, pat: &ClearString) -> (FheUint32, FheBool) {
        with_internal_keys(|keys| match keys {
            InternalServerKey::Cpu(cpu_key) => {
                let (inner, block) = cpu_key.string_key().find(&self.inner.on_cpu(), pat.into());
                (
                    FheUint32::new(
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
                panic!("gpu does not support strings find");
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_) => {
                panic!("hpu does not support strings find");
            }
        })
    }

    /// find a substring inside a string
    ///
    /// Returns the index for the first character of the last match of the pattern in this string,
    /// as well as a [FheBool] that encrypts `true` if the pattern was found.
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
    /// let string = FheAsciiString::try_encrypt("tfhe is an fhe scheme", &client_key).unwrap();
    /// let pattern = ClearString::new("fhe".into());
    /// let (position, found) = string.rfind(&pattern);
    ///
    /// assert!(found.decrypt(&client_key));
    /// let pos: u32 = position.decrypt(&client_key);
    /// assert_eq!(pos, 11);
    /// ```
    fn rfind(&self, pat: &ClearString) -> (FheUint32, FheBool) {
        with_internal_keys(|keys| match keys {
            InternalServerKey::Cpu(cpu_key) => {
                let (inner, block) = cpu_key.string_key().rfind(&self.inner.on_cpu(), pat.into());
                (
                    FheUint32::new(
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
                panic!("gpu does not support strings rfind");
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_) => {
                panic!("hpu does not support strings rfind");
            }
        })
    }
}
