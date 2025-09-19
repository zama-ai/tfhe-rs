use crate::high_level_api::global_state::with_internal_keys;
use crate::high_level_api::keys::InternalServerKey;
use crate::high_level_api::re_randomization::ReRandomizationMetadata;
use crate::high_level_api::strings::ascii::FheAsciiString;
use crate::high_level_api::strings::traits::FheStringMatching;
use crate::strings::ciphertext::ClearString;
use crate::FheBool;

impl FheStringMatching<&Self> for FheAsciiString {
    /// checks if the string contains the given substring
    ///
    /// Returns a [FheBool] that encrypts `true` if the substring was found.
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
    /// let found = string.contains(&pattern);
    ///
    /// assert!(found.decrypt(&client_key));
    /// ```
    fn contains(&self, other: &Self) -> FheBool {
        with_internal_keys(|keys| match keys {
            InternalServerKey::Cpu(cpu_key) => {
                let inner = cpu_key
                    .string_key()
                    .contains(&self.inner.on_cpu(), (&*other.inner.on_cpu()).into());
                FheBool::new(
                    inner,
                    cpu_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("gpu does not support strings contains");
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_) => {
                panic!("hpu does not support contains");
            }
        })
    }

    /// checks if the string starts with the given substring
    ///
    /// Returns a [FheBool] that encrypts `true` if the substring was found at the beginning.
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
    /// let found = string.starts_with(&pattern);
    ///
    /// assert!(!found.decrypt(&client_key));
    /// ```
    fn starts_with(&self, other: &Self) -> FheBool {
        with_internal_keys(|keys| match keys {
            InternalServerKey::Cpu(cpu_key) => {
                let inner = cpu_key
                    .string_key()
                    .starts_with(&self.inner.on_cpu(), (&*other.inner.on_cpu()).into());
                FheBool::new(
                    inner,
                    cpu_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("gpu does not support strings starts_with");
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_) => {
                panic!("hpu does not support starts_with");
            }
        })
    }

    /// checks if the string ends with the given substring
    ///
    /// Returns a [FheBool] that encrypts `true` if the substring was found at the end.
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
    /// let pattern = FheAsciiString::try_encrypt("scheme", &client_key).unwrap();
    /// let found = string.ends_with(&pattern);
    ///
    /// assert!(found.decrypt(&client_key));
    /// ```
    fn ends_with(&self, other: &Self) -> FheBool {
        with_internal_keys(|keys| match keys {
            InternalServerKey::Cpu(cpu_key) => {
                let inner = cpu_key
                    .string_key()
                    .ends_with(&self.inner.on_cpu(), (&*other.inner.on_cpu()).into());
                FheBool::new(
                    inner,
                    cpu_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("gpu does not support strings ends_with");
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_) => {
                panic!("hpu does not support ends_with");
            }
        })
    }
}

impl FheStringMatching<&ClearString> for FheAsciiString {
    fn contains(&self, other: &ClearString) -> FheBool {
        with_internal_keys(|keys| match keys {
            InternalServerKey::Cpu(cpu_key) => {
                let inner = cpu_key
                    .string_key()
                    .contains(&self.inner.on_cpu(), other.into());
                FheBool::new(
                    inner,
                    cpu_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("gpu does not support strings contains");
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_) => {
                panic!("hpu does not support contains");
            }
        })
    }

    fn starts_with(&self, other: &ClearString) -> FheBool {
        with_internal_keys(|keys| match keys {
            InternalServerKey::Cpu(cpu_key) => {
                let inner = cpu_key
                    .string_key()
                    .starts_with(&self.inner.on_cpu(), other.into());
                FheBool::new(
                    inner,
                    cpu_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("gpu does not support strings starts_with");
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_) => {
                panic!("hpu does not support starts_with");
            }
        })
    }

    fn ends_with(&self, other: &ClearString) -> FheBool {
        with_internal_keys(|keys| match keys {
            InternalServerKey::Cpu(cpu_key) => {
                let inner = cpu_key
                    .string_key()
                    .ends_with(&self.inner.on_cpu(), other.into());
                FheBool::new(
                    inner,
                    cpu_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("gpu does not support strings ends_with");
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_) => {
                panic!("hpu does not support ends_with");
            }
        })
    }
}
