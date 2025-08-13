use crate::high_level_api::global_state::with_internal_keys;
use crate::high_level_api::keys::InternalServerKey;
use crate::high_level_api::re_randomization::ReRandomizationMetadata;
use crate::high_level_api::strings::ascii::FheAsciiString;

impl FheAsciiString {
    /// Returns a new encrypted string with whitespace removed from the start.
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
    /// let string = FheAsciiString::try_encrypt("   tfhe-rs   ", &client_key).unwrap();
    /// let trimmed = string.trim_start();
    /// let dec = trimmed.decrypt(&client_key);
    /// assert_eq!(&dec, "tfhe-rs   ");
    /// ```
    pub fn trim_start(&self) -> Self {
        with_internal_keys(|keys| match keys {
            InternalServerKey::Cpu(cpu_key) => {
                let inner = cpu_key.string_key().trim_start(&self.inner.on_cpu());
                Self::new(
                    inner,
                    cpu_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("gpu does not support trim_start");
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_) => {
                panic!("hpu does not support trim_start");
            }
        })
    }

    /// Returns a new encrypted string with whitespace removed from the end.
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
    /// let string = FheAsciiString::try_encrypt("   tfhe-rs   ", &client_key).unwrap();
    /// let trimmed = string.trim_end();
    /// let dec = trimmed.decrypt(&client_key);
    /// assert_eq!(&dec, "   tfhe-rs");
    /// ```
    pub fn trim_end(&self) -> Self {
        with_internal_keys(|keys| match keys {
            InternalServerKey::Cpu(cpu_key) => {
                let inner = cpu_key.string_key().trim_end(&self.inner.on_cpu());
                Self::new(
                    inner,
                    cpu_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("gpu does not support trim_end");
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_) => {
                panic!("hpu does not support trim_end");
            }
        })
    }

    /// Returns a new encrypted string with whitespace removed from both the start and end.
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
    /// let string = FheAsciiString::try_encrypt("   tfhe-rs   ", &client_key).unwrap();
    /// let trimmed = string.trim();
    /// let dec = trimmed.decrypt(&client_key);
    /// assert_eq!(&dec, "tfhe-rs");
    /// ```
    pub fn trim(&self) -> Self {
        with_internal_keys(|keys| match keys {
            InternalServerKey::Cpu(cpu_key) => {
                let inner = cpu_key.string_key().trim(&self.inner.on_cpu());
                Self::new(
                    inner,
                    cpu_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("gpu does not support trim");
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_) => {
                panic!("hpu does not support trim");
            }
        })
    }
}
