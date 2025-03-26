use crate::high_level_api::global_state::with_internal_keys;
use crate::high_level_api::keys::InternalServerKey;
use crate::prelude::FheStringSplitOnce;
use crate::{ClearString, FheAsciiString, FheBool};

impl FheStringSplitOnce<&Self> for FheAsciiString {
    /// Splits the encrypted string into two substrings at the first occurrence of the pattern
    /// and returns a tuple of the two substrings along with a boolean
    /// indicating if the split occurred.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{
    ///     generate_keys, set_server_key, ClearString, ConfigBuilder, FheAsciiString,
    ///     FheStringIsEmpty, FheStringLen,
    /// };
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let string = FheAsciiString::try_encrypt("tfhe is an fhe scheme", &client_key).unwrap();
    /// let separator = FheAsciiString::try_encrypt(" ", &client_key).unwrap();
    ///
    /// // separator is found
    /// let (lhs, rhs, split_occurred) = string.split_once(&separator);
    /// assert!(split_occurred.decrypt(&client_key));
    /// let lhs_decrypted = lhs.decrypt(&client_key);
    /// assert_eq!(&lhs_decrypted, "tfhe");
    /// let rhs_decrypted = rhs.decrypt(&client_key);
    /// assert_eq!(&rhs_decrypted, "is an fhe scheme");
    ///
    /// // separator is not found
    /// let separator = ClearString::new("_".to_string());
    /// let (lhs, rhs, split_occurred) = string.split_once(&separator);
    /// assert!(!split_occurred.decrypt(&client_key));
    /// let lhs_decrypted = lhs.decrypt(&client_key);
    /// assert_eq!(&lhs_decrypted, "");
    /// let rhs_decrypted = rhs.decrypt(&client_key);
    /// assert_eq!(&rhs_decrypted, "fhe is an fhe scheme");
    /// ```
    fn split_once(&self, pat: &Self) -> (Self, Self, FheBool) {
        with_internal_keys(|keys| match keys {
            InternalServerKey::Cpu(cpu_key) => {
                let (inner_1, inner_2, inner_3) = cpu_key
                    .string_key()
                    .split_once(&self.inner.on_cpu(), (&*pat.inner.on_cpu()).into());
                (
                    Self::new(inner_1, cpu_key.tag.clone()),
                    Self::new(inner_2, cpu_key.tag.clone()),
                    FheBool::new(inner_3, cpu_key.tag.clone()),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("gpu does not support strings split_once");
            }
        })
    }

    /// Splits the encrypted string into two substrings at the last occurrence of the pattern
    /// and returns a tuple of the two substrings along with a boolean
    /// indicating if the split occurred.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{
    ///     generate_keys, set_server_key, ClearString, ConfigBuilder, FheAsciiString,
    ///     FheStringIsEmpty, FheStringLen,
    /// };
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let string = FheAsciiString::try_encrypt("tfhe is an fhe scheme", &client_key).unwrap();
    /// let separator = FheAsciiString::try_encrypt(" ", &client_key).unwrap();
    ///
    /// let (lhs, rhs, split_occurred) = string.rsplit_once(&separator);
    /// assert!(split_occurred.decrypt(&client_key));
    /// let lhs_decrypted = lhs.decrypt(&client_key);
    /// assert_eq!(&lhs_decrypted, "tfhe is an fhe");
    /// let rhs_decrypted = rhs.decrypt(&client_key);
    /// assert_eq!(&rhs_decrypted, "scheme");
    /// ```
    fn rsplit_once(&self, pat: &Self) -> (Self, Self, FheBool) {
        with_internal_keys(|keys| match keys {
            InternalServerKey::Cpu(cpu_key) => {
                let (inner_1, inner_2, inner_3) = cpu_key
                    .string_key()
                    .rsplit_once(&self.inner.on_cpu(), (&*pat.inner.on_cpu()).into());
                (
                    Self::new(inner_1, cpu_key.tag.clone()),
                    Self::new(inner_2, cpu_key.tag.clone()),
                    FheBool::new(inner_3, cpu_key.tag.clone()),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("gpu does not support strings rsplit_once");
            }
        })
    }
}

impl FheStringSplitOnce<&ClearString> for FheAsciiString {
    /// Splits the encrypted string into two substrings at the first occurrence of the pattern
    /// and returns a tuple of the two substrings along with a boolean
    /// indicating if the split occurred.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{
    ///     generate_keys, set_server_key, ClearString, ConfigBuilder, FheAsciiString,
    ///     FheStringIsEmpty, FheStringLen,
    /// };
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let string = FheAsciiString::try_encrypt("tfhe is an fhe scheme", &client_key).unwrap();
    /// let separator = ClearString::new(" ".to_string());
    ///
    /// // separator is found
    /// let (lhs, rhs, split_occurred) = string.split_once(&separator);
    /// assert!(split_occurred.decrypt(&client_key));
    /// let lhs_decrypted = lhs.decrypt(&client_key);
    /// assert_eq!(&lhs_decrypted, "tfhe");
    /// let rhs_decrypted = rhs.decrypt(&client_key);
    /// assert_eq!(&rhs_decrypted, "is an fhe scheme");
    /// ```
    fn split_once(&self, pat: &ClearString) -> (Self, Self, FheBool) {
        with_internal_keys(|keys| match keys {
            InternalServerKey::Cpu(cpu_key) => {
                let (inner_1, inner_2, inner_3) = cpu_key
                    .string_key()
                    .split_once(&self.inner.on_cpu(), pat.into());
                (
                    Self::new(inner_1, cpu_key.tag.clone()),
                    Self::new(inner_2, cpu_key.tag.clone()),
                    FheBool::new(inner_3, cpu_key.tag.clone()),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("gpu does not support strings split_once");
            }
        })
    }

    /// Splits the encrypted string into two substrings at the last occurrence of the pattern
    /// and returns a tuple of the two substrings along with a boolean
    /// indicating if the split occurred.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{
    ///     generate_keys, set_server_key, ClearString, ConfigBuilder, FheAsciiString,
    ///     FheStringIsEmpty, FheStringLen,
    /// };
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let string = FheAsciiString::try_encrypt("tfhe is an fhe scheme", &client_key).unwrap();
    /// let separator = ClearString::new(" ".to_string());
    ///
    /// let (lhs, rhs, split_occurred) = string.rsplit_once(&separator);
    /// assert!(split_occurred.decrypt(&client_key));
    /// let lhs_decrypted = lhs.decrypt(&client_key);
    /// assert_eq!(&lhs_decrypted, "tfhe is an fhe");
    /// let rhs_decrypted = rhs.decrypt(&client_key);
    /// assert_eq!(&rhs_decrypted, "scheme");
    /// ```
    fn rsplit_once(&self, pat: &ClearString) -> (Self, Self, FheBool) {
        with_internal_keys(|keys| match keys {
            InternalServerKey::Cpu(cpu_key) => {
                let (inner_1, inner_2, inner_3) = cpu_key
                    .string_key()
                    .rsplit_once(&self.inner.on_cpu(), pat.into());
                (
                    Self::new(inner_1, cpu_key.tag.clone()),
                    Self::new(inner_2, cpu_key.tag.clone()),
                    FheBool::new(inner_3, cpu_key.tag.clone()),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("gpu does not support strings rsplit_once");
            }
        })
    }
}
