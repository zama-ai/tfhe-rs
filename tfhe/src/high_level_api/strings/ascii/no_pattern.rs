use crate::high_level_api::global_state::with_internal_keys;
use crate::high_level_api::integers::FheUint16;
use crate::high_level_api::keys::InternalServerKey;
use crate::high_level_api::re_randomization::ReRandomizationMetadata;
use crate::high_level_api::strings::ascii::FheAsciiString;
use crate::high_level_api::traits::FheTrivialEncrypt;
use crate::prelude::FheStringRepeat;
use crate::strings::ciphertext::UIntArg;
use crate::strings::client_key::EncU16;
use crate::{FheBool, Tag};

pub enum FheStringLen {
    NoPadding(u16),
    Padding(FheUint16),
}

impl FheStringLen {
    /// Transforms self into a ciphertext if it is not already.
    ///
    /// If self contains a clear value, the ciphertext is a trivial encryption
    pub fn into_ciphertext(self) -> FheUint16 {
        match self {
            Self::NoPadding(clear_len) => FheUint16::encrypt_trivial(clear_len),
            Self::Padding(len) => len,
        }
    }
}

impl From<crate::strings::server_key::FheStringLen> for FheStringLen {
    fn from(value: crate::strings::server_key::FheStringLen) -> Self {
        match value {
            crate::strings::server_key::FheStringLen::NoPadding(v) => Self::NoPadding(v as u16),
            crate::strings::server_key::FheStringLen::Padding(v) => Self::Padding(FheUint16::new(
                v,
                Tag::default(),
                ReRandomizationMetadata::default(),
            )),
        }
    }
}

pub enum FheStringIsEmpty {
    NoPadding(bool),
    Padding(FheBool),
}

impl FheStringIsEmpty {
    /// Transforms self into a ciphertext if it is not already.
    ///
    /// If self contains a clear value, the ciphertext is a trivial encryption
    pub fn into_ciphertext(self) -> FheBool {
        match self {
            Self::NoPadding(clear_r) => FheBool::encrypt_trivial(clear_r),
            Self::Padding(r) => r,
        }
    }
}

impl From<crate::strings::server_key::FheStringIsEmpty> for FheStringIsEmpty {
    fn from(value: crate::strings::server_key::FheStringIsEmpty) -> Self {
        match value {
            crate::strings::server_key::FheStringIsEmpty::NoPadding(v) => Self::NoPadding(v),
            crate::strings::server_key::FheStringIsEmpty::Padding(bool_block) => {
                Self::Padding(FheBool::new(
                    bool_block,
                    Tag::default(),
                    ReRandomizationMetadata::default(),
                ))
            }
        }
    }
}

impl FheAsciiString {
    /// Returns the length of an encrypted string as an `FheStringLen` enum.
    ///
    /// * If the encrypted string has no padding, the length is the clear length of the char vector.
    /// * If there is padding, the length is calculated homomorphically and returned encrypted.
    ///
    /// ```
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheAsciiString, FheStringLen};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let string = FheAsciiString::try_encrypt("tfhe-rs", &client_key).unwrap();
    /// match string.len() {
    ///     FheStringLen::NoPadding(length) => assert_eq!(length, 7),
    ///     FheStringLen::Padding(_) => panic!("Unexpected padding"),
    /// }
    ///
    /// let string = FheAsciiString::try_encrypt_with_padding("tfhe-rs", 5, &client_key).unwrap();
    /// match string.len() {
    ///     FheStringLen::NoPadding(_) => panic!("Unexpected no padding"),
    ///     FheStringLen::Padding(enc_len) => {
    ///         let len: u16 = enc_len.decrypt(&client_key);
    ///         assert_eq!(len, 7);
    ///     }
    /// }
    /// ```
    pub fn len(&self) -> FheStringLen {
        with_internal_keys(|keys| match keys {
            InternalServerKey::Cpu(cpu_key) => {
                let mut len = cpu_key.string_key().len(&self.inner.on_cpu()).into();
                if let FheStringLen::Padding(len) = &mut len {
                    len.tag = cpu_key.tag.clone();
                }
                len
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("gpu does not support strings len");
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_) => {
                panic!("hpu does not support strings len");
            }
        })
    }

    /// Returns whether an encrypted string is empty or not as an `FheStringIsEmpty` enum.
    ///
    /// If the encrypted string has no padding, the result is a clear boolean.
    /// If there is padding, the result is calculated homomorphically and returned as [FheBool]
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheAsciiString, FheStringIsEmpty};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let string = FheAsciiString::try_encrypt("", &client_key).unwrap();
    /// match string.is_empty() {
    ///     FheStringIsEmpty::NoPadding(is_empty) => assert!(is_empty),
    ///     FheStringIsEmpty::Padding(_) => panic!("Unexpected padding"),
    /// }
    ///
    /// let string = FheAsciiString::try_encrypt_with_padding("", 5, &client_key).unwrap();
    /// match string.is_empty() {
    ///     FheStringIsEmpty::NoPadding(_) => panic!("Unexpected no padding"),
    ///     FheStringIsEmpty::Padding(enc_is_empty) => {
    ///         let is_empty: bool = enc_is_empty.decrypt(&client_key);
    ///         assert!(is_empty);
    ///     }
    /// }
    /// ```
    pub fn is_empty(&self) -> FheStringIsEmpty {
        with_internal_keys(|keys| match keys {
            InternalServerKey::Cpu(cpu_key) => {
                let mut result = cpu_key.string_key().is_empty(&self.inner.on_cpu()).into();
                if let FheStringIsEmpty::Padding(r) = &mut result {
                    r.tag = cpu_key.tag.clone();
                }
                result
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("gpu does not support strings is_empty");
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_) => {
                panic!("hpu does not support strings is_empty");
            }
        })
    }

    /// Returns a new encrypted string with all characters converted to lowercase.
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
    /// let string = FheAsciiString::try_encrypt("TfHe-RS", &client_key).unwrap();
    /// let lower = string.to_lowercase();
    ///
    /// let dec = lower.decrypt(&client_key);
    /// assert_eq!(&dec, "tfhe-rs");
    /// ```
    pub fn to_lowercase(&self) -> Self {
        with_internal_keys(|keys| match keys {
            InternalServerKey::Cpu(cpu_key) => {
                let inner = cpu_key.string_key().to_lowercase(&self.inner.on_cpu());
                Self::new(
                    inner,
                    cpu_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("gpu does not support strings to_lowercase");
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_) => {
                panic!("hpu does not support strings to_lowercase");
            }
        })
    }

    /// Returns a new encrypted string with all characters converted to uppercase.
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
    /// let string = FheAsciiString::try_encrypt("TfHe-RS", &client_key).unwrap();
    /// let upper = string.to_uppercase();
    ///
    /// let dec = upper.decrypt(&client_key);
    /// assert_eq!(&dec, "TFHE-RS");
    /// ```
    pub fn to_uppercase(&self) -> Self {
        with_internal_keys(|keys| match keys {
            InternalServerKey::Cpu(cpu_key) => {
                let inner = cpu_key.string_key().to_uppercase(&self.inner.on_cpu());
                Self::new(
                    inner,
                    cpu_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("gpu does not support strings to_uppercase");
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_) => {
                panic!("hpu does not support strings to_uppercase");
            }
        })
    }

    /// Concatenates two encrypted strings and returns the result as a new encrypted string.
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
    /// let string1 = FheAsciiString::try_encrypt("tfhe", &client_key).unwrap();
    /// let string2 = FheAsciiString::try_encrypt("-rs", &client_key).unwrap();
    /// let string = string1.concat(&string2);
    ///
    /// let dec = string.decrypt(&client_key);
    /// assert_eq!(&dec, "tfhe-rs");
    /// ```
    pub fn concat(&self, other: &Self) -> Self {
        with_internal_keys(|keys| match keys {
            InternalServerKey::Cpu(cpu_key) => {
                let inner = cpu_key
                    .string_key()
                    .concat(&self.inner.on_cpu(), &other.inner.on_cpu());
                Self::new(
                    inner,
                    cpu_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("gpu does not support strings concatenating");
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_) => {
                panic!("hpu does not support strings concatenating");
            }
        })
    }
}

// Overload for u32 as it's a common type
impl FheStringRepeat<u32> for FheAsciiString {
    fn repeat(&self, count: u32) -> Self {
        self.repeat(count as u16)
    }
}

// Overload for usize as it's a common type
impl FheStringRepeat<usize> for FheAsciiString {
    fn repeat(&self, count: usize) -> Self {
        self.repeat(count as u16)
    }
}

// Overload for usize as it's a common type (literals are i32 by default)
impl FheStringRepeat<i32> for FheAsciiString {
    fn repeat(&self, count: i32) -> Self {
        self.repeat(count as u16)
    }
}

impl FheStringRepeat<u16> for FheAsciiString {
    /// Repeats the string by the given clear count.
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
    /// let string = FheAsciiString::try_encrypt("tfhe ", &client_key).unwrap();
    /// let repeated = string.repeat(3);
    ///
    /// let dec = repeated.decrypt(&client_key);
    /// assert_eq!(&dec, "tfhe tfhe tfhe ");
    /// ```
    fn repeat(&self, count: u16) -> Self {
        with_internal_keys(|keys| match keys {
            InternalServerKey::Cpu(cpu_key) => {
                let inner = cpu_key
                    .string_key()
                    .repeat(&self.inner.on_cpu(), &UIntArg::Clear(count));
                Self::new(
                    inner,
                    cpu_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("gpu does not support strings repeat");
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_) => {
                panic!("hpu does not support strings repeat");
            }
        })
    }
}

impl FheStringRepeat<(FheUint16, u16)> for FheAsciiString {
    /// Repeats the string by the given encrypted amount.
    ///
    /// The count amount is a tuple containing the encrypted value
    /// as well as an upper bound for the count
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheAsciiString, FheUint16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let max = 4;
    /// let clear_amount = rand::random::<u16>() % max;
    /// let clear_string = "tfhe ";
    ///
    /// let string = FheAsciiString::try_encrypt(clear_string, &client_key).unwrap();
    /// let amount = FheUint16::encrypt(clear_amount, &client_key);
    /// let repeated = string.repeat((amount, max));
    ///
    /// let expected = clear_string.repeat(clear_amount as usize);
    /// let dec = repeated.decrypt(&client_key);
    /// assert_eq!(&dec, &expected);
    /// ```
    fn repeat(&self, (count, bound): (FheUint16, u16)) -> Self {
        with_internal_keys(|keys| match keys {
            InternalServerKey::Cpu(cpu_key) => {
                let inner = cpu_key.string_key().repeat(
                    &self.inner.on_cpu(),
                    &UIntArg::Enc(EncU16::new(count.ciphertext.into_cpu(), Some(bound))),
                );
                Self::new(
                    inner,
                    cpu_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("gpu does not support strings repeat");
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_) => {
                panic!("hpu does not support strings repeat");
            }
        })
    }
}
