use crate::high_level_api::global_state::with_internal_keys;
use crate::high_level_api::keys::InternalServerKey;
use crate::high_level_api::re_randomization::ReRandomizationMetadata;
use crate::high_level_api::strings::ascii::FheAsciiString;
use crate::high_level_api::strings::traits::FheStringReplace;
use crate::prelude::FheStringReplaceN;
use crate::strings::ciphertext::{ClearString, UIntArg};
use crate::strings::client_key::EncU16;
use crate::FheUint16;

impl FheStringReplace<&Self> for FheAsciiString {
    /// Returns a new encrypted string with all non-overlapping occurrences of a pattern
    /// replaced by another specified encrypted pattern.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheAsciiString};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let string = FheAsciiString::try_encrypt("tfhe is an fhe scheme", &client_key).unwrap();
    /// let pattern = FheAsciiString::try_encrypt("fhe", &client_key).unwrap();
    /// let new_val = FheAsciiString::try_encrypt("cookie", &client_key).unwrap();
    /// let replaced = string.replace(&pattern, &new_val);
    ///
    /// let dec = replaced.decrypt(&client_key);
    /// assert_eq!(&dec, "tcookie is an cookie scheme");
    /// ```
    fn replace(&self, from: &Self, to: &Self) -> Self {
        with_internal_keys(|keys| match keys {
            InternalServerKey::Cpu(cpu_key) => {
                let inner = cpu_key.string_key().replace(
                    &self.inner.on_cpu(),
                    (&*from.inner.on_cpu()).into(),
                    &to.inner.on_cpu(),
                );
                Self::new(
                    inner,
                    cpu_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("gpu does not support strings replace");
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_) => {
                panic!("hpu does not support strings replace");
            }
        })
    }
}

impl FheStringReplace<&ClearString> for FheAsciiString {
    /// Returns a new encrypted string with all non-overlapping occurrences of a pattern
    /// replaced by another specified encrypted pattern.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ClearString, ConfigBuilder, FheAsciiString};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let string = FheAsciiString::try_encrypt("tfhe is an fhe scheme", &client_key).unwrap();
    /// let pattern = ClearString::new("fhe".into());
    /// let new_val = FheAsciiString::try_encrypt("cookie", &client_key).unwrap();
    /// let replaced = string.replace(&pattern, &new_val);
    ///
    /// let dec = replaced.decrypt(&client_key);
    /// assert_eq!(&dec, "tcookie is an cookie scheme");
    /// ```
    fn replace(&self, from: &ClearString, to: &Self) -> Self {
        with_internal_keys(|keys| match keys {
            InternalServerKey::Cpu(cpu_key) => {
                let inner = cpu_key.string_key().replace(
                    &self.inner.on_cpu(),
                    from.into(),
                    &to.inner.on_cpu(),
                );
                Self::new(
                    inner,
                    cpu_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("gpu does not support strings replace");
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_) => {
                panic!("hpu does not support strings replace");
            }
        })
    }
}

impl FheStringReplaceN<&Self, i32> for FheAsciiString {
    fn replacen(&self, from: &Self, to: &Self, count: i32) -> Self {
        self.replacen(from, to, count as u16)
    }
}

impl FheStringReplaceN<&Self, usize> for FheAsciiString {
    fn replacen(&self, from: &Self, to: &Self, count: usize) -> Self {
        self.replacen(from, to, count as u16)
    }
}

impl FheStringReplaceN<&Self, u32> for FheAsciiString {
    fn replacen(&self, from: &Self, to: &Self, count: u32) -> Self {
        self.replacen(from, to, count as u16)
    }
}

impl FheStringReplaceN<&Self, u16> for FheAsciiString {
    fn replacen(&self, from: &Self, to: &Self, count: u16) -> Self {
        with_internal_keys(|keys| match keys {
            InternalServerKey::Cpu(cpu_key) => {
                let inner = cpu_key.string_key().replacen(
                    &self.inner.on_cpu(),
                    (&*from.inner.on_cpu()).into(),
                    &to.inner.on_cpu(),
                    &UIntArg::Clear(count),
                );
                Self::new(
                    inner,
                    cpu_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("gpu does not support strings replacen");
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_) => {
                panic!("hpu does not support strings replacen");
            }
        })
    }
}

impl FheStringReplaceN<&Self, (FheUint16, u16)> for FheAsciiString {
    fn replacen(&self, from: &Self, to: &Self, (count, max): (FheUint16, u16)) -> Self {
        with_internal_keys(|keys| match keys {
            InternalServerKey::Cpu(cpu_key) => {
                let inner = cpu_key.string_key().replacen(
                    &self.inner.on_cpu(),
                    (&*from.inner.on_cpu()).into(),
                    &to.inner.on_cpu(),
                    &UIntArg::Enc(EncU16::new(count.ciphertext.into_cpu(), Some(max))),
                );
                Self::new(
                    inner,
                    cpu_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("gpu does not support strings replacen");
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_) => {
                panic!("hpu does not support strings replacen");
            }
        })
    }
}

impl FheStringReplaceN<&ClearString, i32> for FheAsciiString {
    fn replacen(&self, from: &ClearString, to: &Self, count: i32) -> Self {
        self.replacen(from, to, count as u16)
    }
}

impl FheStringReplaceN<&ClearString, usize> for FheAsciiString {
    fn replacen(&self, from: &ClearString, to: &Self, count: usize) -> Self {
        self.replacen(from, to, count as u16)
    }
}

impl FheStringReplaceN<&ClearString, u32> for FheAsciiString {
    fn replacen(&self, from: &ClearString, to: &Self, count: u32) -> Self {
        self.replacen(from, to, count as u16)
    }
}

impl FheStringReplaceN<&ClearString, u16> for FheAsciiString {
    fn replacen(&self, from: &ClearString, to: &Self, count: u16) -> Self {
        with_internal_keys(|keys| match keys {
            InternalServerKey::Cpu(cpu_key) => {
                let inner = cpu_key.string_key().replacen(
                    &self.inner.on_cpu(),
                    from.into(),
                    &to.inner.on_cpu(),
                    &UIntArg::Clear(count),
                );
                Self::new(
                    inner,
                    cpu_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("gpu does not support strings replacen");
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_) => {
                panic!("hpu does not support strings replacen");
            }
        })
    }
}

impl FheStringReplaceN<&ClearString, (FheUint16, u16)> for FheAsciiString {
    fn replacen(&self, from: &ClearString, to: &Self, (count, max): (FheUint16, u16)) -> Self {
        with_internal_keys(|keys| match keys {
            InternalServerKey::Cpu(cpu_key) => {
                let inner = cpu_key.string_key().replacen(
                    &self.inner.on_cpu(),
                    from.into(),
                    &to.inner.on_cpu(),
                    &UIntArg::Enc(EncU16::new(count.ciphertext.into_cpu(), Some(max))),
                );
                Self::new(
                    inner,
                    cpu_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("gpu does not support strings replacen");
            }

            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_) => {
                panic!("hpu does not support strings replacen");
            }
        })
    }
}
