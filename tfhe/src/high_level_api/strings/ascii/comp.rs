use crate::high_level_api::global_state::with_internal_keys;
use crate::high_level_api::keys::InternalServerKey;
use crate::high_level_api::re_randomization::ReRandomizationMetadata;
use crate::high_level_api::strings::ascii::FheAsciiString;
use crate::prelude::{FheEq, FheEqIgnoreCase, FheOrd};
use crate::strings::ciphertext::ClearString;
use crate::FheBool;

impl FheEq<&Self> for FheAsciiString {
    fn eq(&self, other: &Self) -> FheBool {
        with_internal_keys(|keys| match keys {
            InternalServerKey::Cpu(cpu_key) => {
                let inner = cpu_key
                    .string_key()
                    .eq(&self.inner.on_cpu(), (&*other.inner.on_cpu()).into());
                FheBool::new(
                    inner,
                    cpu_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("gpu does not support strings eq");
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_) => {
                panic!("Hpu does not support this operation yet.")
            }
        })
    }

    fn ne(&self, other: &Self) -> FheBool {
        with_internal_keys(|keys| match keys {
            InternalServerKey::Cpu(cpu_key) => {
                let inner = cpu_key
                    .string_key()
                    .ne(&self.inner.on_cpu(), (&*other.inner.on_cpu()).into());
                FheBool::new(
                    inner,
                    cpu_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("gpu does not support strings ne");
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_) => {
                panic!("Hpu does not support this operation yet.")
            }
        })
    }
}

impl FheEq<&ClearString> for FheAsciiString {
    fn eq(&self, other: &ClearString) -> FheBool {
        with_internal_keys(|keys| match keys {
            InternalServerKey::Cpu(cpu_key) => {
                let inner = cpu_key.string_key().eq(&self.inner.on_cpu(), other.into());
                FheBool::new(
                    inner,
                    cpu_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("gpu does not support strings eq");
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_) => {
                panic!("Hpu does not support this operation yet.")
            }
        })
    }

    fn ne(&self, other: &ClearString) -> FheBool {
        with_internal_keys(|keys| match keys {
            InternalServerKey::Cpu(cpu_key) => {
                let inner = cpu_key.string_key().ne(&self.inner.on_cpu(), other.into());
                FheBool::new(
                    inner,
                    cpu_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("gpu does not support strings ne");
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_) => {
                panic!("Hpu does not support this operation yet.")
            }
        })
    }
}

impl FheOrd<&Self> for FheAsciiString {
    fn lt(&self, other: &Self) -> FheBool {
        with_internal_keys(|keys| match keys {
            InternalServerKey::Cpu(cpu_key) => {
                let inner = cpu_key
                    .string_key()
                    .lt(&self.inner.on_cpu(), (&*other.inner.on_cpu()).into());
                FheBool::new(
                    inner,
                    cpu_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("gpu does not support strings lt");
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_) => {
                panic!("Hpu does not support this operation yet.")
            }
        })
    }

    fn le(&self, other: &Self) -> FheBool {
        with_internal_keys(|keys| match keys {
            InternalServerKey::Cpu(cpu_key) => {
                let inner = cpu_key
                    .string_key()
                    .le(&self.inner.on_cpu(), (&*other.inner.on_cpu()).into());
                FheBool::new(
                    inner,
                    cpu_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("gpu does not support strings le");
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_) => {
                panic!("Hpu does not support this operation yet.")
            }
        })
    }

    fn gt(&self, other: &Self) -> FheBool {
        with_internal_keys(|keys| match keys {
            InternalServerKey::Cpu(cpu_key) => {
                let inner = cpu_key
                    .string_key()
                    .gt(&self.inner.on_cpu(), (&*other.inner.on_cpu()).into());
                FheBool::new(
                    inner,
                    cpu_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("gpu does not support strings gt");
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_) => {
                panic!("Hpu does not support this operation yet.")
            }
        })
    }

    fn ge(&self, other: &Self) -> FheBool {
        with_internal_keys(|keys| match keys {
            InternalServerKey::Cpu(cpu_key) => {
                let inner = cpu_key
                    .string_key()
                    .ge(&self.inner.on_cpu(), (&*other.inner.on_cpu()).into());
                FheBool::new(
                    inner,
                    cpu_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("gpu does not support strings ge");
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_) => {
                panic!("Hpu does not support this operation yet.")
            }
        })
    }
}

impl FheOrd<&ClearString> for FheAsciiString {
    fn lt(&self, other: &ClearString) -> FheBool {
        with_internal_keys(|keys| match keys {
            InternalServerKey::Cpu(cpu_key) => {
                let inner = cpu_key.string_key().lt(&self.inner.on_cpu(), other.into());
                FheBool::new(
                    inner,
                    cpu_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("gpu does not support strings lt");
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_) => {
                panic!("Hpu does not support this operation yet.")
            }
        })
    }

    fn le(&self, other: &ClearString) -> FheBool {
        with_internal_keys(|keys| match keys {
            InternalServerKey::Cpu(cpu_key) => {
                let inner = cpu_key.string_key().le(&self.inner.on_cpu(), other.into());
                FheBool::new(
                    inner,
                    cpu_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("gpu does not support strings le");
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_) => {
                panic!("Hpu does not support this operation yet.")
            }
        })
    }

    fn gt(&self, other: &ClearString) -> FheBool {
        with_internal_keys(|keys| match keys {
            InternalServerKey::Cpu(cpu_key) => {
                let inner = cpu_key.string_key().gt(&self.inner.on_cpu(), other.into());
                FheBool::new(
                    inner,
                    cpu_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("gpu does not support strings gt");
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_) => {
                panic!("Hpu does not support this operation yet.")
            }
        })
    }

    fn ge(&self, other: &ClearString) -> FheBool {
        with_internal_keys(|keys| match keys {
            InternalServerKey::Cpu(cpu_key) => {
                let inner = cpu_key.string_key().ge(&self.inner.on_cpu(), other.into());
                FheBool::new(
                    inner,
                    cpu_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("gpu does not support strings ge");
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_) => {
                panic!("Hpu does not support this operation yet.")
            }
        })
    }
}

impl FheEqIgnoreCase for FheAsciiString {
    /// checks if the strings are equal, ignoring the case
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
    /// let string1 = FheAsciiString::try_encrypt("tfhe-RS", &client_key).unwrap();
    /// let string2 = FheAsciiString::try_encrypt("TFHE-rs", &client_key).unwrap();
    /// let is_eq = string1.eq_ignore_case(&string2);
    ///
    /// assert!(is_eq.decrypt(&client_key));
    /// ```
    fn eq_ignore_case(&self, rhs: &Self) -> FheBool {
        with_internal_keys(|keys| match keys {
            InternalServerKey::Cpu(cpu_key) => {
                let inner = cpu_key
                    .string_key()
                    .eq_ignore_case(&self.inner.on_cpu(), (&*rhs.inner.on_cpu()).into());
                FheBool::new(
                    inner,
                    cpu_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("gpu does not support strings eq_ignore_case");
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_) => {
                panic!("Hpu does not support this operation yet.")
            }
        })
    }
}

impl FheEqIgnoreCase<ClearString> for FheAsciiString {
    /// checks if the strings are equal, ignoring the case
    ///
    /// Returns a [FheBool] that encrypts `true` if the substring was found.
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
    /// let string1 = FheAsciiString::try_encrypt("tfhe-RS", &client_key).unwrap();
    /// let string2 = ClearString::new("TFHE-rs".into());
    /// let is_eq = string1.eq_ignore_case(&string2);
    ///
    /// assert!(is_eq.decrypt(&client_key));
    /// ```
    fn eq_ignore_case(&self, rhs: &ClearString) -> FheBool {
        with_internal_keys(|keys| match keys {
            InternalServerKey::Cpu(cpu_key) => {
                let inner = cpu_key
                    .string_key()
                    .eq_ignore_case(&self.inner.on_cpu(), rhs.into());
                FheBool::new(
                    inner,
                    cpu_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("gpu does not support strings eq_ignore_case");
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_) => {
                panic!("Hpu does not support this operation yet.")
            }
        })
    }
}
