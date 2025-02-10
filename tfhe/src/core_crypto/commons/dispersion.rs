//! Module containing noise distribution primitives.
//!
//! When dealing with noise, we tend to use different representation for the same value. In
//! general, the noise is specified by the standard deviation of a gaussian distribution, which
//! is of the form $\sigma = 2^p$, with $p$ a negative integer. Depending on the use case though,
//! we rely on different representations for this quantity:
//!
//! + $\sigma$ can be encoded in the [`StandardDev`] type.
//! + $\sigma^2$ can be encoded in the [`Variance`] type.
//!
//! In any of those cases, the corresponding type implements the `DispersionParameter` trait,
//! which makes if possible to use any of those representations generically when noise must be
//! defined.

use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

use crate::core_crypto::backward_compatibility::commons::dispersion::StandardDevVersions;

/// A trait for types representing distribution parameters, for a given unsigned integer type.
//  Warning:
//  DispersionParameter type should ONLY wrap a single native type.
//  As long as Variance wraps a native type (f64) it is ok to derive it from Copy instead of
//  Clone because f64 is itself Copy and stored in register.
pub trait DispersionParameter: Copy {
    /// Return the standard deviation of the distribution, i.e. $\sigma = 2^p$.
    fn get_standard_dev(&self) -> StandardDev;
    /// Return the variance of the distribution, i.e. $\sigma^2 = 2^{2p}$.
    fn get_variance(&self) -> Variance;

    /// For a `Uint` type representing $\mathbb{Z}/2^q\mathbb{Z}$, we return $2^{2(q-p)}$.
    fn get_modular_variance(&self, log2_modulus: u32) -> ModularVariance;
}

fn log2_modulus_to_modulus(log2_modulus: u32) -> f64 {
    2.0f64.powi(log2_modulus as i32)
}

/// A distribution parameter that uses the standard deviation as representation.
///
/// # Example:
///
/// ```rust
/// use tfhe::core_crypto::commons::dispersion::{DispersionParameter, StandardDev};
/// let params = StandardDev::from_standard_dev(2_f64.powf(-25.));
/// assert_eq!(params.get_standard_dev().0, 2_f64.powf(-25.));
/// assert_eq!(params.get_variance().0, 2_f64.powf(-25.).powi(2));
/// assert_eq!(
///     params.get_modular_variance(32).value,
///     2_f64.powf(32. - 25.).powi(2)
/// );
/// ```
#[derive(Debug, Copy, Clone, PartialEq, PartialOrd, Serialize, Deserialize, Versionize)]
#[versionize(StandardDevVersions)]
pub struct StandardDev(pub f64);

impl StandardDev {
    pub fn from_standard_dev(std: f64) -> Self {
        Self(std)
    }

    pub fn from_log_standard_dev(log_std: f64) -> Self {
        Self(2_f64.powf(log_std))
    }

    pub fn from_modular_standard_dev(std: f64, log2_modulus: u32) -> Self {
        Self(std / 2_f64.powf(log2_modulus as f64))
    }
}

impl DispersionParameter for StandardDev {
    fn get_standard_dev(&self) -> Self {
        Self(self.0)
    }
    fn get_variance(&self) -> Variance {
        Variance(self.0.powi(2))
    }
    fn get_modular_variance(&self, log2_modulus: u32) -> ModularVariance {
        ModularVariance {
            value: 2_f64.powf(2. * (log2_modulus as f64 + self.0.log2())),
            modulus: log2_modulus_to_modulus(log2_modulus),
        }
    }
}

/// A distribution parameter that uses the variance as representation
///
/// # Example:
///
/// ```rust
/// use tfhe::core_crypto::commons::dispersion::{DispersionParameter, Variance};
/// let params = Variance::from_variance(2_f64.powi(-50));
/// assert_eq!(params.get_standard_dev().0, 2_f64.powf(-25.));
/// assert_eq!(params.get_variance().0, 2_f64.powf(-25.).powi(2));
/// assert_eq!(
///     params.get_modular_variance(32).value,
///     2_f64.powf(32. - 25.).powi(2)
/// );
/// ```
#[derive(Debug, Copy, Clone, PartialEq, PartialOrd)]
pub struct Variance(pub f64);

#[derive(Debug, Copy, Clone, PartialEq, PartialOrd)]
pub struct ModularVariance {
    pub value: f64,
    pub modulus: f64,
}

impl Variance {
    pub fn from_variance(var: f64) -> Self {
        Self(var)
    }

    pub fn from_modular_variance(var: f64, log2_modulus: u32) -> Self {
        Self(var / 2_f64.powf(log2_modulus as f64 * 2.))
    }
}

impl DispersionParameter for Variance {
    fn get_standard_dev(&self) -> StandardDev {
        StandardDev(self.0.sqrt())
    }
    fn get_variance(&self) -> Self {
        Self(self.0)
    }
    fn get_modular_variance(&self, log2_modulus: u32) -> ModularVariance {
        ModularVariance {
            value: 2_f64.powf(2. * (log2_modulus as f64 + self.0.sqrt().log2())),
            modulus: log2_modulus_to_modulus(log2_modulus),
        }
    }
}
