use serde::{Deserialize, Serialize};

/// The number of elements in a partial GLWE secret key that are drawn from the random distribution.
#[derive(Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize)]
pub struct PartialGlweSecretKeyRandomCoefCount(pub usize);

/// The number of elements in a shared GLWE secret key that come from another key.
#[derive(Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize)]
pub struct GlweSecretKeySharedCoefCount(pub usize);

/// The number of elements in an LWE secret key shared with another key.
#[derive(Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize)]
pub struct LweSecretKeySharedCoefCount(pub usize);

/// The number of elements in an LWE secret key that are not shared with another key.
#[derive(Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize)]
pub struct LweSecretKeyUnsharedCoefCount(pub usize);

impl crate::core_crypto::commons::parameters::LweDimension {
    #[track_caller]
    pub fn shared_coef_count_from(
        &self,
        unshared_coef_count: LweSecretKeyUnsharedCoefCount,
    ) -> LweSecretKeySharedCoefCount {
        assert!(
            unshared_coef_count.0 <= self.0,
            "unshared_coef_count {unshared_coef_count:?} must be smaller than self {:?}",
            *self
        );
        LweSecretKeySharedCoefCount(self.0 - unshared_coef_count.0)
    }

    #[track_caller]
    pub fn unshared_coef_count_from(
        &self,
        shared_coef_count: LweSecretKeySharedCoefCount,
    ) -> LweSecretKeyUnsharedCoefCount {
        assert!(
            shared_coef_count.0 <= self.0,
            "shared_coef_count {shared_coef_count:?} must be smaller than self {:?}",
            *self
        );
        LweSecretKeyUnsharedCoefCount(self.0 - shared_coef_count.0)
    }
}

/// Parameter indicating by how much a LUT polynomial size is multiplied in the extended PBS
/// setting.
///
/// The extended PBS simulates the rotation of a larger LUT using only smaller LUTs. This
/// has nice noise properties in some cases. The extended LUT polynomial size is N' = tau * N where
/// tau is a power of 2, usual notation is tau = 2^nu, so N' = 2^nu * N.
///
/// See [this paper](https://eprint.iacr.org/2025/2214.pdf).
///
/// Currently the extension factor needs to be a power of two to keep a compatible power of two for
/// the extended LUT.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct LweBootstrapExtensionFactor(usize);

impl LweBootstrapExtensionFactor {
    pub const fn new(value: usize) -> Self {
        assert!(
            value > 1,
            "An LweBootstrapExtensionFactor <= 1 makes no sense."
        );
        assert!(
            value.is_power_of_two(),
            "LweBootstrapExtensionFactor needs to be a power of 2"
        );

        Self(value)
    }

    pub const fn get(&self) -> usize {
        self.0
    }
}
