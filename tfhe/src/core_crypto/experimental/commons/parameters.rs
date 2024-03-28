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
