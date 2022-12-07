use crate::core_crypto::commons::numeric::Numeric;

/// A cleartext, not encoded, value.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Cleartext<T: Numeric>(pub T);
