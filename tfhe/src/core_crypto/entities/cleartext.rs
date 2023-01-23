//! Module containing the definition of the Cleartext.

use crate::core_crypto::commons::numeric::Numeric;

/// A cleartext, not encoded, value.
#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize)]
pub struct Cleartext<T: Numeric>(pub T);
