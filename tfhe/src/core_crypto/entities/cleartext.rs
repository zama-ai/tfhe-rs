use crate::core_crypto::commons::numeric::Numeric;

/// A cleartext, not encoded, value
pub struct Cleartext<T: Numeric>(pub T);
