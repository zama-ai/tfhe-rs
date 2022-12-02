use crate::core_crypto::commons::numeric::Numeric;

/// A cleartext, not encoded, value
#[derive(Clone, Debug)]
pub struct Cleartext<T: Numeric>(pub T);
