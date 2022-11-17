use crate::core_crypto::commons::numeric::Numeric;

/// An plaintext (encoded) value.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Encoded<T: Numeric>(pub T);
