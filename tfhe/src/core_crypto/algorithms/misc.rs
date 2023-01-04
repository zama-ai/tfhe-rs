//! Miscellaneous algorithms.

use crate::core_crypto::prelude::*;

/// Convenience function using a bit trick to determine whether a scalar is a power of 2.
pub fn is_power_of_two<Scalar>(scalar: Scalar) -> bool
where
    Scalar: UnsignedInteger,
{
    (scalar != Scalar::ZERO) && ((scalar & (scalar - Scalar::ONE)) == Scalar::ZERO)
}
