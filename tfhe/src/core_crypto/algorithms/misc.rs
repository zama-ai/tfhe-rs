use crate::core_crypto::prelude::*;

pub fn is_power_of_two<Scalar>(degree: Scalar) -> bool
where
    Scalar: UnsignedInteger,
{
    (degree != Scalar::ZERO) && ((degree & (degree - Scalar::ONE)) == Scalar::ZERO)
}
