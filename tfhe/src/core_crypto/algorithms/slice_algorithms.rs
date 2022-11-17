use crate::core_crypto::commons::numeric::UnsignedInteger;

pub fn wrapping_dot_product<Scalar>(lhs: &[Scalar], rhs: &[Scalar]) -> Scalar
where
    Scalar: UnsignedInteger,
{
    assert!(
        lhs.len() == rhs.len(),
        "lhs (len: {}) and rhs (len: {}) must have the same length",
        lhs.len(),
        rhs.len()
    );

    lhs.iter()
        .zip(rhs.iter())
        .fold(Scalar::ZERO, |acc, (&left, &right)| {
            acc.wrapping_add(left.wrapping_mul(right))
        })
}
