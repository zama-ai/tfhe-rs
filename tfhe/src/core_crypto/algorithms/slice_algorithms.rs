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

pub fn update_with_wrapping_add<Scalar>(lhs: &mut [Scalar], rhs: &[Scalar])
where
    Scalar: UnsignedInteger,
{
    assert!(
        lhs.len() == rhs.len(),
        "lhs (len: {}) and rhs (len: {}) must have the same length",
        lhs.len(),
        rhs.len()
    );

    lhs.iter_mut()
        .zip(rhs.iter())
        .for_each(|(lhs, &rhs)| *lhs = (*lhs).wrapping_add(rhs));
}

pub fn update_with_wrapping_add_scalar_mul<Scalar>(
    lhs: &mut [Scalar],
    rhs: &[Scalar],
    scalar: Scalar,
) where
    Scalar: UnsignedInteger,
{
    assert!(
        lhs.len() == rhs.len(),
        "lhs (len: {}) and rhs (len: {}) must have the same length",
        lhs.len(),
        rhs.len()
    );
    lhs.iter_mut()
        .zip(rhs.iter())
        .for_each(|(lhs, &rhs)| *lhs = (*lhs).wrapping_add(rhs.wrapping_mul(scalar)));
}

pub fn update_with_wrapping_sub<Scalar>(lhs: &mut [Scalar], rhs: &[Scalar])
where
    Scalar: UnsignedInteger,
{
    assert!(
        lhs.len() == rhs.len(),
        "lhs (len: {}) and rhs (len: {}) must have the same length",
        lhs.len(),
        rhs.len()
    );

    lhs.iter_mut()
        .zip(rhs.iter())
        .for_each(|(lhs, &rhs)| *lhs = (*lhs).wrapping_sub(rhs));
}

pub fn update_with_wrapping_sub_scalar_mul<Scalar>(
    lhs: &mut [Scalar],
    rhs: &[Scalar],
    scalar: Scalar,
) where
    Scalar: UnsignedInteger,
{
    assert!(
        lhs.len() == rhs.len(),
        "lhs (len: {}) and rhs (len: {}) must have the same length",
        lhs.len(),
        rhs.len()
    );
    lhs.iter_mut()
        .zip(rhs.iter())
        .for_each(|(lhs, &rhs)| *lhs = (*lhs).wrapping_sub(rhs.wrapping_mul(scalar)));
}

pub fn update_with_wrapping_opposite<Scalar>(slice: &mut [Scalar])
where
    Scalar: UnsignedInteger,
{
    slice
        .iter_mut()
        .for_each(|elt| *elt = (*elt).wrapping_neg());
}

pub fn update_with_wrapping_scalar_mul<Scalar>(lhs: &mut [Scalar], rhs: Scalar)
where
    Scalar: UnsignedInteger,
{
    lhs.iter_mut()
        .for_each(|lhs| *lhs = (*lhs).wrapping_mul(rhs));
}
