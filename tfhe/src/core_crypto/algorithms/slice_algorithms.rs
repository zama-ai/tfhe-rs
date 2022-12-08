//! Module providing algorithms to perform computations on raw slices.

use crate::core_crypto::commons::numeric::UnsignedInteger;

/// Compute a dot product between two slices containing unsigned integers.
///
/// # Note
///
/// Computations wrap around (similar to computing modulo $2^{n\_{bits}}$) when exceeding the
/// unsigned integer capacity.
///
/// # Example
///
/// ```
/// use tfhe::core_crypto::algorithms::slice_algorithms::*;
/// let mut first = vec![1u8, 2, 3, 4, 5, 6];
/// let second = vec![255u8, 255, 255, 1, 2, 3];
/// let dot_product = slice_wrapping_dot_product(&first, &second);
/// assert_eq!(dot_product, 26);
/// ```
pub fn slice_wrapping_dot_product<Scalar>(lhs: &[Scalar], rhs: &[Scalar]) -> Scalar
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

/// Add a slice containing unsigned integers to another one element-wise.
///
/// # Note
///
/// Computations wrap around (similar to computing modulo $2^{n\_{bits}}$) when exceeding the
/// unsigned integer capacity.
///
/// # Example
///
/// ```
/// use tfhe::core_crypto::algorithms::slice_algorithms::*;
/// let mut first = vec![1u8, 2, 3, 4, 5, 6];
/// let second = vec![255u8, 255, 255, 1, 2, 3];
/// let mut add = vec![0_u8; 6];
/// slice_wrapping_add(&mut add, &first, &second);
/// assert_eq!(&add, &[0u8, 1, 2, 5, 7, 9]);
/// ```
pub fn slice_wrapping_add<Scalar>(output: &mut [Scalar], lhs: &[Scalar], rhs: &[Scalar])
where
    Scalar: UnsignedInteger,
{
    assert!(
        lhs.len() == rhs.len(),
        "lhs (len: {}) and rhs (len: {}) must have the same length",
        lhs.len(),
        rhs.len()
    );
    assert!(
        output.len() == lhs.len(),
        "output (len: {}) and rhs (lhs: {}) must have the same length",
        output.len(),
        lhs.len()
    );

    output
        .iter_mut()
        .zip(lhs.iter().zip(rhs.iter()))
        .for_each(|(out, (&lhs, &rhs))| *out = lhs.wrapping_add(rhs));
}

/// Add a slice containing unsigned integers to another one element-wise and in place.
///
/// # Note
///
/// Computations wrap around (similar to computing modulo $2^{n\_{bits}}$) when exceeding the
/// unsigned integer capacity.
///
/// # Example
///
/// ```
/// use tfhe::core_crypto::algorithms::slice_algorithms::*;
/// let mut first = vec![1u8, 2, 3, 4, 5, 6];
/// let second = vec![255u8, 255, 255, 1, 2, 3];
/// slice_wrapping_add_assign(&mut first, &second);
/// assert_eq!(&first, &[0u8, 1, 2, 5, 7, 9]);
/// ```
pub fn slice_wrapping_add_assign<Scalar>(lhs: &mut [Scalar], rhs: &[Scalar])
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

/// Add a slice containing unsigned integers to another one mutiplied by a scalar.
///
/// Let *a*,*b* be two slices, let *c* be a scalar, this computes: *a <- a+bc*
///
/// # Note
///
/// Computations wrap around (similar to computing modulo $2^{n\_{bits}}$) when exceeding the
/// unsigned integer capacity.
///
/// # Example
///
/// ```
/// use tfhe::core_crypto::algorithms::slice_algorithms::*;
/// let mut first = vec![1u8, 2, 3, 4, 5, 6];
/// let second = vec![255u8, 255, 255, 1, 2, 3];
/// let scalar = 4u8;
/// slice_wrapping_add_scalar_mul_assign(&mut first, &second, scalar);
/// assert_eq!(&first, &[253u8, 254, 255, 8, 13, 18]);
/// ```
pub fn slice_wrapping_add_scalar_mul_assign<Scalar>(
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

/// Subtract a slice containing unsigned integers to another one element-wise.
///
/// # Note
///
/// Computations wrap around (similar to computing modulo $2^{n\_{bits}}$) when exceeding the
/// unsigned integer capacity.
///
/// # Example
///
/// ```
/// use tfhe::core_crypto::algorithms::slice_algorithms::*;
/// let mut first = vec![1u8, 2, 3, 4, 5, 6];
/// let second = vec![255u8, 255, 255, 1, 2, 3];
/// let mut add = vec![0_u8; 6];
/// slice_wrapping_sub(&mut add, &first, &second);
/// assert_eq!(&add, &[2, 3, 4, 3, 3, 3]);
/// ```
pub fn slice_wrapping_sub<Scalar>(output: &mut [Scalar], lhs: &[Scalar], rhs: &[Scalar])
where
    Scalar: UnsignedInteger,
{
    assert!(
        lhs.len() == rhs.len(),
        "lhs (len: {}) and rhs (len: {}) must have the same length",
        lhs.len(),
        rhs.len()
    );
    assert!(
        output.len() == lhs.len(),
        "output (len: {}) and rhs (lhs: {}) must have the same length",
        output.len(),
        lhs.len()
    );

    output
        .iter_mut()
        .zip(lhs.iter().zip(rhs.iter()))
        .for_each(|(out, (&lhs, &rhs))| *out = lhs.wrapping_sub(rhs));
}

/// Subtract a slice containing unsigned integers to another one, element-wise and in place.
///
/// # Note
///
/// Computations wrap around (similar to computing modulo $2^{n\_{bits}}$) when exceeding the
/// unsigned integer capacity.
///
/// # Example
///
/// ```
/// use tfhe::core_crypto::algorithms::slice_algorithms::*;
/// let mut first = vec![1u8, 2, 3, 4, 5, 6];
/// let second = vec![255u8, 255, 255, 1, 2, 3];
/// slice_wrapping_sub_assign(&mut first, &second);
/// assert_eq!(&first, &[2u8, 3, 4, 3, 3, 3]);
/// ```
pub fn slice_wrapping_sub_assign<Scalar>(lhs: &mut [Scalar], rhs: &[Scalar])
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

/// Subtract a slice containing unsigned integers to another one mutiplied by a scalar,
/// element-wise and in place.
///
/// Let *a*,*b* be two slices, let *c* be a scalar, this computes: *a <- a-bc*
///
/// # Note
///
/// Computations wrap around (similar to computing modulo $2^{n\_{bits}}$) when exceeding the
/// unsigned integer capacity.
///
/// # Example
///
/// ```
/// use tfhe::core_crypto::algorithms::slice_algorithms::*;
/// let mut first = vec![1u8, 2, 3, 4, 5, 6];
/// let second = vec![255u8, 255, 255, 1, 2, 3];
/// let scalar = 4u8;
/// slice_wrapping_sub_scalar_mul_assign(&mut first, &second, scalar);
/// assert_eq!(&first, &[5u8, 6, 7, 0, 253, 250]);
pub fn slice_wrapping_sub_scalar_mul_assign<Scalar>(
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

/// Compute the opposite of a slice containing unsigned integers, element-wise and in place.
///
/// # Note
///
/// Computations wrap around (similar to computing modulo $2^{n\_{bits}}$) when exceeding the
/// unsigned integer capacity.
///
/// # Example
///
/// ```
/// use tfhe::core_crypto::algorithms::slice_algorithms::*;
/// let mut first = vec![1u8, 2, 3, 4, 5, 6];
/// slice_wrapping_opposite_assign(&mut first);
/// assert_eq!(&first, &[255u8, 254, 253, 252, 251, 250]);
/// ```
pub fn slice_wrapping_opposite_assign<Scalar>(slice: &mut [Scalar])
where
    Scalar: UnsignedInteger,
{
    slice
        .iter_mut()
        .for_each(|elt| *elt = (*elt).wrapping_neg());
}

/// Multiply a slice containing unsigned integers by a scalar, element-wise and in place.
///
/// # Note
///
/// Computations wrap around (similar to computing modulo $2^{n\_{bits}}$) when exceeding the
/// unsigned integer capacity.
///
/// # Example
///
/// ```
/// use tfhe::core_crypto::algorithms::slice_algorithms::*;
/// let mut first = vec![1u8, 2, 3, 4, 5, 6];
/// let scalar = 252;
/// slice_wrapping_scalar_mul_assign(&mut first, scalar);
/// assert_eq!(&first, &[252, 248, 244, 240, 236, 232]);
/// ```
pub fn slice_wrapping_scalar_mul_assign<Scalar>(lhs: &mut [Scalar], rhs: Scalar)
where
    Scalar: UnsignedInteger,
{
    lhs.iter_mut()
        .for_each(|lhs| *lhs = (*lhs).wrapping_mul(rhs));
}
