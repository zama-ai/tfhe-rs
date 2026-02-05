//! Module providing algorithms to perform computations on raw slices.

use crate::core_crypto::algorithms::polynomial_algorithms::polynomial_wrapping_add_mul_assign;
use crate::core_crypto::commons::math::ntt::ntt_native_binary64::NttNativeBinary64;
use crate::core_crypto::commons::numeric::UnsignedInteger;
use crate::core_crypto::commons::parameters::PolynomialSize;
use crate::core_crypto::entities::Polynomial;
use core::any::TypeId;

/// Compute a dot product between two slices containing unsigned integers.
///
/// # Note
///
/// Computations wrap around (similar to computing modulo $2^{n\_{bits}}$) when exceeding the
/// unsigned integer capacity.
///
/// # Example
///
/// ```rust
/// use tfhe::core_crypto::algorithms::slice_algorithms::*;
/// let first = vec![1u8, 2, 3, 4, 5, 6];
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

/// This primitive is meant to manage the dot product avoiding overflow on multiplication by casting
/// to u128, for example for u64, avoiding overflow on each multiplication (as u64::MAX * u64::MAX <
/// u128::MAX)
pub fn slice_wrapping_dot_product_custom_mod<Scalar>(
    lhs: &[Scalar],
    rhs: &[Scalar],
    modulus: Scalar,
) -> Scalar
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
            acc.wrapping_add_custom_mod(left.wrapping_mul_custom_mod(right, modulus), modulus)
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
/// ```rust
/// use tfhe::core_crypto::algorithms::slice_algorithms::*;
/// let first = vec![1u8, 2, 3, 4, 5, 6];
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
        "output (len: {}) and rhs (len: {}) must have the same length",
        output.len(),
        lhs.len()
    );

    output
        .iter_mut()
        .zip(lhs.iter().zip(rhs.iter()))
        .for_each(|(out, (&lhs, &rhs))| *out = lhs.wrapping_add(rhs));
}

pub fn slice_wrapping_add_custom_mod<Scalar>(
    output: &mut [Scalar],
    lhs: &[Scalar],
    rhs: &[Scalar],
    custom_modulus: Scalar,
) where
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
        "output (len: {}) and rhs (len: {}) must have the same length",
        output.len(),
        lhs.len()
    );

    output
        .iter_mut()
        .zip(lhs.iter().zip(rhs.iter()))
        .for_each(|(out, (&lhs, &rhs))| *out = lhs.wrapping_add_custom_mod(rhs, custom_modulus));
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
/// ```rust
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

pub fn slice_wrapping_add_assign_custom_mod<Scalar>(
    lhs: &mut [Scalar],
    rhs: &[Scalar],
    custom_modulus: Scalar,
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
        .for_each(|(lhs, &rhs)| *lhs = (*lhs).wrapping_add_custom_mod(rhs, custom_modulus));
}

/// Add a slice containing unsigned integers to another one multiplied by a scalar.
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
/// ```rust
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
/// ```rust
/// use tfhe::core_crypto::algorithms::slice_algorithms::*;
/// let first = vec![1u8, 2, 3, 4, 5, 6];
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
        "output (len: {}) and rhs (len: {}) must have the same length",
        output.len(),
        lhs.len()
    );

    output
        .iter_mut()
        .zip(lhs.iter().zip(rhs.iter()))
        .for_each(|(out, (&lhs, &rhs))| *out = lhs.wrapping_sub(rhs));
}

pub fn slice_wrapping_sub_custom_mod<Scalar>(
    output: &mut [Scalar],
    lhs: &[Scalar],
    rhs: &[Scalar],
    custom_modulus: Scalar,
) where
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
        "output (len: {}) and rhs (len: {}) must have the same length",
        output.len(),
        lhs.len()
    );

    output
        .iter_mut()
        .zip(lhs.iter().zip(rhs.iter()))
        .for_each(|(out, (&lhs, &rhs))| *out = lhs.wrapping_sub_custom_mod(rhs, custom_modulus));
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
/// ```rust
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

pub fn slice_wrapping_sub_assign_custom_mod<Scalar>(
    lhs: &mut [Scalar],
    rhs: &[Scalar],
    custom_modulus: Scalar,
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
        .for_each(|(lhs, &rhs)| *lhs = (*lhs).wrapping_sub_custom_mod(rhs, custom_modulus));
}

/// Subtract a slice containing unsigned integers to another one multiplied by a scalar,
/// element-wise and in place.
///
/// Let *a*,*b* be two slices, let *c* be a scalar, this computes: *a <- a-bc*
///
/// # Note
///
/// Computations wrap around (similar to computing modulo $2^{n\_{bits}}$) when exceeding the
/// unsigned integer capacity.
///
/// This functions has hardcoded cases for small values for `scalar` in $[-16, 16]$ which allows
/// for specifically optimized code paths (a multiplication by a power of 2 can be changed to shift
/// by the compiler), this yields significant performance improvements for the keyswitch which
/// heavily relies on that primitive.
///
/// # Example
///
/// ```rust
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
    struct Impl<'a, Scalar> {
        lhs: &'a mut [Scalar],
        rhs: &'a [Scalar],
        scalar: Scalar,
    }

    impl<Scalar: UnsignedInteger> pulp::NullaryFnOnce for Impl<'_, Scalar> {
        type Output = ();

        #[inline(always)]
        fn call(self) -> Self::Output {
            let Self { lhs, rhs, scalar } = self;

            macro_rules! spec_constant {
                ($constant: expr) => {
                    if scalar == Scalar::cast_from($constant as u128) {
                        for (lhs, &rhs) in lhs.iter_mut().zip(rhs.iter()) {
                            *lhs = (*lhs).wrapping_sub(
                                rhs.wrapping_mul(Scalar::cast_from($constant as u128)),
                            )
                        }
                        return;
                    }
                };
            }

            // Manage all values with hardcoded paths for values in [-16; 16]
            // This takes care of all keyswitch base logs <= 5
            // The negated value is handled in the spec constant to avoid bad surprises with the
            // constant type vs the Scalar type
            // UnsignedInteger is CastFrom<u128> by default, we give the constant in a readable form
            // as an i128, it then gets cast to u128
            spec_constant!(-16i128);
            spec_constant!(-15i128);
            spec_constant!(-14i128);
            spec_constant!(-13i128);
            spec_constant!(-12i128);
            spec_constant!(-11i128);
            spec_constant!(-10i128);
            spec_constant!(-9i128);
            spec_constant!(-8i128);
            spec_constant!(-7i128);
            spec_constant!(-6i128);
            spec_constant!(-5i128);
            spec_constant!(-4i128);
            spec_constant!(-3i128);
            spec_constant!(-2i128);
            spec_constant!(-1i128);
            spec_constant!(0i128);
            spec_constant!(1i128);
            spec_constant!(2i128);
            spec_constant!(3i128);
            spec_constant!(4i128);
            spec_constant!(5i128);
            spec_constant!(6i128);
            spec_constant!(7i128);
            spec_constant!(8i128);
            spec_constant!(9i128);
            spec_constant!(10i128);
            spec_constant!(11i128);
            spec_constant!(12i128);
            spec_constant!(13i128);
            spec_constant!(14i128);
            spec_constant!(15i128);
            spec_constant!(16i128);

            // Fall back case, will likely be slower as the compiler cannot hard code optimized code
            // like filling with 0s for the 0 case, noop for the 1 case, shift left by 1 for 2, etc.
            for (lhs, &rhs) in lhs.iter_mut().zip(rhs.iter()) {
                *lhs = (*lhs).wrapping_sub(rhs.wrapping_mul(scalar));
            }
        }
    }

    // Const evaluated
    assert!(
        Scalar::BITS <= 128,
        "Scalar has more than 128 bits, \
        specialized constants will not work properly for negative values."
    );

    assert!(
        lhs.len() == rhs.len(),
        "lhs (len: {}) and rhs (len: {}) must have the same length",
        lhs.len(),
        rhs.len()
    );

    pulp::Arch::new().dispatch(Impl { lhs, rhs, scalar });
}

/// This primitive is meant to manage the sub_scalar_mul operation for values that were cast to a
/// bigger type, for example u64 to u128, avoiding overflow on each multiplication (as u64::MAX *
/// u64::MAX < u128::MAX )
pub fn slice_wrapping_sub_scalar_mul_assign_custom_modulus<Scalar>(
    lhs: &mut [Scalar],
    rhs: &[Scalar],
    scalar: Scalar,
    modulus: Scalar,
) where
    Scalar: UnsignedInteger,
{
    assert!(
        lhs.len() == rhs.len(),
        "lhs (len: {}) and rhs (len: {}) must have the same length",
        lhs.len(),
        rhs.len()
    );
    lhs.iter_mut().zip(rhs.iter()).for_each(|(lhs, &rhs)| {
        *lhs =
            (*lhs).wrapping_sub_custom_mod(rhs.wrapping_mul_custom_mod(scalar, modulus), modulus);
    });
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
/// ```rust
/// use tfhe::core_crypto::algorithms::slice_algorithms::*;
/// let mut first = vec![1u8, 2, 3, 4, 5, 6];
/// slice_wrapping_opposite_assign(&mut first);
/// assert_eq!(&first, &[255u8, 254, 253, 252, 251, 250]);
/// ```
pub fn slice_wrapping_opposite_assign<Scalar>(slice: &mut [Scalar])
where
    Scalar: UnsignedInteger,
{
    for elt in slice.iter_mut() {
        *elt = (*elt).wrapping_neg();
    }
}

pub fn slice_wrapping_opposite_assign_custom_mod<Scalar>(
    slice: &mut [Scalar],
    custom_modulus: Scalar,
) where
    Scalar: UnsignedInteger,
{
    for elt in slice.iter_mut() {
        *elt = (*elt).wrapping_neg_custom_mod(custom_modulus);
    }
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
/// ```rust
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
    for lhs in lhs.iter_mut() {
        *lhs = (*lhs).wrapping_mul(rhs);
    }
}

pub fn slice_wrapping_scalar_mul_assign_custom_mod<Scalar>(
    lhs: &mut [Scalar],
    rhs: Scalar,
    custom_modulus: Scalar,
) where
    Scalar: UnsignedInteger,
{
    for lhs in lhs.iter_mut() {
        *lhs = (*lhs).wrapping_mul_custom_mod(rhs, custom_modulus);
    }
}

pub fn slice_wrapping_scalar_div_assign<Scalar>(lhs: &mut [Scalar], rhs: Scalar)
where
    Scalar: UnsignedInteger,
{
    for lhs in lhs.iter_mut() {
        *lhs = (*lhs).wrapping_div(rhs);
    }
}

/// Add the same scalar to all elements of mutable slice in place.
///
/// # Note
///
/// Computations wrap around (similar to computing modulo $2^{n\_{bits}}$) when exceeding the
/// unsigned integer capacity.
///
/// # Example
///
/// ```rust
/// use tfhe::core_crypto::algorithms::slice_algorithms::*;
/// let mut first = vec![1u8, 2, 3, 4, 5, 255];
/// let scalar = 1;
/// slice_wrapping_scalar_add_assign(&mut first, scalar);
/// assert_eq!(&first, &[2u8, 3, 4, 5, 6, 0]);
/// ```
pub fn slice_wrapping_scalar_add_assign<Scalar>(lhs: &mut [Scalar], rhs: Scalar)
where
    Scalar: UnsignedInteger,
{
    for dst in lhs.iter_mut() {
        *dst = (*dst).wrapping_add(rhs);
    }
}

/// Subtract the same scalar to all elements of mutable slice in place.
///
/// # Note
///
/// Computations wrap around (similar to computing modulo $2^{n\_{bits}}$) when exceeding the
/// unsigned integer capacity.
///
/// # Example
///
/// ```rust
/// use tfhe::core_crypto::algorithms::slice_algorithms::*;
/// let mut first = vec![0u8, 1, 2, 3, 4, 5];
/// let scalar = 1;
/// slice_wrapping_scalar_sub_assign(&mut first, scalar);
/// assert_eq!(&first, &[255u8, 0, 1, 2, 3, 4]);
/// ```
pub fn slice_wrapping_scalar_sub_assign<Scalar>(lhs: &mut [Scalar], rhs: Scalar)
where
    Scalar: UnsignedInteger,
{
    for dst in lhs.iter_mut() {
        *dst = (*dst).wrapping_sub(rhs);
    }
}

/// Primitive for compact LWE public key
///
/// Here $i$ from section 3 of <https://eprint.iacr.org/2023/603> is taken equal to $n$.
/// ```rust
/// use tfhe::core_crypto::algorithms::slice_algorithms::*;
/// let lhs = vec![1u8, 2u8, 3u8];
/// let rhs = vec![4u8, 5u8, 6u8];
/// let mut output = vec![0u8; 3];
/// slice_semi_reverse_negacyclic_convolution(&mut output, &lhs, &rhs);
/// assert_eq!(&output, &[(-17i8) as u8, 5, 32]);
/// ```
pub fn slice_semi_reverse_negacyclic_convolution<Scalar>(
    output: &mut [Scalar],
    lhs: &[Scalar],
    rhs: &[Scalar],
) where
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
        "output (len: {}) and lhs (len: {}) must have the same length",
        output.len(),
        lhs.len()
    );

    // Apply phi_1 to the rhs term
    let mut phi_1_rhs: Vec<_> = rhs.to_vec();
    phi_1_rhs.reverse();

    let phi_1_rhs_as_polynomial = Polynomial::from_container(phi_1_rhs.as_slice());

    // Clear output as we'll add the multiplication result
    output.fill(Scalar::ZERO);
    let mut output_as_polynomial = Polynomial::from_container(output);
    let lhs_as_polynomial = Polynomial::from_container(lhs);

    // Apply the classic negacyclic convolution via polynomial mul in the X^N + 1 ring, with the
    // phi_1 rhs it is equivalent to the operator we need
    polynomial_wrapping_add_mul_assign(
        &mut output_as_polynomial,
        &lhs_as_polynomial,
        &phi_1_rhs_as_polynomial,
    );
}

/// Specialized variant of [`slice_semi_reverse_negacyclic_convolution`] where the right hand side
/// input **has** to be binary.
///
/// Here $i$ from section 3 of <https://eprint.iacr.org/2023/603> is taken equal to $n$.
/// ```rust
/// use tfhe::core_crypto::algorithms::slice_algorithms::*;
/// let lhs = vec![1u8, 2u8, 3u8];
/// let rhs = vec![0u8, 1u8, 1u8];
/// let mut output = vec![0u8; 3];
/// slice_binary_semi_reverse_negacyclic_convolution(&mut output, &lhs, &rhs);
/// assert_eq!(&output, &[254u8, 3, 5]);
/// ```
pub fn slice_binary_semi_reverse_negacyclic_convolution<Scalar>(
    output: &mut [Scalar],
    lhs: &[Scalar],
    rhs: &[Scalar],
) where
    Scalar: UnsignedInteger,
{
    debug_assert!(rhs.iter().all(|&x| x <= Scalar::ONE));

    assert!(
        lhs.len() == rhs.len(),
        "lhs (len: {}) and rhs (len: {}) must have the same length",
        lhs.len(),
        rhs.len()
    );
    assert!(
        output.len() == lhs.len(),
        "output (len: {}) and lhs (len: {}) must have the same length",
        output.len(),
        lhs.len()
    );

    // Compile-time check
    if TypeId::of::<Scalar>() == TypeId::of::<u64>() {
        let poly_size = PolynomialSize(lhs.len());

        // Runtime check
        // 32 and 32768 are limit sizes valid for the native64 NTT from tfhe_ntt
        if poly_size.0 >= 32 && poly_size.0 <= 32768 {
            // Apply phi_1 to the rhs term
            let mut phi_1_rhs: Vec<_> = rhs.to_vec();
            phi_1_rhs.reverse();

            let output: &mut [u64] = bytemuck::cast_slice_mut(output);
            let lhs: &[u64] = bytemuck::cast_slice(lhs);

            let rhs = phi_1_rhs.as_slice();
            let rhs: &[u64] = bytemuck::cast_slice(rhs);

            #[cfg(all(feature = "avx512", any(target_arch = "x86", target_arch = "x86_64")))]
            {
                use crate::core_crypto::commons::math::ntt::ntt_native_binary64::NttNativeBinary64Avx512;
                if let Some(ntt_native_64) = NttNativeBinary64Avx512::try_new(poly_size) {
                    ntt_native_64.as_view().negacyclic_polymul(output, lhs, rhs);
                    return;
                }
            }

            // Fallback if avx512 is not available
            let ntt_native_64 = NttNativeBinary64::new(poly_size);
            ntt_native_64.as_view().negacyclic_polymul(output, lhs, rhs);
            return;
        }
    }

    // Fallback to generic impl
    slice_semi_reverse_negacyclic_convolution(output, lhs, rhs);
}

#[cfg(test)]
mod test {
    use super::*;

    /// This test does not use the optimized variant since the optimized variant is only available
    /// for u64 as of the time of the introduction of this test
    #[test]
    fn test_equivalence_slice_binary_semi_reverse_negacyclic_convolution_u32() {
        let poly_size = 2048;
        let mut output_ref = vec![0u32; poly_size];
        let mut output_optimized = vec![0u32; poly_size];
        let mut lhs = vec![0u32; poly_size];
        let mut rhs = vec![0u32; poly_size];

        for _ in 0..100_000 {
            lhs.fill_with(rand::random);
            rhs.fill_with(|| rand::random::<u32>() % 2);

            slice_semi_reverse_negacyclic_convolution(&mut output_ref, &lhs, &rhs);
            slice_binary_semi_reverse_negacyclic_convolution(&mut output_optimized, &lhs, &rhs);

            assert_eq!(output_ref, output_optimized, "lhs: {lhs:?}, rhs: {rhs:?}");
        }
    }

    /// This test uses the optimized variant since the optimized variant is available for u64
    #[test]
    fn test_equivalence_slice_binary_semi_reverse_negacyclic_convolution_u64() {
        let poly_size = 2048;
        let mut output_ref = vec![0u64; poly_size];
        let mut output_optimized = vec![0u64; poly_size];
        let mut lhs = vec![0u64; poly_size];
        let mut rhs = vec![0u64; poly_size];

        for _ in 0..100_000 {
            lhs.fill_with(rand::random);
            rhs.fill_with(|| rand::random::<u64>() % 2);

            slice_semi_reverse_negacyclic_convolution(&mut output_ref, &lhs, &rhs);
            slice_binary_semi_reverse_negacyclic_convolution(&mut output_optimized, &lhs, &rhs);

            assert_eq!(output_ref, output_optimized, "lhs: {lhs:?}, rhs: {rhs:?}");
        }
    }
}
