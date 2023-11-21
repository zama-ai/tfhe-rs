//! Division by a clear scalar
//!
//! This module implements the paper
//! [Division by Invariant Integers using Multiplication](https://gmplib.org/~tege/divcnst-pldi94.pdf)
//!
//! It is based on the commonly used technique of replacing division
//! by a multiplication with an approximation of inverse with correction steps
//! afterwards.
//!
//! In this case, the constant is a clear value at runtime, however,
//! due to the huge difference between clear computation and FHE computation
//! it is absolutely worth to compute the approximation of the inverse.
use std::ops::{Add, AddAssign, BitAnd, Div, Mul, Neg, Shl, Shr, Sub};

use crate::core_crypto::prelude::{CastFrom, CastInto, Numeric, SignedNumeric, UnsignedInteger};
use crate::integer::block_decomposition::DecomposableInto;
use crate::integer::ciphertext::{RadixCiphertext, SignedRadixCiphertext};
use crate::integer::server_key::radix::scalar_mul::ScalarMultiplier;
use crate::integer::{IntegerCiphertext, ServerKey, I256, I512, U256, U512};

#[inline(always)]
fn is_even<T>(d: T) -> bool
where
    T: Numeric + BitAnd<T, Output = T>,
{
    (d & T::ONE) == T::ZERO
}

pub trait MiniUnsignedInteger:
    Numeric
    + Shl<usize, Output = Self>
    + Shr<usize, Output = Self>
    + Add<Self, Output = Self>
    + Mul<Self, Output = Self>
    + Div<Self, Output = Self>
    + Sub<Self, Output = Self>
    + BitAnd<Self, Output = Self>
    + AddAssign<Self>
{
    fn ceil_ilog2(self) -> u32;

    fn ilog2(self) -> u32;

    fn is_power_of_two(self) -> bool;
}

impl<T> MiniUnsignedInteger for T
where
    T: UnsignedInteger,
{
    fn ceil_ilog2(self) -> u32 {
        <T as UnsignedInteger>::ceil_ilog2(self)
    }

    fn ilog2(self) -> u32 {
        <T as UnsignedInteger>::ilog2(self)
    }

    fn is_power_of_two(self) -> bool {
        <T as UnsignedInteger>::is_power_of_two(self)
    }
}

impl MiniUnsignedInteger for U256 {
    fn ceil_ilog2(self) -> u32 {
        self.ceil_ilog2()
    }

    fn ilog2(self) -> u32 {
        self.ilog2()
    }

    fn is_power_of_two(self) -> bool {
        self.is_power_of_two()
    }
}

impl MiniUnsignedInteger for U512 {
    fn ceil_ilog2(self) -> u32 {
        self.ceil_ilog2()
    }

    fn ilog2(self) -> u32 {
        self.ilog2()
    }

    fn is_power_of_two(self) -> bool {
        self.is_power_of_two()
    }
}

pub trait Reciprocable: MiniUnsignedInteger {
    // We need the double precision to compute and store the reciprocal
    // u8 -> u16, u32 -> u64
    type DoublePrecision: MiniUnsignedInteger
        + CastFrom<Self>
        + CastInto<Self>
        + ScalarMultiplier // Needed for scalar_mul
        + DecomposableInto<u8>; // Needed for scalar_mul
}

impl Reciprocable for u8 {
    type DoublePrecision = u16;
}

impl Reciprocable for u16 {
    type DoublePrecision = u32;
}

impl Reciprocable for u32 {
    type DoublePrecision = u64;
}

impl Reciprocable for u64 {
    type DoublePrecision = u128;
}

impl Reciprocable for u128 {
    type DoublePrecision = U256;
}

impl Reciprocable for U256 {
    type DoublePrecision = U512;
}

pub trait SignedReciprocable:
    DecomposableInto<u64>
    + DecomposableInto<u8>
    + SignedNumeric
    + Neg<Output = Self>
    + Shl<usize, Output = Self>
    + Shr<usize, Output = Self>
    + std::fmt::Debug
{
    type Unsigned: Reciprocable + CastFrom<Self> + std::fmt::Debug;
    type DoublePrecision: DecomposableInto<u8>
        + ScalarMultiplier
        + CastFrom<<Self::Unsigned as Reciprocable>::DoublePrecision>
        + std::fmt::Debug;

    fn wrapping_abs(self) -> Self;
}

impl SignedReciprocable for i8 {
    type Unsigned = u8;

    type DoublePrecision = i16;

    fn wrapping_abs(self) -> Self {
        self.wrapping_abs()
    }
}

impl SignedReciprocable for i16 {
    type Unsigned = u16;

    type DoublePrecision = i32;

    fn wrapping_abs(self) -> Self {
        self.wrapping_abs()
    }
}

impl SignedReciprocable for i32 {
    type Unsigned = u32;

    type DoublePrecision = i64;

    fn wrapping_abs(self) -> Self {
        self.wrapping_abs()
    }
}

impl SignedReciprocable for i64 {
    type Unsigned = u64;

    type DoublePrecision = i128;

    fn wrapping_abs(self) -> Self {
        self.wrapping_abs()
    }
}

impl SignedReciprocable for i128 {
    type Unsigned = u128;

    type DoublePrecision = I256;

    fn wrapping_abs(self) -> Self {
        self.wrapping_abs()
    }
}

impl SignedReciprocable for I256 {
    type Unsigned = U256;

    type DoublePrecision = I512;

    fn wrapping_abs(self) -> Self {
        self.wrapping_abs()
    }
}

#[derive(Debug, Copy, Clone)]
struct ApproximatedMultiplier<T> {
    // The approximation of the inverse
    multiplier: T,
    // The shift that we might need
    // to do post multiplication to correct error
    shift_post: u32,
    // Ceil ilog2 of the divisor
    // that is, we have: (l-1) < log2(divisor) <= l
    l: u32,
}

#[allow(non_snake_case)]
fn choose_multiplier<T: Reciprocable>(
    divisor: T,
    precision: u32,
    integer_bits: u32,
) -> ApproximatedMultiplier<T::DoublePrecision> {
    // Keep the same name as in the paper
    let N = integer_bits;

    assert_ne!(divisor, T::ZERO, "attempt to divide by 0");
    assert!(precision >= 1 && precision <= N);

    let d = T::DoublePrecision::cast_from(divisor);
    let two_pow_n = T::DoublePrecision::ONE << N;

    // Find l such that (l-1) < log2(d) <= l
    let l = d.ceil_ilog2();
    let mut shift_post = l;

    // The formula is m_low == 2**(N+l) / d
    // however N + l may be == to 128, which means doing
    // 2**(N + l) would not be valid, so the formula has been written in a
    // way that does not overflow.
    //
    // By writing m_low = (m_low - 2**N) + (2**N)
    let mut m_low = (two_pow_n * ((T::DoublePrecision::ONE << l as usize) - d)) / d;
    m_low += two_pow_n;

    // The formula is (2**(N+l) + 2**(N + l - precision)) / d
    // again 2**(N+l) could overflow
    let mut m_high = ((two_pow_n * ((T::DoublePrecision::ONE << l as usize) - d))
        + (T::DoublePrecision::ONE << (N + l - precision)))
        / d;
    m_high += two_pow_n;

    assert!(m_low < m_high);

    loop {
        let m_low_i = m_low >> 1usize;
        let m_high_i = m_high >> 1usize;

        if m_low_i >= m_high_i || shift_post == 0 {
            break;
        }

        m_low = m_low_i;
        m_high = m_high_i;
        shift_post -= 1;
    }

    ApproximatedMultiplier {
        multiplier: m_high,
        shift_post,
        l,
    }
}

impl ServerKey {
    /// computes lhs * rhs on the full precision (num_block * 2) and returns
    /// the most significant num blocks.
    ///
    /// In other words, it is like doing
    /// fn mulhi (a: u32, b: u32) -> u32 {
    ///    (a as 64 * b as u64) >> 32) as u32
    /// }
    fn scalar_mul_high<T>(&self, lhs: &RadixCiphertext, rhs: T) -> RadixCiphertext
    where
        T: ScalarMultiplier + DecomposableInto<u8>,
    {
        let mut result = lhs.clone();
        self.extend_radix_with_trivial_zero_blocks_msb_assign(&mut result, lhs.blocks.len());
        self.scalar_mul_assign_parallelized(&mut result, rhs);
        self.trim_radix_blocks_lsb_assign(&mut result, lhs.blocks.len());
        result
    }

    fn signed_scalar_mul_high<T>(
        &self,
        lhs: &SignedRadixCiphertext,
        rhs: T,
    ) -> SignedRadixCiphertext
    where
        T: ScalarMultiplier + DecomposableInto<u8>,
    {
        let num_blocks = lhs.blocks.len();
        let mut result = self.extend_radix_with_sign_msb(lhs, num_blocks);
        self.scalar_mul_assign_parallelized(&mut result, rhs);
        let mut result = RadixCiphertext::from_blocks(result.blocks);
        self.trim_radix_blocks_lsb_assign(&mut result, num_blocks);
        SignedRadixCiphertext::from_blocks(result.blocks)
    }

    pub fn unchecked_scalar_div_parallelized<T>(
        &self,
        numerator: &RadixCiphertext,
        divisor: T,
    ) -> RadixCiphertext
    where
        T: Reciprocable,
    {
        let numerator_bits = self.key.message_modulus.0.ilog2() * numerator.blocks.len() as u32;

        // Rust has a check on all division, so we shall also have one
        assert_ne!(divisor, T::ZERO, "attempt to divide by 0");

        assert!(
            T::BITS >= numerator_bits as usize,
            "The scalar divisor type must have a number of bits that is \
            >= to the number of bits encrypted in the ciphertext: \n\
            encrypted bits: {numerator_bits}, scalar bits: {}
            ",
            T::BITS
        );

        if divisor.is_power_of_two() {
            // Even in FHE, shifting is faster than multiplying / dividing
            return self
                .unchecked_scalar_right_shift_parallelized(numerator, divisor.ilog2() as u64);
        }

        let log2_divisor = divisor.ceil_ilog2();
        if log2_divisor > numerator_bits {
            return self.create_trivial_zero_radix(numerator.blocks.len());
        }

        let mut chosen_multiplier = choose_multiplier(divisor, numerator_bits, numerator_bits);

        let shift_pre = if chosen_multiplier.multiplier
            >= (T::DoublePrecision::ONE << numerator_bits as usize)
            && is_even(divisor)
        {
            let divisor = T::DoublePrecision::cast_from(divisor);
            // Find e such that d = (1 << e) * divisor_odd
            // where divisor_odd is odd
            let two_pow_e =
                divisor & ((T::DoublePrecision::ONE << numerator_bits as usize) - divisor);
            let e = MiniUnsignedInteger::ilog2(two_pow_e);
            let divisor_odd = divisor / two_pow_e;

            assert!(numerator_bits > e && e <= T::BITS as u32);
            let divisor_odd: T = divisor_odd.cast_into(); // cast to lower precision
            chosen_multiplier = choose_multiplier(divisor_odd, numerator_bits - e, numerator_bits);
            e as u64
        } else {
            0
        };

        if chosen_multiplier.multiplier >= (T::DoublePrecision::ONE << numerator_bits as usize) {
            assert!(shift_pre == 0);

            let inverse =
                chosen_multiplier.multiplier - (T::DoublePrecision::ONE << numerator_bits as usize);
            let t1 = self.scalar_mul_high(numerator, inverse);

            // Compute: quotient = (t1 + ((numerator - t1) >> 1)) >> sh_post -1)
            assert_eq!(t1.blocks.len(), numerator.blocks.len());
            // Due to the use of a shifts, we can't use unchecked_add/sub
            let mut quotient = self.sub_parallelized(numerator, &t1);
            self.unchecked_scalar_right_shift_assign_parallelized(&mut quotient, 1);
            self.add_assign_parallelized(&mut quotient, &t1);
            assert!(chosen_multiplier.shift_post > 0);

            self.unchecked_scalar_right_shift_assign_parallelized(
                &mut quotient,
                chosen_multiplier.shift_post as u64 - 1,
            );

            quotient
        } else {
            let shifted_n = self.unchecked_scalar_right_shift(numerator, shift_pre);
            let mut quotient = self.scalar_mul_high(&shifted_n, chosen_multiplier.multiplier);
            self.unchecked_scalar_right_shift_assign_parallelized(
                &mut quotient,
                chosen_multiplier.shift_post as u64,
            );
            quotient
        }
    }

    /// # Note
    /// This division rounds (truncates) the quotient towards zero
    pub fn unchecked_signed_scalar_div_parallelized<T>(
        &self,
        numerator: &SignedRadixCiphertext,
        divisor: T,
    ) -> SignedRadixCiphertext
    where
        T: SignedReciprocable,
        <<T as SignedReciprocable>::Unsigned as Reciprocable>::DoublePrecision: Send,
    {
        assert_ne!(divisor, T::ZERO, "attempt to divide by 0");

        let numerator_bits = self.key.message_modulus.0.ilog2() * numerator.blocks.len() as u32;
        assert!(
            T::BITS >= numerator_bits as usize,
            "The scalar divisor type must have a number of bits that is\
            >= to the number of bits encrypted in the ciphertext"
        );

        // wrappings_abs returns T::MIN when its input is T::MIN (since in signed numbers
        // T::MIN's absolute value cannot be represented.
        // However, casting T::MIN to signed value will give the correct abs value
        // If T and T::Unsigned have the same number of bits
        let absolute_divisor = T::Unsigned::cast_from(divisor.wrapping_abs());

        if absolute_divisor == T::Unsigned::ONE {
            // Strangely, the paper says: Issue q = d;
            return if divisor < T::ZERO {
                // quotient = -quotient;
                self.neg_parallelized(numerator)
            } else {
                numerator.clone()
            };
        }

        let chosen_multiplier =
            choose_multiplier(absolute_divisor, numerator_bits - 1, numerator_bits);

        if chosen_multiplier.l >= numerator_bits {
            return self.create_trivial_zero_radix(numerator.blocks.len());
        }

        let quotient;
        if absolute_divisor == (T::Unsigned::ONE << chosen_multiplier.l as usize) {
            // Issue q = SRA(n + SRL(SRA(n, l − 1), N − l), l);
            let l = chosen_multiplier.l;

            // SRA(n, l − 1)
            let mut tmp = self.unchecked_scalar_right_shift_parallelized(numerator, l - 1);

            // SRL(SRA(n, l − 1), N − l)
            self.unchecked_scalar_right_shift_logical_assign_parallelized(
                &mut tmp,
                (numerator_bits - l) as usize,
            );
            // n + SRL(SRA(n, l − 1), N − l)
            self.add_assign_parallelized(&mut tmp, numerator);
            // SRA(n + SRL(SRA(n, l − 1), N − l), l);
            self.unchecked_scalar_right_shift_assign_parallelized(&mut tmp, l);
            quotient = tmp;
        } else if chosen_multiplier.multiplier
            < (<T::Unsigned as Reciprocable>::DoublePrecision::ONE << (numerator_bits - 1))
        {
            // in the condition above works (it makes more values take this branch,
            // but results still seemed correct)

            // multiplier is less than the max possible value of T
            // Issue q = SRA(MULSH(m, n), shpost) − XSIGN(n);

            let (mut tmp, xsign) = rayon::join(
                move || {
                    // MULSH(m, n)
                    let mut tmp =
                        self.signed_scalar_mul_high(numerator, chosen_multiplier.multiplier);

                    // SRA(MULSH(m, n), shpost)
                    self.unchecked_scalar_right_shift_arithmetic_assign_parallelized(
                        &mut tmp,
                        chosen_multiplier.shift_post,
                    );
                    tmp
                },
                || {
                    // XSIGN is: -1 if x < 0 { -1 } else { 0 }
                    // It is equivalent to SRA(x, N − 1)
                    self.unchecked_scalar_right_shift_arithmetic_parallelized(
                        numerator,
                        numerator_bits - 1,
                    )
                },
            );

            self.sub_assign_parallelized(&mut tmp, &xsign);
            quotient = tmp;
        } else {
            // Issue q = SRA(n + MULSH(m − 2^N , n), shpost) − XSIGN(n);
            // Note from the paper: m - 2^N is negative

            let (mut tmp, xsign) = rayon::join(
                move || {
                    // The subtraction may overflow.
                    // We then cast the result to a signed type.
                    // Overall, this will work fine due to two's complement representation
                    let cst = chosen_multiplier.multiplier
                        - (<T::Unsigned as Reciprocable>::DoublePrecision::ONE << numerator_bits);
                    let cst = T::DoublePrecision::cast_from(cst);

                    // MULSH(m - 2^N, n)
                    let mut tmp = self.signed_scalar_mul_high(numerator, cst);

                    // n + MULSH(m − 2^N , n)
                    self.add_assign_parallelized(&mut tmp, numerator);

                    // SRA(n + MULSH(m - 2^N, n), shpost)
                    self.unchecked_scalar_right_shift_assign_parallelized(
                        &mut tmp,
                        chosen_multiplier.shift_post,
                    );

                    tmp
                },
                || {
                    // XSIGN is: -1 if x < 0 { -1 } else { 0 }
                    // It is equivalent to SRA(x, N − 1)
                    self.unchecked_scalar_right_shift_parallelized(numerator, numerator_bits - 1)
                },
            );

            self.sub_assign_parallelized(&mut tmp, &xsign);
            quotient = tmp;
        }

        if divisor < T::ZERO {
            self.neg_parallelized(&quotient)
        } else {
            quotient
        }
    }

    /// # Note
    ///
    /// - This division rounds (truncates) the quotient towards 0
    pub fn unchecked_signed_scalar_div_rem_parallelized<T>(
        &self,
        numerator: &SignedRadixCiphertext,
        divisor: T,
    ) -> (SignedRadixCiphertext, SignedRadixCiphertext)
    where
        T: SignedReciprocable + ScalarMultiplier,
        <<T as SignedReciprocable>::Unsigned as Reciprocable>::DoublePrecision: Send,
    {
        let quotient = self.unchecked_signed_scalar_div_parallelized(numerator, divisor);

        // remainder = numerator - (quotient * divisor)
        let tmp = self.unchecked_scalar_mul_parallelized(&quotient, divisor);
        let remainder = self.sub_parallelized(numerator, &tmp);

        (quotient, remainder)
    }

    /// # Note
    ///
    /// - This division rounds (truncates) the quotient towards 0
    /// - If you need both the quotient and remainder use
    ///   [Self::unchecked_signed_scalar_div_rem_parallelized] instead.
    pub fn unchecked_signed_scalar_rem_parallelized<T>(
        &self,
        numerator: &SignedRadixCiphertext,
        divisor: T,
    ) -> SignedRadixCiphertext
    where
        T: SignedReciprocable + ScalarMultiplier,
        <<T as SignedReciprocable>::Unsigned as Reciprocable>::DoublePrecision: Send,
    {
        let (_, remainder) = self.unchecked_signed_scalar_div_rem_parallelized(numerator, divisor);

        remainder
    }

    /// Computes and returns the quotient and remainder of the division between
    /// a signed ciphertext and a signed clear value.
    ///
    /// # Note
    ///
    /// - This division rounds (truncates) the quotient towards 0
    pub fn signed_scalar_div_rem_parallelized<T>(
        &self,
        numerator: &SignedRadixCiphertext,
        divisor: T,
    ) -> (SignedRadixCiphertext, SignedRadixCiphertext)
    where
        T: SignedReciprocable + ScalarMultiplier,
        <<T as SignedReciprocable>::Unsigned as Reciprocable>::DoublePrecision: Send,
    {
        if numerator.block_carries_are_empty() {
            self.unchecked_signed_scalar_div_rem_parallelized(numerator, divisor)
        } else {
            let mut tmp = numerator.clone();
            self.full_propagate_parallelized(&mut tmp);
            self.unchecked_signed_scalar_div_rem_parallelized(&tmp, divisor)
        }
    }

    /// Computes the quotient of the division between
    /// a signed ciphertext and a signed clear value and assigns the
    /// result to the input ciphertext.
    ///
    /// # Note
    ///
    /// - This division rounds (truncates) the quotient towards 0
    pub fn signed_scalar_div_assign_parallelized<T>(
        &self,
        numerator: &mut SignedRadixCiphertext,
        divisor: T,
    ) where
        T: SignedReciprocable,
        <<T as SignedReciprocable>::Unsigned as Reciprocable>::DoublePrecision: Send,
    {
        if !numerator.block_carries_are_empty() {
            self.full_propagate_parallelized(numerator);
        }

        *numerator = self.unchecked_signed_scalar_div_parallelized(numerator, divisor);
    }

    /// Computes and returns the quotient of the division between
    /// a signed ciphertext and a signed clear value.
    ///
    /// # Note
    ///
    /// - This division rounds (truncates) the quotient towards 0
    /// - If you need both the quotient and remainder use [Self::signed_scalar_div_rem_parallelized]
    ///   instead.
    pub fn signed_scalar_div_parallelized<T>(
        &self,
        numerator: &SignedRadixCiphertext,
        divisor: T,
    ) -> SignedRadixCiphertext
    where
        T: SignedReciprocable,
        <<T as SignedReciprocable>::Unsigned as Reciprocable>::DoublePrecision: Send,
    {
        let mut result = numerator.clone();
        self.signed_scalar_div_assign_parallelized(&mut result, divisor);
        result
    }

    /// Computes and returns the remainder of the division between
    /// a signed ciphertext and a signed clear value.
    ///
    /// # Note
    ///
    /// - If you need both the quotient and remainder use [Self::signed_scalar_div_rem_parallelized]
    ///   instead.
    pub fn signed_scalar_rem_parallelized<T>(
        &self,
        numerator: &SignedRadixCiphertext,
        divisor: T,
    ) -> SignedRadixCiphertext
    where
        T: SignedReciprocable + ScalarMultiplier,
        <<T as SignedReciprocable>::Unsigned as Reciprocable>::DoublePrecision: Send,
    {
        let mut result = numerator.clone();
        self.signed_scalar_rem_assign_parallelized(&mut result, divisor);
        result
    }

    /// Computes the remainder of the division between
    /// a signed ciphertext and a signed clear value and assigns the
    /// result to the input ciphertext.
    pub fn signed_scalar_rem_assign_parallelized<T>(
        &self,
        numerator: &mut SignedRadixCiphertext,
        divisor: T,
    ) where
        T: SignedReciprocable + ScalarMultiplier,
        <<T as SignedReciprocable>::Unsigned as Reciprocable>::DoublePrecision: Send,
    {
        if !numerator.block_carries_are_empty() {
            self.full_propagate_parallelized(numerator);
        }

        let remainder = self.unchecked_signed_scalar_rem_parallelized(numerator, divisor);
        *numerator = remainder;
    }

    /// # Note
    /// This division rounds the quotient towards minus infinity
    pub fn unchecked_signed_scalar_div_floor_parallelized<T>(
        &self,
        numerator: &SignedRadixCiphertext,
        divisor: T,
    ) -> SignedRadixCiphertext
    where
        T: SignedReciprocable,
        <<T as SignedReciprocable>::Unsigned as Reciprocable>::DoublePrecision: Send,
    {
        assert_ne!(divisor, T::ZERO, "Cannot divide by zero");

        let numerator_bits = self.key.message_modulus.0.ilog2() * numerator.blocks.len() as u32;

        if divisor < T::ZERO {
            //dsign = XSIGN(d
            // Rust uses arithmetic shift by default
            let dsign = divisor >> (T::BITS - 1);

            // nsign = XSIGN(OR(n, n + dsign))
            let mut nsign = self.scalar_add_parallelized(numerator, dsign);
            self.unchecked_bitor_assign_parallelized(&mut nsign, numerator);
            self.scalar_right_shift_assign_parallelized(&mut nsign, numerator_bits - 1);

            // qsign = EOR(nsign, dsign).
            let qsign = self.unchecked_scalar_bitxor_parallelized(&nsign, dsign);

            let mut new_n = numerator.clone();
            self.smart_scalar_add_assign_parallelized(&mut new_n, dsign);
            self.smart_sub_assign_parallelized(&mut new_n, &mut nsign);
            self.full_propagate_parallelized(&mut new_n);

            let mut q = self.unchecked_signed_scalar_div_parallelized(&new_n, divisor);
            self.add_assign_parallelized(&mut q, &qsign);

            q
        } else {
            let chosen_multiplier = choose_multiplier(
                T::Unsigned::cast_from(divisor),
                numerator_bits - 1,
                numerator_bits,
            );

            if chosen_multiplier.l >= numerator_bits {
                // divisor is > numerator
                // so, in truncating div, q == 0, however in floor_div
                // * q == 0 || q == -1.
                // * q == -1 if the sign bit of the numerator and divisor sings differs.
                // So here we will build that 0 or -1

                // Conveniently in two's complement for the value 0, all bits are 0s
                // and for the value 1, all bits are one, meaning all blocks are the same.
                // So the idea is to build one correct block full of 0 or 1
                // and clone it to build ou resulting integer ciphertext.
                let divisor_sign_bit_is_set = u64::from(divisor < T::ZERO);
                let sign_bit_pos = self.key.message_modulus.0.ilog2() - 1;
                let lut = self.key.generate_lookup_table(|x| {
                    let x = x % self.key.message_modulus.0 as u64;
                    let numerator_sign_bit_is_set = (x >> sign_bit_pos) & 1;
                    let numerator_and_divisor_sign_differs =
                        numerator_sign_bit_is_set != divisor_sign_bit_is_set;

                    if numerator_and_divisor_sign_differs {
                        self.key.message_modulus.0 as u64 - 1
                    } else {
                        0
                    }
                });
                let block = self
                    .key
                    .apply_lookup_table(&numerator.blocks[numerator.blocks.len() - 1], &lut);

                let blocks = vec![block; numerator.blocks.len()];
                return SignedRadixCiphertext::from(blocks);
            }

            assert!(chosen_multiplier.l <= (T::BITS - 1) as u32);
            if divisor == (T::ONE << chosen_multiplier.l) {
                self.unchecked_scalar_right_shift_parallelized(numerator, chosen_multiplier.l)
            } else {
                assert!(
                    chosen_multiplier.multiplier
                        < <T::Unsigned as Reciprocable>::DoublePrecision::ONE << numerator_bits
                );

                // XSIGN is: -1 if x < 0 { -1 } else { 0 }
                // It is equivalent to SRA(x, N − 1)
                let xsign =
                    self.unchecked_scalar_right_shift_parallelized(numerator, numerator_bits - 1);

                let tmp = self.unchecked_bitxor_parallelized(&xsign, numerator);
                // Cast to Unsigned
                let tmp = RadixCiphertext::from(tmp.blocks);
                let mut tmp = self.scalar_mul_high(&tmp, chosen_multiplier.multiplier);
                self.unchecked_scalar_right_shift_logical_assign_parallelized(
                    &mut tmp,
                    chosen_multiplier.shift_post,
                );
                // Cast xsign to unsigned
                let xsign = RadixCiphertext::from(xsign.blocks);
                self.unchecked_bitxor_assign_parallelized(&mut tmp, &xsign);

                // cast quotient to signed
                SignedRadixCiphertext::from(tmp.blocks)
            }
        }
    }

    /// # Note
    /// This division rounds the quotient towards minus infinity
    pub fn unchecked_signed_scalar_div_rem_floor_parallelized<T>(
        &self,
        numerator: &SignedRadixCiphertext,
        divisor: T,
    ) -> (SignedRadixCiphertext, SignedRadixCiphertext)
    where
        T: SignedReciprocable + ScalarMultiplier,
        <<T as SignedReciprocable>::Unsigned as Reciprocable>::DoublePrecision: Send,
    {
        let quotient = self.unchecked_signed_scalar_div_floor_parallelized(numerator, divisor);

        // remainder = numerator - (quotient * divisor)
        let tmp = self.unchecked_scalar_mul_parallelized(&quotient, divisor);
        let remainder = self.sub_parallelized(numerator, &tmp);

        (quotient, remainder)
    }

    pub fn unchecked_scalar_div_rem_parallelized<T>(
        &self,
        numerator: &RadixCiphertext,
        divisor: T,
    ) -> (RadixCiphertext, RadixCiphertext)
    where
        T: Reciprocable + ScalarMultiplier + DecomposableInto<u8>,
    {
        let quotient = self.unchecked_scalar_div_parallelized(numerator, divisor);
        let remainder = if MiniUnsignedInteger::is_power_of_two(divisor) {
            // unchecked_scalar_div would have panicked if divisor was zero
            self.scalar_bitand_parallelized(numerator, divisor - T::ONE)
        } else {
            // remainder = numerator - (quotient * divisor)
            let tmp = self.unchecked_scalar_mul_parallelized(&quotient, divisor);
            self.sub_parallelized(numerator, &tmp)
        };

        (quotient, remainder)
    }

    pub fn unchecked_scalar_rem_parallelized<T>(
        &self,
        numerator: &RadixCiphertext,
        divisor: T,
    ) -> RadixCiphertext
    where
        T: Reciprocable + ScalarMultiplier + DecomposableInto<u8>,
    {
        if MiniUnsignedInteger::is_power_of_two(divisor) {
            // The remainder is simply the bits that would get 'shifted out'
            return self.scalar_bitand_parallelized(numerator, divisor - T::ONE);
        }

        let (_quotient, remainder) = self.unchecked_scalar_div_rem_parallelized(numerator, divisor);
        remainder
    }

    pub fn smart_scalar_div_assign_parallelized<T>(
        &self,
        numerator: &mut RadixCiphertext,
        divisor: T,
    ) where
        T: Reciprocable + DecomposableInto<u8>,
    {
        if !numerator.block_carries_are_empty() {
            self.full_propagate_parallelized(numerator);
        }

        *numerator = self.unchecked_scalar_div_parallelized(numerator, divisor);
    }

    pub fn smart_scalar_rem_assign_parallelized<T>(
        &self,
        numerator: &mut RadixCiphertext,
        divisor: T,
    ) where
        T: Reciprocable + ScalarMultiplier + DecomposableInto<u8>,
    {
        if !numerator.block_carries_are_empty() {
            self.full_propagate_parallelized(numerator);
        }

        *numerator = self.unchecked_scalar_rem_parallelized(numerator, divisor);
    }

    pub fn smart_scalar_div_parallelized<T>(
        &self,
        numerator: &mut RadixCiphertext,
        divisor: T,
    ) -> RadixCiphertext
    where
        T: Reciprocable + DecomposableInto<u8>,
    {
        if !numerator.block_carries_are_empty() {
            self.full_propagate_parallelized(numerator);
        }

        self.unchecked_scalar_div_parallelized(numerator, divisor)
    }

    pub fn smart_scalar_rem_parallelized<T>(
        &self,
        numerator: &mut RadixCiphertext,
        divisor: T,
    ) -> RadixCiphertext
    where
        T: Reciprocable + ScalarMultiplier + DecomposableInto<u8>,
    {
        if !numerator.block_carries_are_empty() {
            self.full_propagate_parallelized(numerator);
        }

        self.unchecked_scalar_rem_parallelized(numerator, divisor)
    }

    pub fn smart_scalar_div_rem_parallelized<T>(
        &self,
        numerator: &mut RadixCiphertext,
        divisor: T,
    ) -> (RadixCiphertext, RadixCiphertext)
    where
        T: Reciprocable + ScalarMultiplier + DecomposableInto<u8>,
    {
        if !numerator.block_carries_are_empty() {
            self.full_propagate_parallelized(numerator);
        }

        self.unchecked_scalar_div_rem_parallelized(numerator, divisor)
    }

    pub fn scalar_div_assign_parallelized<T>(&self, numerator: &mut RadixCiphertext, divisor: T)
    where
        T: Reciprocable + DecomposableInto<u8>,
    {
        if !numerator.block_carries_are_empty() {
            self.full_propagate_parallelized(numerator);
        }

        *numerator = self.unchecked_scalar_div_parallelized(numerator, divisor);
    }

    pub fn scalar_rem_assign_parallelized<T>(&self, numerator: &mut RadixCiphertext, divisor: T)
    where
        T: Reciprocable + ScalarMultiplier + DecomposableInto<u8>,
    {
        if !numerator.block_carries_are_empty() {
            self.full_propagate_parallelized(numerator);
        }

        *numerator = self.unchecked_scalar_rem_parallelized(numerator, divisor);
    }

    /// Computes homomorphically a division of a ciphertext by a scalar.
    ///
    /// # Note
    ///
    /// If you need both the quotient and the remainder of the division
    /// use [Self::scalar_div_rem_parallelized].
    ///
    /// # Panics
    ///
    /// Panics if scalar is zero.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2, size);
    ///
    /// let msg = 230u8;
    /// let scalar = 12u8;
    ///
    /// let ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a scalar division:
    /// let ct_res = sks.scalar_div_parallelized(&ct, scalar);
    ///
    /// let decrypted: u8 = cks.decrypt(&ct_res);
    /// assert_eq!(msg / scalar, decrypted);
    /// ```
    pub fn scalar_div_parallelized<T>(
        &self,
        numerator: &RadixCiphertext,
        divisor: T,
    ) -> RadixCiphertext
    where
        T: Reciprocable + DecomposableInto<u8>,
    {
        let mut result = numerator.clone();
        self.scalar_div_assign_parallelized(&mut result, divisor);
        result
    }

    /// Computes homomorphically the remainder of the division of a ciphertext by a scalar.
    ///
    /// # Note
    ///
    /// If you need both the quotient and the remainder of the division
    /// use [Self::scalar_div_rem_parallelized].
    ///
    /// # Panics
    ///
    /// Panics if scalar is zero.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2, size);
    ///
    /// let msg = 230u8;
    /// let scalar = 12u8;
    ///
    /// let ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a scalar division:
    /// let ct_res = sks.scalar_rem_parallelized(&ct, scalar);
    ///
    /// let decrypted: u8 = cks.decrypt(&ct_res);
    /// assert_eq!(msg % scalar, decrypted);
    /// ```
    pub fn scalar_rem_parallelized<T>(
        &self,
        numerator: &RadixCiphertext,
        divisor: T,
    ) -> RadixCiphertext
    where
        T: Reciprocable + ScalarMultiplier + DecomposableInto<u8>,
    {
        let mut result = numerator.clone();
        self.scalar_rem_assign_parallelized(&mut result, divisor);
        result
    }

    /// Computes homomorphically the euclidean the division of a ciphertext by a scalar.
    ///
    /// # Panics
    ///
    /// Panics if scalar is zero.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2, size);
    ///
    /// let msg = 230u8;
    /// let scalar = 12u8;
    ///
    /// let ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a scalar division:
    /// let (q, r) = sks.scalar_div_rem_parallelized(&ct, scalar);
    ///
    /// let decrypted_quotient: u8 = cks.decrypt(&q);
    /// let decrypted_remainder: u8 = cks.decrypt(&r);
    /// assert_eq!(msg / scalar, decrypted_quotient);
    /// assert_eq!(msg % scalar, decrypted_remainder);
    /// ```
    pub fn scalar_div_rem_parallelized<T>(
        &self,
        numerator: &RadixCiphertext,
        divisor: T,
    ) -> (RadixCiphertext, RadixCiphertext)
    where
        T: Reciprocable + ScalarMultiplier + DecomposableInto<u8>,
    {
        if numerator.block_carries_are_empty() {
            self.unchecked_scalar_div_rem_parallelized(numerator, divisor)
        } else {
            let mut cloned_numerator = numerator.clone();
            self.full_propagate_parallelized(&mut cloned_numerator);
            self.unchecked_scalar_div_rem_parallelized(&cloned_numerator, divisor)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_approximated_multiplier() {
        // These are taken from the original paper
        let chosen = choose_multiplier(10u64, 32, 32);
        assert_eq!(chosen.shift_post, 3);
        assert_eq!(chosen.multiplier, ((1u128 << 34) + 1) / 5);

        let chosen = choose_multiplier(7u64, 32, 32);
        assert_eq!(chosen.multiplier, ((1u128 << 35) + 3) / 7);

        // signed usage example
        let chosen = choose_multiplier(3u64, 31, 32);
        assert_eq!(chosen.multiplier, ((1u128 << 32) + 2) / 3);
        assert_eq!(chosen.shift_post, 0);
    }
}
