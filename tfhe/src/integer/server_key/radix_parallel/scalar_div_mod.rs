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
use crate::core_crypto::prelude::{Numeric, UnsignedInteger};
use crate::integer::block_decomposition::DecomposableInto;
use crate::integer::ciphertext::RadixCiphertext;
use crate::integer::ServerKey;

#[inline(always)]
fn is_even(d: u64) -> bool {
    (d & 1) == 0
}

#[derive(Debug, Copy, Clone)]
struct ApproximatedMultiplier {
    // The approximation of the inverse
    multiplier: u128,
    // The shift that we might need
    // to do post mutliplication to correct error
    shift_post: u32,
}

impl ApproximatedMultiplier {
    #[allow(non_snake_case)]
    fn choose(divisor: u64, precision: u32, integer_bits: u32) -> Self {
        // Keep the same name as in the paper
        let N = integer_bits;

        assert_ne!(divisor, 0);
        assert!(precision >= 1 && precision <= N);

        let d = u128::from(divisor);
        let two_pow_n = 1u128 << N;

        // Find l such that (l-1) < log2(d) <= l
        let l = d.ilog2() + u32::from(!d.is_power_of_two());
        let mut shift_post = l;

        // The formula is m_low == 2**(N+l) / d
        // however N + l may be == to 128, which means doing
        // 2**(N + l) would not be valid, so the formula has been written in a
        // way that does not overlflow.
        //
        // By writing m_low = (m_low - 2**N) + (2**N)
        let mut m_low = (two_pow_n * ((1 << l) - d)) / d;
        m_low += two_pow_n;

        // The formula is (2**(N+l) + 2**(N + l - precision)) / d
        // again 2**(N+l) could overflow
        let mut m_high = ((two_pow_n * ((1 << l) - d)) + (1 << (N + l - precision))) / d;
        m_high += two_pow_n;

        assert!(m_low < m_high);

        loop {
            let m_low_i = m_low >> 1;
            let m_high_i = m_high >> 1;

            if m_low_i >= m_high_i || shift_post == 0 {
                break;
            }

            m_low = m_low_i;
            m_high = m_high_i;
            shift_post -= 1;
        }

        Self {
            multiplier: m_high,
            shift_post,
        }
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
    fn scalar_mul_high(&self, lhs: &RadixCiphertext, rhs: u128) -> RadixCiphertext {
        let mut result = lhs.clone();
        self.extend_radix_with_trivial_zero_blocks_msb_assign(&mut result, lhs.blocks.len());
        self.scalar_mul_assign_parallelized(&mut result, rhs);
        self.trim_radix_blocks_lsb_assign(&mut result, lhs.blocks.len());
        result
    }

    pub fn unchecked_scalar_div_parallelized<T>(
        &self,
        numerator: &RadixCiphertext,
        divisor: T,
    ) -> RadixCiphertext
    where
        u64: From<T>,
        T: Numeric,
    {
        let numerator_bits = self.key.message_modulus.0.ilog2() * numerator.blocks.len() as u32;

        let divisor = u64::from(divisor);
        // Rust has a check on all division, so we shall also have one
        assert_ne!(divisor, 0, "Cannot divide by zero");

        if divisor.is_power_of_two() {
            // Even in FHE, shifting is faster than multiplying / dividing
            return self
                .unchecked_scalar_right_shift_parallelized(numerator, divisor.ilog2() as u64);
        }

        let log2_divisor = divisor.ceil_ilog2();
        if log2_divisor > numerator_bits {
            return self.create_trivial_zero_radix(numerator.blocks.len());
        }

        let mut chosen_multiplier =
            ApproximatedMultiplier::choose(divisor, numerator_bits, numerator_bits);

        let mut shift_pre = 0;
        if chosen_multiplier.multiplier >= (1u128 << numerator_bits) && is_even(divisor) {
            // Find e such that d = (1 << e) * divisor_odd
            // where divisor_odd is odd
            let two_pow_e = (divisor as u128) & ((1u128 << numerator_bits) - divisor as u128);
            let e = two_pow_e.ilog2();
            let divisor_odd = divisor as u128 / two_pow_e;

            assert!(numerator_bits > e && e <= 64);
            chosen_multiplier = ApproximatedMultiplier::choose(
                divisor_odd as u64,
                numerator_bits - e,
                numerator_bits,
            );
            shift_pre = e as u64;
        }

        if chosen_multiplier.multiplier >= (1u128 << numerator_bits) {
            assert!(shift_pre == 0);

            let inverse = chosen_multiplier.multiplier - (1u128 << numerator_bits);
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

    pub fn unchecked_scalar_div_rem_parallelized<T>(
        &self,
        numerator: &RadixCiphertext,
        divisor: T,
    ) -> (RadixCiphertext, RadixCiphertext)
    where
        u64: From<T>,
        T: UnsignedInteger + DecomposableInto<u8>,
    {
        let quotient = self.unchecked_scalar_div_parallelized(numerator, divisor);
        let remainder = if divisor.is_power_of_two() {
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
        u64: From<T>,
        T: UnsignedInteger + DecomposableInto<u8>,
    {
        if divisor.is_power_of_two() {
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
        u64: From<T>,
        T: UnsignedInteger + DecomposableInto<u8>,
    {
        if !numerator.block_carries_are_empty() {
            self.full_propagate_parallelized(numerator)
        }

        *numerator = self.unchecked_scalar_div_parallelized(numerator, divisor);
    }

    pub fn smart_scalar_rem_assign_parallelized<T>(
        &self,
        numerator: &mut RadixCiphertext,
        divisor: T,
    ) where
        u64: From<T>,
        T: UnsignedInteger + DecomposableInto<u8>,
    {
        if !numerator.block_carries_are_empty() {
            self.full_propagate_parallelized(numerator)
        }

        *numerator = self.unchecked_scalar_rem_parallelized(numerator, divisor);
    }

    pub fn smart_scalar_div_parallelized<T>(
        &self,
        numerator: &mut RadixCiphertext,
        divisor: T,
    ) -> RadixCiphertext
    where
        u64: From<T>,
        T: UnsignedInteger + DecomposableInto<u8>,
    {
        if !numerator.block_carries_are_empty() {
            self.full_propagate_parallelized(numerator)
        }

        self.unchecked_scalar_div_parallelized(numerator, divisor)
    }

    pub fn smart_scalar_rem_parallelized<T>(
        &self,
        numerator: &mut RadixCiphertext,
        divisor: T,
    ) -> RadixCiphertext
    where
        u64: From<T>,
        T: UnsignedInteger + DecomposableInto<u8>,
    {
        if !numerator.block_carries_are_empty() {
            self.full_propagate_parallelized(numerator)
        }

        self.unchecked_scalar_rem_parallelized(numerator, divisor)
    }

    pub fn smart_scalar_div_rem_parallelized<T>(
        &self,
        numerator: &mut RadixCiphertext,
        divisor: T,
    ) -> (RadixCiphertext, RadixCiphertext)
    where
        u64: From<T>,
        T: UnsignedInteger + DecomposableInto<u8>,
    {
        if !numerator.block_carries_are_empty() {
            self.full_propagate_parallelized(numerator)
        }

        self.unchecked_scalar_div_rem_parallelized(numerator, divisor)
    }

    pub fn scalar_div_assign_parallelized<T>(&self, numerator: &mut RadixCiphertext, divisor: T)
    where
        u64: From<T>,
        T: UnsignedInteger + DecomposableInto<u8>,
    {
        if !numerator.block_carries_are_empty() {
            self.full_propagate_parallelized(numerator)
        }

        *numerator = self.unchecked_scalar_div_parallelized(numerator, divisor);
    }

    pub fn scalar_rem_assign_parallelized<T>(&self, numerator: &mut RadixCiphertext, divisor: T)
    where
        u64: From<T>,
        T: UnsignedInteger + DecomposableInto<u8>,
    {
        if !numerator.block_carries_are_empty() {
            self.full_propagate_parallelized(numerator)
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
        u64: From<T>,
        T: UnsignedInteger + DecomposableInto<u8>,
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
        u64: From<T>,
        T: UnsignedInteger + DecomposableInto<u8>,
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
        u64: From<T>,
        T: UnsignedInteger + DecomposableInto<u8>,
    {
        if !numerator.block_carries_are_empty() {
            let mut cloned_numerator = numerator.clone();
            self.full_propagate_parallelized(&mut cloned_numerator);
            self.unchecked_scalar_div_rem_parallelized(&cloned_numerator, divisor)
        } else {
            self.unchecked_scalar_div_rem_parallelized(numerator, divisor)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_approximated_multiplier() {
        // These are taken from the original paper
        let chosen = ApproximatedMultiplier::choose(10, 32, 32);
        assert_eq!(chosen.shift_post, 3);
        assert_eq!(chosen.multiplier, ((1u128 << 34) + 1) / 5);

        let chosen = ApproximatedMultiplier::choose(7, 32, 32);
        assert_eq!(chosen.multiplier, ((1u128 << 35) + 3) / 7);
    }
}
