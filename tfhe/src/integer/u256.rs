use std::ops::{BitAnd, BitOrAssign, Shl, ShlAssign, Shr, SubAssign};

use crate::core_crypto::prelude::{CastFrom, Numeric, UnsignedInteger};

#[inline(always)]
pub fn add_with_carry<T: UnsignedInteger>(l: T, r: T, c: bool) -> (T, bool) {
    let (lr, o0) = l.overflowing_add(r);
    let (lrc, o1) = lr.overflowing_add(T::cast_from(c));
    (lrc, o0 | o1)
}

pub fn add_assign_words<T: UnsignedInteger>(lhs: &mut [T], rhs: &[T]) {
    let iter = lhs
        .iter_mut()
        .zip(rhs.iter().copied().chain(std::iter::repeat(T::ZERO)));

    let mut carry = false;
    for (lhs_block, rhs_block) in iter {
        let (result, out_carry) = add_with_carry(*lhs_block, rhs_block, carry);
        *lhs_block = result;
        carry = out_carry;
    }
}

/// lhs and rhs are slice of words.
///
/// They must be in lsb -> msb order
pub(crate) fn schoolbook_mul_assign(lhs: &mut [u64], rhs: &[u64]) {
    assert!(lhs.len() >= rhs.len());
    let mut terms = Vec::with_capacity(rhs.len());

    for (i, rhs_block) in rhs.iter().copied().enumerate() {
        let mut blocks = Vec::with_capacity(lhs.len() + i);
        blocks.resize(i, 0u64); // pad with 0

        let mut carry = 0;
        for lhs_block in lhs.iter().copied() {
            let mut res = lhs_block as u128 * rhs_block as u128;
            res += carry;
            let carry_out = res >> u64::BITS;
            blocks.push((res & u64::MAX as u128) as u64);
            carry = carry_out;
        }
        blocks.push(carry as u64);

        terms.push(blocks)
    }

    let mut result = terms.pop().unwrap();
    for term in terms {
        add_assign_words(&mut result, &term);
    }

    for (lhs_block, result_block) in lhs.iter_mut().zip(result) {
        *lhs_block = result_block;
    }
}

pub(crate) fn slow_div<T>(numerator: T, divisor: T) -> (T, T)
where
    T: Numeric
        + ShlAssign<u32>
        + Shl<u32, Output = T>
        + Shr<u32, Output = T>
        + BitOrAssign<T>
        + SubAssign<T>
        + BitAnd<T, Output = T>
        + Ord,
{
    assert!(divisor != T::ZERO);

    let mut quotient = T::ZERO;
    let mut remainder = T::ZERO;

    for i in (0..T::BITS).rev() {
        remainder <<= 1;
        remainder |= (numerator >> i as u32) & T::ONE;

        if remainder >= divisor {
            remainder -= divisor;
            quotient |= T::ONE << (i as u32);
        }
    }

    (quotient, remainder)
}

const BYTES_PER_U64: usize = std::mem::size_of::<u64>() / std::mem::size_of::<u8>();

// Little endian order
#[derive(Default, Copy, Clone, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct U256(pub(crate) [u64; 4]);

impl U256 {
    pub const BITS: u32 = 256;
    pub const MAX: Self = Self([u64::MAX; 4]);
    pub const MIN: Self = Self([0; 4]);
    pub const ZERO: Self = Self([0; 4]);
    pub const ONE: Self = Self([1, 0, 0, 0]);
    pub const TWO: Self = Self([2, 0, 0, 0]);

    /// Replaces the current value by interpreting the bytes in big endian order
    pub fn copy_from_be_byte_slice(&mut self, bytes: &[u8]) {
        assert_eq!(bytes.len(), BYTES_PER_U64 * 4);

        let mut array = [0u8; BYTES_PER_U64];
        for (sub_bytes, word) in bytes
            .chunks_exact(BYTES_PER_U64)
            .zip(self.0.iter_mut().rev())
        {
            array.copy_from_slice(sub_bytes);
            *word = u64::from_be_bytes(array);
        }
    }

    /// Replaces the current value by interpreting the bytes in little endian order
    pub fn copy_from_le_byte_slice(&mut self, bytes: &[u8]) {
        assert_eq!(bytes.len(), BYTES_PER_U64 * 4);

        let mut array = [0u8; BYTES_PER_U64];
        for (sub_bytes, word) in bytes.chunks_exact(BYTES_PER_U64).zip(self.0.iter_mut()) {
            array.copy_from_slice(sub_bytes);
            *word = u64::from_le_bytes(array);
        }
    }

    pub fn copy_to_le_byte_slice(&self, bytes: &mut [u8]) {
        assert_eq!(bytes.len(), BYTES_PER_U64 * 4);

        for (sub_bytes, word) in bytes.chunks_exact_mut(BYTES_PER_U64).zip(self.0.iter()) {
            sub_bytes.copy_from_slice(word.to_le_bytes().as_slice());
        }
    }

    pub fn copy_to_be_byte_slice(&self, bytes: &mut [u8]) {
        assert_eq!(bytes.len(), BYTES_PER_U64 * 4);

        for (sub_bytes, word) in bytes
            .chunks_exact_mut(BYTES_PER_U64)
            .zip(self.0.iter().rev())
        {
            sub_bytes.copy_from_slice(word.to_be_bytes().as_slice());
        }
    }

    pub fn to_low_high_u128(self) -> (u128, u128) {
        let low = self.0[0] as u128 | ((self.0[1] as u128) << 64);
        let high = self.0[2] as u128 | ((self.0[3] as u128) << 64);
        (low, high)
    }

    pub fn is_power_of_two(self) -> bool {
        if self == Self::ZERO {
            return false;
        }
        (self & (self - Self::ONE)) == Self::ZERO
    }

    pub fn leading_zeros(self) -> u32 {
        // iter from msb to lsb
        for (i, word) in self.0.iter().copied().rev().enumerate() {
            let leading_zeros = dbg!(word.leading_zeros());
            if leading_zeros != u64::BITS {
                return (i as u32 * u64::BITS) + leading_zeros;
            }
        }

        // Everyting is zero
        self.0.len() as u32 * u64::BITS
    }

    pub fn ilog2(self) -> u32 {
        // Rust has the same assert
        assert!(
            self > Self::ZERO,
            "argument of integer logarithm must be positive"
        );
        (self.0.len() as u32 * u64::BITS) - self.leading_zeros() - 1
    }
}

#[cfg(test)]
impl rand::distributions::Distribution<U256> for rand::distributions::Standard {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> U256 {
        U256([rng.gen(), rng.gen(), rng.gen(), rng.gen()])
    }
}

// Since we store as [low, high], deriving ord
// would produces bad ordering
impl std::cmp::Ord for U256 {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let mut current_ord = std::cmp::Ordering::Equal;
        for (w_self, w_other) in self.0.iter().rev().zip(other.0.iter().rev()) {
            current_ord = w_self.cmp(w_other);
            if current_ord != std::cmp::Ordering::Equal {
                break;
            }
        }

        current_ord
    }
}

impl std::cmp::PartialOrd for U256 {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl std::ops::Add<Self> for U256 {
    type Output = Self;

    fn add(mut self, rhs: Self) -> Self::Output {
        self += rhs;
        self
    }
}

impl std::ops::AddAssign<Self> for U256 {
    fn add_assign(&mut self, rhs: Self) {
        add_assign_words(self.0.as_mut_slice(), rhs.0.as_slice())
    }
}

impl std::ops::Sub<Self> for U256 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        let negated = !rhs + Self::from(1u64);
        self + negated
    }
}

impl std::ops::SubAssign<Self> for U256 {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl std::ops::Shr<u32> for U256 {
    type Output = Self;

    fn shr(mut self, rhs: u32) -> Self::Output {
        self >>= rhs;
        self
    }
}

impl std::ops::MulAssign<Self> for U256 {
    fn mul_assign(&mut self, rhs: Self) {
        if rhs.is_power_of_two() {
            self.shl_assign(rhs.ilog2());
            return;
        }
        schoolbook_mul_assign(self.0.as_mut_slice(), rhs.0.as_slice());
    }
}

impl std::ops::Mul<Self> for U256 {
    type Output = Self;

    fn mul(mut self, rhs: Self) -> Self::Output {
        self *= rhs;
        self
    }
}

impl std::ops::DivAssign<Self> for U256 {
    fn div_assign(&mut self, rhs: Self) {
        *self = *self / rhs;
    }
}

impl std::ops::Div<Self> for U256 {
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        let (q, _) = slow_div(self, rhs);
        q
    }
}

impl std::ops::RemAssign<Self> for U256 {
    fn rem_assign(&mut self, rhs: Self) {
        *self = *self % rhs;
    }
}

impl std::ops::Rem<Self> for U256 {
    type Output = Self;

    fn rem(self, rhs: Self) -> Self::Output {
        let (_, r) = slow_div(self, rhs);
        r
    }
}

impl std::ops::ShrAssign<u32> for U256 {
    // move bits from MSB to LSB
    fn shr_assign(&mut self, shift: u32) {
        let shift = shift % Self::BITS;

        let num_rotations = (shift / u64::BITS) as usize;
        self.0.rotate_left(num_rotations);

        let len = self.0.len();
        let (head, tail) = self.0.as_mut_slice().split_at_mut(len - num_rotations);
        tail.fill(0);

        let shift_in_words = shift % u64::BITS;

        let value_mask = u64::MAX >> shift_in_words;
        let carry_mask = ((1u64 << shift_in_words) - 1u64).rotate_right(shift_in_words);

        let mut carry = 0u64;
        for word in &mut head.iter_mut().rev() {
            let rotated = word.rotate_right(shift_in_words);
            let value = (rotated & value_mask) | carry;
            let carry_for_next = rotated & carry_mask;

            *word = value;
            carry = carry_for_next;
        }
    }
}

impl std::ops::Shl<u32> for U256 {
    type Output = Self;

    fn shl(mut self, rhs: u32) -> Self::Output {
        self <<= rhs;
        self
    }
}

impl std::ops::ShlAssign<u32> for U256 {
    // move bits from LSB to MSB
    fn shl_assign(&mut self, shift: u32) {
        let shift = shift % Self::BITS;

        let num_rotations = (shift / u64::BITS) as usize;
        self.0.rotate_right(num_rotations);

        let (head, tail) = self.0.as_mut_slice().split_at_mut(num_rotations);
        head.fill(0);

        let shift_in_words = shift % u64::BITS;

        let carry_mask = (1u64 << shift_in_words) - 1u64;
        let value_mask = u64::MAX << (shift_in_words);

        let mut carry = 0u64;
        for word in &mut tail.iter_mut() {
            let rotated = word.rotate_left(shift_in_words);
            let value = (rotated & value_mask) | carry;
            let carry_for_next = rotated & carry_mask;

            *word = value;
            carry = carry_for_next;
        }
    }
}

impl std::ops::Not for U256 {
    type Output = Self;

    fn not(mut self) -> Self::Output {
        for self_word in self.0.iter_mut() {
            *self_word = !*self_word;
        }
        self
    }
}

impl std::ops::BitAnd<Self> for U256 {
    type Output = Self;

    fn bitand(mut self, rhs: Self) -> Self::Output {
        self &= rhs;
        self
    }
}

impl std::ops::BitAndAssign<Self> for U256 {
    fn bitand_assign(&mut self, rhs: Self) {
        for (self_word, rhs_word) in self.0.iter_mut().zip(rhs.0) {
            *self_word &= rhs_word;
        }
    }
}

impl std::ops::BitOrAssign<Self> for U256 {
    fn bitor_assign(&mut self, rhs: Self) {
        for (self_word, rhs_word) in self.0.iter_mut().zip(rhs.0) {
            *self_word |= rhs_word;
        }
    }
}

impl std::ops::BitOr<Self> for U256 {
    type Output = Self;

    fn bitor(mut self, rhs: Self) -> Self::Output {
        self |= rhs;
        self
    }
}

impl From<(u64, u64, u64, u64)> for U256 {
    fn from(value: (u64, u64, u64, u64)) -> Self {
        Self([value.0, value.1, value.2, value.3])
    }
}

impl std::ops::BitXorAssign<Self> for U256 {
    fn bitxor_assign(&mut self, rhs: Self) {
        for (self_word, rhs_word) in self.0.iter_mut().zip(rhs.0) {
            *self_word ^= rhs_word;
        }
    }
}

impl std::ops::BitXor<Self> for U256 {
    type Output = Self;

    fn bitxor(mut self, rhs: Self) -> Self::Output {
        self ^= rhs;
        self
    }
}
impl From<(u128, u128)> for U256 {
    fn from(v: (u128, u128)) -> Self {
        Self([
            (v.0 & u128::from(u64::MAX)) as u64,
            (v.0 >> 64) as u64,
            (v.1 & u128::from(u64::MAX)) as u64,
            (v.1 >> 64) as u64,
        ])
    }
}

impl From<u8> for U256 {
    fn from(value: u8) -> Self {
        Self::from(value as u128)
    }
}

impl From<u16> for U256 {
    fn from(value: u16) -> Self {
        Self::from(value as u128)
    }
}

impl From<u32> for U256 {
    fn from(value: u32) -> Self {
        Self::from(value as u128)
    }
}

impl From<u64> for U256 {
    fn from(value: u64) -> Self {
        Self::from(value as u128)
    }
}

impl From<u128> for U256 {
    fn from(value: u128) -> Self {
        Self([
            (value & u128::from(u64::MAX)) as u64,
            (value >> 64) as u64,
            0,
            0,
        ])
    }
}

impl CastFrom<U256> for u64 {
    fn cast_from(input: U256) -> Self {
        input.0[0]
    }
}

impl CastFrom<U256> for u8 {
    fn cast_from(input: U256) -> Self {
        input.0[0] as u8
    }
}

impl CastFrom<u32> for U256 {
    fn cast_from(input: u32) -> Self {
        Self::from(input)
    }
}

impl CastFrom<u64> for U256 {
    fn cast_from(input: u64) -> Self {
        Self::from(input)
    }
}

impl CastFrom<u8> for U256 {
    fn cast_from(input: u8) -> Self {
        Self::from(input as u64)
    }
}

impl From<bool> for U256 {
    fn from(input: bool) -> Self {
        Self::from(if input { 1u64 } else { 0u64 })
    }
}

// SAFETY
//
// U256 is allowed to be all zeros
unsafe impl bytemuck::Zeroable for U256 {}

// SAFETY
//
// u64 impl bytemuck::Pod,
// [T; N] impl bytemuck::Pod if T: bytemuck::Pod
//
// https://docs.rs/bytemuck/latest/bytemuck/trait.Pod.html#foreign-impls
//
// Thus U256 can safely be considered Pod
unsafe impl bytemuck::Pod for U256 {}

impl Numeric for U256 {
    const BITS: usize = Self::BITS as usize;

    const ZERO: Self = Self::ZERO;

    const ONE: Self = Self::ONE;

    const TWO: Self = Self::TWO;

    const MAX: Self = Self::MAX;
}

#[cfg(test)]
mod tests {
    use std::panic::catch_unwind;

    use rand::Rng;

    use super::*;

    fn u64_with_odd_bits_set() -> u64 {
        let mut v = 0u64;

        for i in (1..=63).step_by(2) {
            v |= 1u64 << i;
        }

        v
    }

    fn u64_with_even_bits_set() -> u64 {
        let mut v = 0u64;

        // bit index are from 0 to 63
        for i in (0..=62).step_by(2) {
            v |= 1u64 << i;
        }

        v
    }

    #[test]
    fn test_u64_even_odd_bits() {
        let all_even_bits_set = u64_with_even_bits_set();
        let all_odd_bits_set = u64_with_odd_bits_set();

        assert_ne!(all_odd_bits_set, all_even_bits_set);

        assert_eq!(all_even_bits_set.rotate_right(1), all_odd_bits_set);
        assert_eq!(all_even_bits_set, all_odd_bits_set.rotate_left(1));
    }

    #[test]
    fn test_bitand() {
        let all_even_bits_set = U256([u64_with_even_bits_set(); 4]);
        let all_odd_bits_set = U256([u64_with_odd_bits_set(); 4]);

        assert_ne!(all_odd_bits_set, all_even_bits_set);
        assert_eq!(all_odd_bits_set & all_odd_bits_set, all_odd_bits_set);
        assert_eq!(all_even_bits_set & all_even_bits_set, all_even_bits_set);
        assert_eq!(all_even_bits_set & all_odd_bits_set, U256::ZERO);
    }

    #[test]
    fn test_bitor() {
        let all_even_bits_set = U256([u64_with_even_bits_set(); 4]);
        let all_odd_bits_set = U256([u64_with_odd_bits_set(); 4]);

        assert_ne!(all_odd_bits_set, all_even_bits_set);
        assert_eq!(all_odd_bits_set | all_odd_bits_set, all_odd_bits_set);
        assert_eq!(all_even_bits_set | all_even_bits_set, all_even_bits_set);
        assert_eq!(all_even_bits_set | all_odd_bits_set, U256::MAX);
    }

    #[test]
    fn test_bitxor() {
        let all_even_bits_set = U256([u64_with_even_bits_set(); 4]);
        let all_odd_bits_set = U256([u64_with_odd_bits_set(); 4]);

        assert_ne!(all_odd_bits_set, all_even_bits_set);
        assert_eq!(all_odd_bits_set ^ all_odd_bits_set, U256::ZERO);
        assert_eq!(all_even_bits_set ^ all_even_bits_set, U256::ZERO);
        assert_eq!(all_even_bits_set ^ all_odd_bits_set, U256::MAX);
    }

    #[test]
    fn test_is_power_of_two() {
        assert!(!U256::ZERO.is_power_of_two());
        assert!(!U256::MAX.is_power_of_two());
        assert!(!U256::from(8329842348123u64).is_power_of_two());

        for i in 0..U256::BITS {
            assert!((U256::ONE << i).is_power_of_two())
        }
    }

    #[test]
    fn test_ilog2() {
        assert!(catch_unwind(|| { U256::ZERO.ilog2() }).is_err());

        assert_eq!(U256::MAX.ilog2(), 255);
        assert_eq!(
            U256::from(8329842348123u64).ilog2(),
            8329842348123u64.ilog2()
        );

        assert_eq!(
            U256::from(8320912948329842348123u128).ilog2(),
            8320912948329842348123u128.ilog2()
        );

        assert_eq!(
            U256::from(2323912928329942718123u128).ilog2(),
            2323912928329942718123u128.ilog2()
        );

        for i in 0..U256::BITS {
            assert_eq!((U256::ONE << i).ilog2(), i)
        }
    }

    #[test]
    fn test_mul() {
        let u64_max = U256::from(u64::MAX);
        let expected = u64::MAX as u128 * u64::MAX as u128;
        assert_eq!(u64_max * u64_max, U256::from(expected));

        let mut rng = rand::thread_rng();
        for _ in 0..5 {
            let a = rng.gen::<u64>();
            let b = rng.gen::<u64>();

            let res = U256::from(a) * U256::from(b);
            let expected = a as u128 * b as u128;
            assert_eq!(res, U256::from(expected));
        }

        let u128_max = U256::from(u128::MAX);
        let res = u128_max * u128_max;
        let expected = U256::from((1u128, 340282366920938463463374607431768211454u128));
        assert_eq!(res, expected);

        let u128_max = U256::from(u128::MAX);
        let res = u128_max * U256::from(3284723894u64);
        let expected = U256::from((340282366920938463463374607428483487562u128, 3284723893u128));
        assert_eq!(res, expected);

        let u128_max = U256::from(u128::MAX);
        let res = u128_max * U256::from(u64::MAX);
        let expected = U256::from((
            340282366920938463444927863358058659841u128,
            18446744073709551614u128,
        ));
        assert_eq!(res, expected);

        let u128_max = U256::from(u128::MAX);
        let res = u128_max * U256::ZERO;
        assert_eq!(res, U256::ZERO);

        let u128_max = U256::from(u128::MAX);
        let res = u128_max * U256::ONE;
        assert_eq!(res, u128_max);
    }

    #[test]
    fn test_div_rem() {
        let u64_max = U256::from(u64::MAX);
        let (expected_q, expected_r) = (u64::MAX / u64::MAX, u64::MAX % u64::MAX);
        assert_eq!(u64_max / u64_max, U256::from(expected_q));
        assert_eq!(u64_max % u64_max, U256::from(expected_r));

        let mut rng = rand::thread_rng();
        for _ in 0..5 {
            let a = rng.gen::<u128>();
            let b = rng.gen::<u128>();

            let res_q = U256::from(a) / U256::from(b);
            let res_r = U256::from(a) % U256::from(b);
            let expected_q = a / b;
            let expected_r = a % b;
            assert_eq!(res_q, U256::from(expected_q));
            assert_eq!(res_r, U256::from(expected_r));
        }

        let u128_max = U256::from(u128::MAX);
        let res_q = u128_max / U256::from(3284723894u64);
        let res_r = u128_max % U256::from(3284723894u64);
        let expected_q = U256::from(103595424730374145554705368314u128);
        let expected_r = U256::from(701916739u128);
        assert_eq!(res_q, expected_q);
        assert_eq!(res_r, expected_r);

        let u256_max = U256::MAX;
        let res_q = u256_max / U256::ONE;
        let res_r = u256_max % U256::ONE;
        assert_eq!(res_q, u256_max);
        assert_eq!(res_r, U256::ZERO);

        let a = U256::from((
            98789923123891239238309u128,
            166153499473114484112975882535043072u128,
        ));
        let b = U256::from((12937934723948230984120983u128, 2u128));
        let expected_q = U256::from(83076749736555662718753084335755618u128);
        let expected_r = U256::from((169753858020977627805335755091673007575u128, 1u128));
        assert_eq!(a / b, expected_q);
        assert_eq!(a % b, expected_r);
        assert_eq!(b / a, U256::ZERO);
        assert_eq!(b % a, b);

        let a = U256::from((283984787393485348590806231, 18446744073709551616));
        let b = U256::from((53249231281381239239045, 134217728));
        let expected_q = U256::from(137438953471u128);
        let expected_r = U256::from((340275048402601999976919705355157542492, 134217727));
        assert_eq!(a / b, expected_q);
        assert_eq!(a % b, expected_r);
        assert_eq!(b / a, U256::ZERO);
        assert_eq!(b % a, b);
    }

    #[test]
    fn test_add_wrap_around() {
        assert_eq!(U256::MAX + U256::from(1u32), U256::MIN);
    }

    #[test]
    fn test_sub_wrap_around() {
        assert_eq!(U256::MIN - U256::from(1u32), U256::MAX);
    }

    #[test]
    fn test_bitnot() {
        assert_eq!(!U256::MAX, U256::MIN);
        assert_eq!(!U256::MIN, U256::MAX);

        // To prove we are testing the correct thing
        assert_eq!(!u128::MAX, u128::MIN);
        assert_eq!(!u128::MIN, u128::MAX);
    }

    #[test]
    fn test_shl_limits() {
        assert_eq!(U256::ONE << 256, U256::ONE << (256 % U256::BITS));
        assert_eq!(U256::ONE << 257, U256::ONE << (257 % U256::BITS));

        // We aim to have same behaviour as rust native types
        assert_eq!(1u128.wrapping_shl(128), 1u128 << (128 % u128::BITS));
        assert_eq!(1u128.wrapping_shl(129), 1u128 << (129 % u128::BITS));
    }

    #[test]
    fn test_shr_limits() {
        assert_eq!(U256::MAX >> 256, U256::MAX >> (256 % U256::BITS));
        assert_eq!(U256::MAX >> 257, U256::MAX >> (257 % U256::BITS));

        // We aim to have same behaviour as rust native types
        assert_eq!(u128::MAX.wrapping_shr(128), u128::MAX >> (128 % u128::BITS));
        assert_eq!(u128::MAX.wrapping_shr(129), u128::MAX >> (129 % u128::BITS));
    }

    #[test]
    fn test_shr() {
        assert_eq!(U256::MAX >> 128, U256::from(u128::MAX));

        let input = (u64::MAX as u128) << 64;
        let a = U256::from(input);

        assert_eq!(a >> 1, U256::from(input >> 1));
    }

    #[test]
    fn test_shl() {
        let input = (u64::MAX as u128) << 64;
        let a = U256::from(input);

        // input a u128 with its 64 MSB set to one
        // so left shifting it by one will move one bit
        // to the next inner u64 block
        assert_eq!(a << 1, U256::from((input << 1, 1u128)));
    }

    #[test]
    fn test_le_byte_slice() {
        // Create a u128 where each bytes stores its index:
        // u128 as &[u8] = [0u8, 1 , 2, 3, .., 15]
        let low = u128::from_le_bytes(core::array::from_fn::<u8, 16, _>(|i| i as u8));
        let high = u128::from_le_bytes(core::array::from_fn::<u8, 16, _>(|i| 16 + i as u8));

        let mut le_bytes = vec![0u8; 32];
        le_bytes[..16].copy_from_slice(low.to_le_bytes().as_slice());
        le_bytes[16..].copy_from_slice(high.to_le_bytes().as_slice());

        let mut b = U256::from(1u128 << 64); // To make sure copy cleans self
        b.copy_from_le_byte_slice(le_bytes.as_slice());

        assert_eq!(b, U256::from((low, high)));

        let mut le_bytes_2 = vec![0u8; 32];
        b.copy_to_le_byte_slice(&mut le_bytes_2);

        assert_eq!(le_bytes_2, le_bytes);
    }

    #[test]
    fn test_be_byte_slice() {
        let low = u128::from_le_bytes(core::array::from_fn::<u8, 16, _>(|i| i as u8));
        let high = u128::from_le_bytes(core::array::from_fn::<u8, 16, _>(|i| 16 + i as u8));

        let mut be_bytes = vec![0u8; 32];
        be_bytes[16..].copy_from_slice(low.to_be_bytes().as_slice());
        be_bytes[..16].copy_from_slice(high.to_be_bytes().as_slice());

        let mut b = U256::from(1u128 << 64); // To make sure copy cleans self
        b.copy_from_be_byte_slice(be_bytes.as_slice());

        assert_eq!(b, U256::from((low, high)));

        let mut be_bytes_2 = vec![0u8; 32];
        b.copy_to_be_byte_slice(&mut be_bytes_2);

        assert_eq!(be_bytes_2, be_bytes);
    }
}
