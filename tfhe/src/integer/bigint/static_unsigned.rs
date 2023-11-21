use std::ops::ShlAssign;

use crate::core_crypto::prelude::{CastFrom, Numeric, UnsignedNumeric};

const fn one_for_unsigned_u64_based_integer<const N: usize>() -> [u64; N] {
    let mut max = [0u64; N];
    max[0] = 1u64;
    max
}

const fn two_for_unsigned_u64_based_integer<const N: usize>() -> [u64; N] {
    let mut max = [0u64; N];
    max[0] = 2u64;
    max
}

// Little endian order
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct StaticUnsignedBigInt<const N: usize>(pub(crate) [u64; N]);

// Cannot derive Default, [u64, N] only impl default for a few sizes
impl<const N: usize> Default for StaticUnsignedBigInt<N> {
    fn default() -> Self {
        Self([0u64; N])
    }
}

impl<const N: usize> From<[u64; N]> for StaticUnsignedBigInt<N> {
    fn from(array: [u64; N]) -> Self {
        Self(array)
    }
}

impl<const N: usize> StaticUnsignedBigInt<N> {
    pub const BITS: u32 = u64::BITS * N as u32;
    pub const MAX: Self = Self([u64::MAX; N]);
    pub const MIN: Self = Self([0; N]);
    pub const ZERO: Self = Self([0; N]);
    pub const ONE: Self = Self(one_for_unsigned_u64_based_integer());
    pub const TWO: Self = Self(two_for_unsigned_u64_based_integer());

    /// Replaces the current value by interpreting the bytes in big endian order
    pub fn copy_from_be_byte_slice(&mut self, bytes: &[u8]) {
        super::algorithms::copy_from_be_byte_slice(self.0.as_mut_slice(), bytes);
    }

    /// Replaces the current value by interpreting the bytes in little endian order
    pub fn copy_from_le_byte_slice(&mut self, bytes: &[u8]) {
        super::algorithms::copy_from_le_byte_slice(self.0.as_mut_slice(), bytes);
    }

    pub fn copy_to_le_byte_slice(&self, bytes: &mut [u8]) {
        super::algorithms::copy_to_le_byte_slice(self.0.as_slice(), bytes);
    }

    pub fn copy_to_be_byte_slice(&self, bytes: &mut [u8]) {
        super::algorithms::copy_to_be_byte_slice(self.0.as_slice(), bytes);
    }

    pub fn is_power_of_two(self) -> bool {
        if self == Self::ZERO {
            return false;
        }
        (self & (self - Self::ONE)) == Self::ZERO
    }

    pub fn leading_zeros(self) -> u32 {
        super::algorithms::leading_zeros(self.0.as_slice())
    }

    pub fn ilog2(self) -> u32 {
        // Rust has the same assert
        assert!(
            self > Self::ZERO,
            "argument of integer logarithm must be positive"
        );
        (self.0.len() as u32 * u64::BITS) - self.leading_zeros() - 1
    }

    pub fn ceil_ilog2(self) -> u32 {
        self.ilog2() + u32::from(!self.is_power_of_two())
    }
}

#[cfg(test)]
impl<const N: usize> rand::distributions::Distribution<StaticUnsignedBigInt<N>>
    for rand::distributions::Standard
{
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> StaticUnsignedBigInt<N> {
        let mut s = StaticUnsignedBigInt::<N>::ZERO;
        rng.fill(s.0.as_mut_slice());
        s
    }
}

impl<const N: usize> std::cmp::Ord for StaticUnsignedBigInt<N> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        super::algorithms::compare_unsigned(&self.0, &other.0)
    }
}

impl<const N: usize> std::cmp::PartialOrd for StaticUnsignedBigInt<N> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<const N: usize> std::ops::AddAssign<Self> for StaticUnsignedBigInt<N> {
    fn add_assign(&mut self, rhs: Self) {
        super::algorithms::add_assign_words(self.0.as_mut_slice(), rhs.0.as_slice());
    }
}

impl<const N: usize> std::ops::Add<Self> for StaticUnsignedBigInt<N> {
    type Output = Self;

    fn add(mut self, rhs: Self) -> Self::Output {
        self += rhs;
        self
    }
}

impl<const N: usize> std::ops::SubAssign<Self> for StaticUnsignedBigInt<N> {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl<const N: usize> std::ops::Sub<Self> for StaticUnsignedBigInt<N> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        let negated = !rhs + Self::from(1u64);
        self + negated
    }
}

impl<const N: usize> std::ops::MulAssign<Self> for StaticUnsignedBigInt<N> {
    fn mul_assign(&mut self, rhs: Self) {
        if rhs.is_power_of_two() {
            self.shl_assign(rhs.ilog2());
            return;
        }
        super::algorithms::schoolbook_mul_assign(self.0.as_mut_slice(), rhs.0.as_slice());
    }
}

impl<const N: usize> std::ops::Mul<Self> for StaticUnsignedBigInt<N> {
    type Output = Self;

    fn mul(mut self, rhs: Self) -> Self::Output {
        self *= rhs;
        self
    }
}

impl<const N: usize> std::ops::DivAssign<Self> for StaticUnsignedBigInt<N> {
    fn div_assign(&mut self, rhs: Self) {
        *self = *self / rhs;
    }
}

impl<const N: usize> std::ops::Div<Self> for StaticUnsignedBigInt<N> {
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        let (q, _) = super::algorithms::slow_div_unsigned(self, rhs);
        q
    }
}

impl<const N: usize> std::ops::RemAssign<Self> for StaticUnsignedBigInt<N> {
    fn rem_assign(&mut self, rhs: Self) {
        *self = *self % rhs;
    }
}

impl<const N: usize> std::ops::Rem<Self> for StaticUnsignedBigInt<N> {
    type Output = Self;

    fn rem(self, rhs: Self) -> Self::Output {
        let (_, r) = super::algorithms::slow_div_unsigned(self, rhs);
        r
    }
}

impl<const N: usize> std::ops::ShrAssign<u32> for StaticUnsignedBigInt<N> {
    fn shr_assign(&mut self, shift: u32) {
        super::algorithms::shr_assign(
            self.0.as_mut_slice(),
            shift,
            super::algorithms::ShiftType::Logical,
        );
    }
}

impl<const N: usize> std::ops::Shl<u32> for StaticUnsignedBigInt<N> {
    type Output = Self;

    fn shl(mut self, rhs: u32) -> Self::Output {
        self <<= rhs;
        self
    }
}
impl<const N: usize> std::ops::Shr<u32> for StaticUnsignedBigInt<N> {
    type Output = Self;

    fn shr(mut self, rhs: u32) -> Self::Output {
        self >>= rhs;
        self
    }
}

impl<const N: usize> std::ops::ShlAssign<u32> for StaticUnsignedBigInt<N> {
    fn shl_assign(&mut self, shift: u32) {
        super::algorithms::shl_assign(self.0.as_mut_slice(), shift);
    }
}

impl<const N: usize> std::ops::Shl<usize> for StaticUnsignedBigInt<N> {
    type Output = Self;

    fn shl(mut self, rhs: usize) -> Self::Output {
        self <<= rhs;
        self
    }
}

impl<const N: usize> std::ops::ShrAssign<usize> for StaticUnsignedBigInt<N> {
    fn shr_assign(&mut self, shift: usize) {
        super::algorithms::shr_assign(
            self.0.as_mut_slice(),
            shift as u32,
            super::algorithms::ShiftType::Logical,
        );
    }
}

impl<const N: usize> std::ops::Shr<usize> for StaticUnsignedBigInt<N> {
    type Output = Self;

    fn shr(mut self, rhs: usize) -> Self::Output {
        self >>= rhs;
        self
    }
}

impl<const N: usize> std::ops::ShlAssign<usize> for StaticUnsignedBigInt<N> {
    fn shl_assign(&mut self, shift: usize) {
        super::algorithms::shl_assign(self.0.as_mut_slice(), shift as u32);
    }
}

impl<const N: usize> std::ops::Not for StaticUnsignedBigInt<N> {
    type Output = Self;

    fn not(mut self) -> Self::Output {
        super::algorithms::bitnot_assign(self.0.as_mut_slice());
        self
    }
}

impl<const N: usize> std::ops::BitAndAssign<Self> for StaticUnsignedBigInt<N> {
    fn bitand_assign(&mut self, rhs: Self) {
        super::algorithms::bitand_assign(self.0.as_mut_slice(), rhs.0.as_slice());
    }
}

impl<const N: usize> std::ops::BitAnd<Self> for StaticUnsignedBigInt<N> {
    type Output = Self;

    fn bitand(mut self, rhs: Self) -> Self::Output {
        self &= rhs;
        self
    }
}

impl<const N: usize> std::ops::BitOrAssign<Self> for StaticUnsignedBigInt<N> {
    fn bitor_assign(&mut self, rhs: Self) {
        super::algorithms::bitor_assign(self.0.as_mut_slice(), rhs.0.as_slice());
    }
}

impl<const N: usize> std::ops::BitOr<Self> for StaticUnsignedBigInt<N> {
    type Output = Self;

    fn bitor(mut self, rhs: Self) -> Self::Output {
        self |= rhs;
        self
    }
}

impl<const N: usize> std::ops::BitXorAssign<Self> for StaticUnsignedBigInt<N> {
    fn bitxor_assign(&mut self, rhs: Self) {
        super::algorithms::bitxor_assign(self.0.as_mut_slice(), rhs.0.as_slice());
    }
}

impl<const N: usize> std::ops::BitXor<Self> for StaticUnsignedBigInt<N> {
    type Output = Self;

    fn bitxor(mut self, rhs: Self) -> Self::Output {
        self ^= rhs;
        self
    }
}

impl<const N: usize> From<(u64, u64, u64, u64)> for StaticUnsignedBigInt<N> {
    fn from(value: (u64, u64, u64, u64)) -> Self {
        let mut converted = [u64::ZERO; N];
        if let Some(e) = converted.get_mut(0) {
            *e = value.0;
        }
        if let Some(e) = converted.get_mut(1) {
            *e = value.1;
        }
        if let Some(e) = converted.get_mut(2) {
            *e = value.2;
        }
        if let Some(e) = converted.get_mut(3) {
            *e = value.3;
        }
        Self(converted)
    }
}

impl<const N: usize> From<u8> for StaticUnsignedBigInt<N> {
    fn from(value: u8) -> Self {
        Self::from(value as u128)
    }
}

impl<const N: usize> From<u16> for StaticUnsignedBigInt<N> {
    fn from(value: u16) -> Self {
        Self::from(value as u128)
    }
}

impl<const N: usize> From<u32> for StaticUnsignedBigInt<N> {
    fn from(value: u32) -> Self {
        Self::from(value as u128)
    }
}

impl<const N: usize> From<u64> for StaticUnsignedBigInt<N> {
    fn from(value: u64) -> Self {
        Self::from(value as u128)
    }
}

impl<const N: usize> From<u128> for StaticUnsignedBigInt<N> {
    fn from(value: u128) -> Self {
        let mut converted = [u64::ZERO; N];
        converted[0] = (value & u128::from(u64::MAX)) as u64;
        if let Some(e) = converted.get_mut(1) {
            *e = (value >> 64) as u64;
        }
        Self(converted)
    }
}

impl<const N: usize> CastFrom<StaticUnsignedBigInt<N>> for u64 {
    fn cast_from(input: StaticUnsignedBigInt<N>) -> Self {
        input.0[0]
    }
}

impl<const N: usize> CastFrom<StaticUnsignedBigInt<N>> for u8 {
    fn cast_from(input: StaticUnsignedBigInt<N>) -> Self {
        input.0[0] as Self
    }
}

impl<const N: usize> CastFrom<u128> for StaticUnsignedBigInt<N> {
    fn cast_from(input: u128) -> Self {
        Self::from(input)
    }
}

impl<const N: usize> CastFrom<StaticUnsignedBigInt<N>> for u128 {
    fn cast_from(input: StaticUnsignedBigInt<N>) -> Self {
        input.0[0] as Self | input.0.get(1).copied().unwrap_or(0) as Self
    }
}

impl<const N: usize> CastFrom<u8> for StaticUnsignedBigInt<N> {
    fn cast_from(input: u8) -> Self {
        Self::from(input as u64)
    }
}

impl<const N: usize> CastFrom<u32> for StaticUnsignedBigInt<N> {
    fn cast_from(input: u32) -> Self {
        Self::from(input)
    }
}

impl<const N: usize> CastFrom<u64> for StaticUnsignedBigInt<N> {
    fn cast_from(input: u64) -> Self {
        Self::from(input)
    }
}

impl<const N: usize> From<bool> for StaticUnsignedBigInt<N> {
    fn from(input: bool) -> Self {
        Self::from(if input { 1u64 } else { 0u64 })
    }
}

impl<const N: usize> CastFrom<super::static_signed::StaticSignedBigInt<N>>
    for StaticUnsignedBigInt<N>
{
    fn cast_from(input: super::static_signed::StaticSignedBigInt<N>) -> Self {
        Self(input.0)
    }
}

// SAFETY
//
// StaticUnsignedBigInt<N> is allowed to be all zeros
unsafe impl<const N: usize> bytemuck::Zeroable for StaticUnsignedBigInt<N> {}

// SAFETY
//
// u64 impl bytemuck::Pod,
// [T; N] impl bytemuck::Pod if T: bytemuck::Pod
//
// https://docs.rs/bytemuck/latest/bytemuck/trait.Pod.html#foreign-impls
//
// Thus StaticUnsignedBigInt<N> can safely be considered Pod
unsafe impl<const N: usize> bytemuck::Pod for StaticUnsignedBigInt<N> {}

impl<const N: usize> Numeric for StaticUnsignedBigInt<N> {
    const BITS: usize = Self::BITS as usize;

    const ZERO: Self = Self::ZERO;

    const ONE: Self = Self::ONE;

    const TWO: Self = Self::TWO;

    const MAX: Self = Self::MAX;
}

impl<const N: usize> UnsignedNumeric for StaticUnsignedBigInt<N> {
    type NumericSignedType = super::static_signed::StaticSignedBigInt<N>;
}
