use std::ops::{AddAssign, ShlAssign};

use crate::core_crypto::prelude::{CastFrom, Numeric, SignedNumeric};

const fn max_value_for_signed_u64_based_integer<const N: usize>() -> [u64; N] {
    let mut max = [u64::MAX; N];
    max[N - 1] = u64::MAX >> 1;
    max
}

const fn min_value_for_signed_u64_based_integer<const N: usize>() -> [u64; N] {
    let mut max = [0u64; N];
    max[N - 1] = 1u64 << 63;
    max
}

const fn one_for_signed_u64_based_integer<const N: usize>() -> [u64; N] {
    let mut max = [0u64; N];
    max[0] = 1u64;
    max
}

const fn two_for_signed_u64_based_integer<const N: usize>() -> [u64; N] {
    let mut max = [0u64; N];
    max[0] = 2u64;
    max
}

// Little endian order
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct StaticSignedBigInt<const N: usize>(pub(crate) [u64; N]);

// Cannot derive Default, [u64, N] only impl default for a few sizes
impl<const N: usize> Default for StaticSignedBigInt<N> {
    fn default() -> Self {
        Self([0u64; N])
    }
}

impl<const N: usize> From<[u64; N]> for StaticSignedBigInt<N> {
    fn from(array: [u64; N]) -> Self {
        Self(array)
    }
}

impl<const N: usize> StaticSignedBigInt<N> {
    pub const BITS: u32 = u64::BITS * N as u32;
    pub const MAX: Self = Self(max_value_for_signed_u64_based_integer());
    pub const MIN: Self = Self(min_value_for_signed_u64_based_integer());
    pub const ZERO: Self = Self([0; N]);
    pub const ONE: Self = Self(one_for_signed_u64_based_integer());
    pub const TWO: Self = Self(two_for_signed_u64_based_integer());

    pub fn data(&self) -> &[u64; N] {
        &self.0
    }

    pub fn wrapping_neg(self) -> Self {
        -self
    }

    pub fn wrapping_sub(self, other: Self) -> Self {
        self - other
    }

    pub fn is_power_of_two(self) -> bool {
        if self <= Self::ZERO {
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

    pub fn wrapping_abs(self) -> Self {
        super::algorithms::absolute_value(self)
    }
}

impl<const N: usize> std::cmp::Ord for StaticSignedBigInt<N> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        super::algorithms::compare_signed(&self.0, &other.0)
    }
}

impl<const N: usize> std::cmp::PartialOrd for StaticSignedBigInt<N> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<const N: usize> std::ops::Add<Self> for StaticSignedBigInt<N> {
    type Output = Self;

    fn add(mut self, rhs: Self) -> Self::Output {
        self += rhs;
        self
    }
}

impl<const N: usize> std::ops::AddAssign<Self> for StaticSignedBigInt<N> {
    fn add_assign(&mut self, rhs: Self) {
        super::algorithms::add_assign_words(self.0.as_mut_slice(), rhs.0.as_slice());
    }
}

impl<const N: usize> std::ops::Neg for StaticSignedBigInt<N> {
    type Output = Self;

    fn neg(mut self) -> Self::Output {
        super::algorithms::bitnot_assign(&mut self.0);
        self += Self::ONE;
        self
    }
}

impl<const N: usize> std::ops::Not for StaticSignedBigInt<N> {
    type Output = Self;

    fn not(mut self) -> Self::Output {
        super::algorithms::bitnot_assign(&mut self.0);
        self
    }
}

impl<const N: usize> std::ops::SubAssign<Self> for StaticSignedBigInt<N> {
    fn sub_assign(&mut self, rhs: Self) {
        self.add_assign(-rhs);
    }
}

impl<const N: usize> std::ops::Sub<Self> for StaticSignedBigInt<N> {
    type Output = Self;

    fn sub(mut self, rhs: Self) -> Self::Output {
        self -= rhs;
        self
    }
}

impl<const N: usize> std::ops::MulAssign<Self> for StaticSignedBigInt<N> {
    fn mul_assign(&mut self, rhs: Self) {
        if rhs.is_power_of_two() {
            self.shl_assign(rhs.ilog2());
            return;
        }
        super::algorithms::schoolbook_mul_assign(self.0.as_mut_slice(), rhs.0.as_slice());
    }
}

impl<const N: usize> std::ops::Mul<Self> for StaticSignedBigInt<N> {
    type Output = Self;

    fn mul(mut self, rhs: Self) -> Self::Output {
        self *= rhs;
        self
    }
}

impl<const N: usize> std::ops::DivAssign<Self> for StaticSignedBigInt<N> {
    fn div_assign(&mut self, rhs: Self) {
        *self = *self / rhs;
    }
}

impl<const N: usize> std::ops::Div<Self> for StaticSignedBigInt<N> {
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        let (q, _) = super::algorithms::slow_div_signed(self, rhs);
        q
    }
}

impl<const N: usize> std::ops::RemAssign<Self> for StaticSignedBigInt<N> {
    fn rem_assign(&mut self, rhs: Self) {
        *self = *self % rhs;
    }
}

impl<const N: usize> std::ops::Rem<Self> for StaticSignedBigInt<N> {
    type Output = Self;

    fn rem(self, rhs: Self) -> Self::Output {
        let (_, r) = super::algorithms::slow_div_signed(self, rhs);
        r
    }
}

impl<const N: usize> std::ops::ShrAssign<u32> for StaticSignedBigInt<N> {
    fn shr_assign(&mut self, shift: u32) {
        super::algorithms::shr_assign(
            self.0.as_mut_slice(),
            shift,
            super::algorithms::ShiftType::Arithmetic,
        );
    }
}

impl<const N: usize> std::ops::Shr<u32> for StaticSignedBigInt<N> {
    type Output = Self;

    fn shr(mut self, rhs: u32) -> Self::Output {
        self >>= rhs;
        self
    }
}

impl<const N: usize> std::ops::ShrAssign<usize> for StaticSignedBigInt<N> {
    fn shr_assign(&mut self, shift: usize) {
        super::algorithms::shr_assign(
            self.0.as_mut_slice(),
            shift as u32,
            super::algorithms::ShiftType::Arithmetic,
        );
    }
}

impl<const N: usize> std::ops::Shr<usize> for StaticSignedBigInt<N> {
    type Output = Self;

    fn shr(mut self, rhs: usize) -> Self::Output {
        self >>= rhs;
        self
    }
}

impl<const N: usize> std::ops::ShlAssign<u32> for StaticSignedBigInt<N> {
    fn shl_assign(&mut self, shift: u32) {
        super::algorithms::shl_assign(self.0.as_mut_slice(), shift);
    }
}

impl<const N: usize> std::ops::ShlAssign<usize> for StaticSignedBigInt<N> {
    fn shl_assign(&mut self, shift: usize) {
        super::algorithms::shl_assign(self.0.as_mut_slice(), shift as u32);
    }
}

impl<const N: usize> std::ops::Shl<u32> for StaticSignedBigInt<N> {
    type Output = Self;

    fn shl(mut self, rhs: u32) -> Self::Output {
        self <<= rhs;
        self
    }
}

impl<const N: usize> std::ops::Shl<usize> for StaticSignedBigInt<N> {
    type Output = Self;

    fn shl(mut self, rhs: usize) -> Self::Output {
        self <<= rhs;
        self
    }
}

impl<const N: usize> std::ops::BitAndAssign<Self> for StaticSignedBigInt<N> {
    fn bitand_assign(&mut self, rhs: Self) {
        super::algorithms::bitand_assign(self.0.as_mut_slice(), rhs.0.as_slice());
    }
}

impl<const N: usize> std::ops::BitAnd<Self> for StaticSignedBigInt<N> {
    type Output = Self;

    fn bitand(mut self, rhs: Self) -> Self::Output {
        self &= rhs;
        self
    }
}

impl<const N: usize> std::ops::BitOrAssign<Self> for StaticSignedBigInt<N> {
    fn bitor_assign(&mut self, rhs: Self) {
        super::algorithms::bitor_assign(self.0.as_mut_slice(), rhs.0.as_slice());
    }
}

impl<const N: usize> std::ops::BitOr<Self> for StaticSignedBigInt<N> {
    type Output = Self;

    fn bitor(mut self, rhs: Self) -> Self::Output {
        self |= rhs;
        self
    }
}

impl<const N: usize> std::ops::BitXorAssign<Self> for StaticSignedBigInt<N> {
    fn bitxor_assign(&mut self, rhs: Self) {
        super::algorithms::bitxor_assign(self.0.as_mut_slice(), rhs.0.as_slice());
    }
}

impl<const N: usize> std::ops::BitXor<Self> for StaticSignedBigInt<N> {
    type Output = Self;

    fn bitxor(mut self, rhs: Self) -> Self::Output {
        self ^= rhs;
        self
    }
}

// SAFETY
//
// StaticBigInt<N> is allowed to be all zeros
unsafe impl<const N: usize> bytemuck::Zeroable for StaticSignedBigInt<N> {}

// SAFETY
//
// u64 impl bytemuck::Pod,
// [T; N] impl bytemuck::Pod if T: bytemuck::Pod
//
// https://docs.rs/bytemuck/latest/bytemuck/trait.Pod.html#foreign-impls
//
// Thus StaticBigInt<N> can safely be considered Pod
unsafe impl<const N: usize> bytemuck::Pod for StaticSignedBigInt<N> {}

impl<const N: usize> Numeric for StaticSignedBigInt<N> {
    const BITS: usize = Self::BITS as usize;

    const ZERO: Self = Self::ZERO;

    const ONE: Self = Self::ONE;

    const TWO: Self = Self::TWO;

    const MAX: Self = Self::MAX;
}

impl<const N: usize> SignedNumeric for StaticSignedBigInt<N> {
    type NumericUnsignedType = super::static_unsigned::StaticUnsignedBigInt<N>;
}

impl<const N: usize> From<i32> for StaticSignedBigInt<N> {
    fn from(value: i32) -> Self {
        Self::from(value as i64)
    }
}

impl<const N: usize> From<i64> for StaticSignedBigInt<N> {
    fn from(value: i64) -> Self {
        // Casting from signed to unsigned is a no op
        if value < 0 {
            let mut converted = [u64::MAX; N];
            converted[0] = value as u64;
            Self(converted)
        } else {
            let mut converted = [u64::ZERO; N];
            converted[0] = value as u64;
            Self(converted)
        }
    }
}

impl<const N: usize> From<i128> for StaticSignedBigInt<N> {
    fn from(value: i128) -> Self {
        // Casting from signed to unsigned is a no op
        let mut converted = if value < 0 {
            [u64::MAX; N]
        } else {
            [u64::ZERO; N]
        };

        converted[0] = value as u64;
        if let Some(v) = converted.get_mut(1) {
            *v = ((value as u128) >> i64::BITS) as u64;
        }
        Self(converted)
    }
}

impl<const N: usize> From<(u64, u64, u64, u64)> for StaticSignedBigInt<N> {
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

impl<const N: usize> CastFrom<Self> for StaticSignedBigInt<N> {
    fn cast_from(input: Self) -> Self {
        input
    }
}

impl<const N: usize> CastFrom<u8> for StaticSignedBigInt<N> {
    fn cast_from(input: u8) -> Self {
        let mut converted = [u64::ZERO; N];
        converted[0] = input as u64;
        Self(converted)
    }
}

impl<const N: usize> CastFrom<u16> for StaticSignedBigInt<N> {
    fn cast_from(input: u16) -> Self {
        let mut converted = [u64::ZERO; N];
        converted[0] = input as u64;
        Self(converted)
    }
}

impl<const N: usize> CastFrom<u32> for StaticSignedBigInt<N> {
    fn cast_from(input: u32) -> Self {
        let mut converted = [u64::ZERO; N];
        converted[0] = input as u64;
        Self(converted)
    }
}

impl<const N: usize> CastFrom<u64> for StaticSignedBigInt<N> {
    fn cast_from(input: u64) -> Self {
        let mut converted = [u64::ZERO; N];
        converted[0] = input;
        Self(converted)
    }
}

impl<const N: usize> CastFrom<StaticSignedBigInt<N>> for u8 {
    fn cast_from(input: StaticSignedBigInt<N>) -> Self {
        input.0[0] as Self
    }
}

impl<const N: usize> CastFrom<StaticSignedBigInt<N>> for u16 {
    fn cast_from(input: StaticSignedBigInt<N>) -> Self {
        input.0[0] as Self
    }
}

impl<const N: usize> CastFrom<StaticSignedBigInt<N>> for u32 {
    fn cast_from(input: StaticSignedBigInt<N>) -> Self {
        input.0[0] as Self
    }
}

impl<const N: usize> CastFrom<StaticSignedBigInt<N>> for u64 {
    fn cast_from(input: StaticSignedBigInt<N>) -> Self {
        input.0[0]
    }
}

impl<const N: usize> CastFrom<super::static_unsigned::StaticUnsignedBigInt<N>>
    for StaticSignedBigInt<N>
{
    fn cast_from(input: super::static_unsigned::StaticUnsignedBigInt<N>) -> Self {
        Self(input.0)
    }
}
impl<const N: usize> CastFrom<StaticSignedBigInt<N>> for i128 {
    fn cast_from(input: StaticSignedBigInt<N>) -> Self {
        input.0[0] as Self | ((input.0.get(1).copied().unwrap_or(0) as Self) << 64)
    }
}
