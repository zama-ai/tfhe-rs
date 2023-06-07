use crate::core_crypto::prelude::{CastFrom, Numeric};

#[inline(always)]
pub const fn adc(l: u64, r: u64, c: bool) -> (u64, bool) {
    let (lr, o0) = l.overflowing_add(r);
    let (lrc, o1) = lr.overflowing_add(c as u64);
    (lrc, o0 | o1)
}

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
        assert_eq!(bytes.len(), 32);
        // We internally have
        //
        // [ index 0    |  index 1   |  index 2 | index 3     ]
        // [WB0,.., WB7 | WB0,..,WB7 | WB0,..,WB7 | WB0,..,WB7]
        // [B0,.., B7   | B8 ,..,B15 | B16,..,B23 | B24,..,B31]
        //   Least                                     Most
        //
        // Where each [WB0,...WB7] are in target_endian order,
        // so, if target_endian == big it means, the full range
        // B0..B31 is not a true little endian order,
        // thus requiring an additional step

        let inner_slice = self.0.as_mut_slice();
        inner_slice.fill(0);
        unsafe {
            // SAFETY SLICES are contiguous
            // (4 * 64) bits / 8 bits = 32
            let inner_byte_slice =
                std::slice::from_raw_parts_mut(inner_slice.as_mut_ptr() as *mut u8, 32);
            let shortest_len = inner_byte_slice.len().min(bytes.len());
            inner_byte_slice[..shortest_len].copy_from_slice(&bytes[..shortest_len]);
            inner_byte_slice.reverse();
        }
        #[cfg(target_endian = "big")]
        for word in self.0.iter_mut() {
            *word = word.swap_bytes();
        }
    }

    /// Replaces the current value by interpreting the bytes in little endian order
    pub fn copy_from_le_byte_slice(&mut self, bytes: &[u8]) {
        assert_eq!(bytes.len(), 32);
        // Same principle as in copy_from_be_byte_slice applies here

        let inner_slice = self.0.as_mut_slice();
        inner_slice.fill(0);
        unsafe {
            // SAFETY SLICES are contiguous
            // (4 * 64) bits / 8 bits = 32
            let inner_byte_slice =
                std::slice::from_raw_parts_mut(inner_slice.as_mut_ptr() as *mut u8, 32);
            let shortest_len = inner_byte_slice.len().min(bytes.len());
            inner_byte_slice[..shortest_len].copy_from_slice(&bytes[..shortest_len]);
        }
        #[cfg(target_endian = "big")]
        for word in self.0.iter_mut() {
            *word = word.swap_bytes();
        }
    }

    pub fn copy_to_le_byte_slice(&self, bytes: &mut [u8]) {
        assert_eq!(bytes.len(), 32);
        let inner_slice = self.0.as_slice();
        unsafe {
            // SAFETY SLICES are contiguous
            // (4 * 64) bits / 8 bits = 32
            let inner_byte_slice =
                std::slice::from_raw_parts(inner_slice.as_ptr() as *const u8, 32);
            let shortest_len = inner_byte_slice.len().min(bytes.len());
            bytes[..shortest_len].copy_from_slice(&inner_byte_slice[..shortest_len]);
        }
        #[cfg(target_endian = "big")]
        for sub_slice in bytes.chunks_mut(8) {
            sub_slice.reverse();
        }
    }

    pub fn copy_to_be_byte_slice(&self, bytes: &mut [u8]) {
        assert_eq!(bytes.len(), 32);
        let inner_slice = self.0.as_slice();

        unsafe {
            // SAFETY SLICES are contiguous
            // (4 * 64) bits / 8 bits = 32
            let inner_byte_slice =
                std::slice::from_raw_parts(inner_slice.as_ptr() as *const u8, 32);
            let shortest_len = inner_byte_slice.len().min(bytes.len());
            bytes[..shortest_len].copy_from_slice(&inner_byte_slice[..shortest_len]);
        }
        #[cfg(target_endian = "big")]
        for sub_slice in bytes.chunks_mut(8) {
            sub_slice.reverse();
        }
    }

    pub fn to_low_high_u128(self) -> (u128, u128) {
        let low = self.0[0] as u128 | ((self.0[1] as u128) << 64);
        let high = self.0[2] as u128 | ((self.0[3] as u128) << 64);
        (low, high)
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

impl std::ops::Add<Self> for U256 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let (x0, carry) = adc(self.0[0], rhs.0[0], false);
        let (x1, carry) = adc(self.0[1], rhs.0[1], carry);
        let (x2, carry) = adc(self.0[2], rhs.0[2], carry);
        let (x3, _) = adc(self.0[3], rhs.0[3], carry);

        Self([x0, x1, x2, x3])
    }
}

impl std::ops::Sub<Self> for U256 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        let negated = !rhs + Self::from(1u64);
        self + negated
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

impl std::ops::Shr<u32> for U256 {
    type Output = Self;

    fn shr(mut self, rhs: u32) -> Self::Output {
        self >>= rhs;
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

impl std::ops::Shl<u32> for U256 {
    type Output = Self;

    fn shl(mut self, rhs: u32) -> Self::Output {
        self <<= rhs;
        self
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

impl std::ops::BitAndAssign<Self> for U256 {
    fn bitand_assign(&mut self, rhs: Self) {
        for (self_word, rhs_word) in self.0.iter_mut().zip(rhs.0) {
            *self_word &= rhs_word;
        }
    }
}

impl std::ops::BitAnd<Self> for U256 {
    type Output = Self;

    fn bitand(mut self, rhs: Self) -> Self::Output {
        self &= rhs;
        self
    }
}

impl std::ops::AddAssign<Self> for U256 {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl std::ops::BitOr<Self> for U256 {
    type Output = Self;

    fn bitor(mut self, rhs: Self) -> Self::Output {
        self |= rhs;
        self
    }
}

impl std::ops::BitOrAssign<Self> for U256 {
    fn bitor_assign(&mut self, rhs: Self) {
        for (self_word, rhs_word) in self.0.iter_mut().zip(rhs.0) {
            *self_word |= rhs_word;
        }
    }
}

impl std::cmp::PartialOrd for U256 {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl From<(u64, u64, u64, u64)> for U256 {
    fn from(value: (u64, u64, u64, u64)) -> Self {
        Self([value.0, value.1, value.2, value.3])
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

#[cfg(test)]
mod tests {
    use super::*;

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
        let low = u64::MAX as u128;
        let high = (u64::MAX as u128) << 64;

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
        let low = u64::MAX as u128;
        let high = (u64::MAX as u128) << 64;

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
