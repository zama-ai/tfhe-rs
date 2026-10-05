use rand::{Rng, RngCore};

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(crate) struct Int {
    value: i128,
    bits: u32,
}

impl Int {
    pub(crate) fn bits(self) -> u32 {
        self.bits
    }

    pub(crate) fn value(self) -> i128 {
        self.value
    }

    pub(crate) fn new(value: i128, bits: u32) -> Self {
        assert!(
            (1..=128).contains(&bits),
            "Int width must be in 1..=128, got {bits}"
        );

        Self { bits: 128, value }.cast(bits)
    }

    pub(crate) fn random(bits: u32) -> impl Fn(&mut dyn RngCore) -> Self {
        move |rng| {
            let range = Self::value_range(bits);
            let raw = rng.gen_range(range);
            Self::new(raw, bits)
        }
    }

    pub(crate) fn one(bits: u32) -> Self {
        Self::new(1, bits)
    }

    pub(crate) fn zero(bits: u32) -> Self {
        Self::new(0, bits)
    }

    /// The smallest value representable on `bits` bits (`-2^(bits - 1)`).
    pub(crate) fn min(bits: u32) -> Self {
        Self::new(Self::min_value(bits), bits)
    }

    /// The largest value representable on `bits` bits (`2^(bits - 1) - 1`).
    pub(crate) fn max(bits: u32) -> Self {
        Self::new(Self::max_value(bits), bits)
    }

    /// `2^bits - 1` as a raw integer, used to keep the low `bits` bits of a value.
    fn mask(bits: u32) -> i128 {
        if bits >= 128 {
            -1
        } else {
            (1i128 << bits) - 1
        }
    }

    fn min_value(bits: u32) -> i128 {
        assert!(
            (1..=128).contains(&bits),
            "Int width must be in 1..=128, got {bits}"
        );
        -1 << (bits - 1)
    }

    fn max_value(bits: u32) -> i128 {
        assert!(
            (1..=128).contains(&bits),
            "Int width must be in 1..=128, got {bits}"
        );
        -1 ^ (-1 << (bits - 1))
    }

    /// The values representable on `bits` bits.
    pub(crate) fn value_range(bits: u32) -> std::ops::RangeInclusive<i128> {
        Self::min_value(bits)..=Self::max_value(bits)
    }

    pub(crate) fn assert_same_width(self, other: Self) {
        assert_eq!(
            self.bits, other.bits,
            "Int arithmetic on mismatched widths ({} vs {})",
            self.bits, other.bits
        );
    }

    pub(crate) fn wrapping_add(self, other: Self) -> Self {
        self.assert_same_width(other);
        Self::new(self.value.wrapping_add(other.value), self.bits)
    }

    pub(crate) fn wrapping_sub(self, other: Self) -> Self {
        self.assert_same_width(other);
        Self::new(self.value.wrapping_sub(other.value), self.bits)
    }

    pub(crate) fn overflowing_sub(self, other: Self) -> (Self, bool) {
        self.assert_same_width(other);
        self.overflowing_scalar_sub(other)
    }

    /// `self + scalar` where `scalar` may have any width: the result is on `self`'s width,
    /// the overflow is that of the exact sum, like the FHE `overflowing_scalar_add`.
    pub(crate) fn overflowing_scalar_add(self, scalar: Self) -> (Self, bool) {
        let result = self.wrapping_add(scalar.cast(self.bits));
        // An i128 overflow means the exact sum fits no width the model supports
        let overflowed = self
            .value
            .checked_add(scalar.value)
            .is_none_or(|exact| !Self::value_range(self.bits).contains(&exact));
        (result, overflowed)
    }

    /// `self - scalar` where `scalar` may have any width: the result is on `self`'s width,
    /// the overflow is that of the exact difference, like the FHE `overflowing_scalar_sub`.
    pub(crate) fn overflowing_scalar_sub(self, scalar: Self) -> (Self, bool) {
        let result = self.wrapping_sub(scalar.cast(self.bits));
        let overflowed = self
            .value
            .checked_sub(scalar.value)
            .is_none_or(|exact| !Self::value_range(self.bits).contains(&exact));
        (result, overflowed)
    }

    pub(crate) fn cast(self, target_bits: u32) -> Self {
        assert!(
            (1..=128).contains(&target_bits),
            "Int width must be in 1..=128, got {target_bits}"
        );

        if target_bits >= self.bits {
            // We do nothing because the `value` is already
            // in a representable range
            Self {
                bits: target_bits,
                value: self.value,
            }
        } else {
            // First truncate the bits, then sign extend to get a valid i128
            let mut value = self.value & Self::mask(target_bits);
            value <<= u128::BITS - target_bits;
            value >>= u128::BITS - target_bits;

            Self {
                bits: target_bits,
                value,
            }
        }
    }
}

/// The value alone, for reports.
impl std::fmt::Display for Int {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_reduces_the_value_modulo_the_width() {
        assert_eq!(Int::new(-128, 8).value(), -128);
        assert_eq!(Int::new(-256, 8).value(), 0);
        assert_eq!(Int::new(-257, 8).value(), (-257i128) as i8 as i128);
        assert_eq!(Int::new(-14, 128).value(), -14);
        assert_eq!(Int::new(u32::MAX as i128, 128).value(), u32::MAX as i128);
    }

    #[test]
    fn test_value_range() {
        assert_eq!(Int::value_range(8), -128..=127);
        assert_eq!(Int::value_range(9), -256..=255);
    }

    #[test]
    fn bounds_at_various_widths() {
        assert_eq!(Int::min(1).value(), -1);
        assert_eq!(Int::max(1).value(), 0);
        assert_eq!(Int::min(8).value(), -128);
        assert_eq!(Int::max(8).value(), 127);
        assert_eq!(Int::min(128).value(), i128::MIN);
        assert_eq!(Int::max(128).value(), i128::MAX);
        assert_eq!(Int::max(6).bits(), 6);
    }

    /// At 8 bits the model must agree with `i8`.
    #[test]
    fn arithmetic_matches_i8_at_8_bits() {
        for a in i8::MIN..=i8::MAX {
            for b in i8::MIN..=i8::MAX {
                let (ia, ib) = (Int::new(a.into(), 8), Int::new(b.into(), 8));
                assert_eq!(ia.wrapping_add(ib).value(), i128::from(a.wrapping_add(b)));
                assert_eq!(ia.wrapping_sub(ib).value(), i128::from(a.wrapping_sub(b)));
                let (diff, overflowed) = ia.overflowing_sub(ib);
                let (expected_diff, expected_overflow) = a.overflowing_sub(b);
                assert_eq!(diff.value(), i128::from(expected_diff), "{a} - {b}");
                assert_eq!(overflowed, expected_overflow, "{a} - {b}");
            }
        }
    }

    /// Widths without a Rust primitive wrap at their own bounds.
    #[test]
    fn arithmetic_wraps_at_odd_widths() {
        let one = Int::one(6);
        assert_eq!(Int::max(6).wrapping_add(one), Int::min(6));
        assert_eq!(Int::min(6).wrapping_sub(one), Int::max(6));
        assert_eq!(Int::min(6).overflowing_sub(one), (Int::max(6), true));
        assert_eq!(Int::new(-31, 6).overflowing_sub(one), (Int::min(6), false));
        // 128 bits: the i128 subtraction itself overflows
        assert_eq!(
            Int::min(128).overflowing_sub(Int::one(128)),
            (Int::max(128), true)
        );
    }

    #[test]
    fn scalar_ops_accept_any_scalar_width() {
        // 100 + 200 = 300 does not fit 8 bits, the result is 300 - 256
        assert_eq!(
            Int::new(100, 8).overflowing_scalar_add(Int::new(200, 16)),
            (Int::new(44, 8), true)
        );
        // -100 + 200 = 100 fits, although 200 reduced to 8 bits is -56
        assert_eq!(
            Int::new(-100, 8).overflowing_scalar_add(Int::new(200, 16)),
            (Int::new(100, 8), false)
        );
        // 100 - (-200) = 300 does not fit
        assert_eq!(
            Int::new(100, 8).overflowing_scalar_sub(Int::new(-200, 16)),
            (Int::new(44, 8), true)
        );
        // A scalar narrower than the radix is sign extended: -1i4 is -1
        assert_eq!(
            Int::new(-128, 8).overflowing_scalar_sub(Int::new(-1, 4)),
            (Int::new(-127, 8), false)
        );
    }

    #[test]
    #[should_panic(expected = "mismatched widths")]
    fn arithmetic_on_mismatched_widths_panics() {
        let _ = Int::one(4).wrapping_add(Int::one(8));
    }

    #[test]
    fn cast_truncates_and_sign_extends_when_narrowing_and_keeps_the_value_when_widening() {
        // 100 = 0b0110_0100: the low 4 bits are 4, the low 3 bits (100) read as -4
        let x = Int::new(100, 8);
        assert_eq!(x.cast(4).value(), 4);
        assert_eq!(x.cast(3).value(), -4);
        assert_eq!(x.cast(16), Int::new(100, 16));
        assert_eq!(Int::new(-100, 8).cast(16), Int::new(-100, 16));
        assert_eq!(x.cast(8), x);
    }
}
