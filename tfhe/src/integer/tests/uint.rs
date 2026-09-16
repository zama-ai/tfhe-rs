//! [`Uint`]: unsigned clear integer with a *runtime* bit-width, the clear model for
//! unsigned radix ciphertexts in tests.
use rand::{Rng, RngCore};

/// Unsigned clear integer with a *runtime* bit-width, for testing widths that
/// have no Rust primitive (6, 12, 40 bits, ...). Values are always kept
/// reduced modulo `2^bits`, so arithmetic on it models the encrypted type.
///
/// Its input generator is `Uint::random(bits)`, which lets a test loop over
/// widths at runtime.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(crate) struct Uint {
    bits: u32,
    value: u128,
}

impl Uint {
    pub(crate) fn bits(self) -> u32 {
        self.bits
    }

    pub(crate) fn value(self) -> u128 {
        self.value
    }

    pub(crate) fn new(bits: u32, value: u128) -> Self {
        assert!(
            (1..=128).contains(&bits),
            "Uint width must be in 1..=128, got {bits}"
        );
        Self {
            bits,
            value: value & Self::mask(bits),
        }
    }
    pub(crate) fn one(bits: u32) -> Self {
        Self::new(bits, 1)
    }

    pub(crate) fn zero(bits: u32) -> Self {
        Self::new(bits, 0)
    }
    /// The largest value representable on `bits` bits (`2^bits - 1`).
    pub(crate) fn max(bits: u32) -> Self {
        Self::new(bits, Self::mask(bits))
    }

    /// `2^bits - 1` as a raw integer, used to reduce a value modulo `2^bits`.
    fn mask(bits: u32) -> u128 {
        if bits >= 128 {
            u128::MAX
        } else {
            (1u128 << bits) - 1
        }
    }

    /// Input generator drawing uniformly in `0..2^bits`.
    pub(crate) fn random(bits: u32) -> impl Fn(&mut dyn RngCore) -> Self {
        move |rng| Self::new(bits, rng.gen())
    }
    pub(crate) fn assert_same_width(self, other: Self) {
        assert_eq!(
            self.bits, other.bits,
            "Uint arithmetic on mismatched widths ({} vs {})",
            self.bits, other.bits
        );
    }
    pub(crate) fn wrapping_add(self, other: Self) -> Self {
        self.assert_same_width(other);
        Self::new(self.bits, self.value.wrapping_add(other.value))
    }
    pub(crate) fn wrapping_sub(self, other: Self) -> Self {
        self.assert_same_width(other);
        Self::new(self.bits, self.value.wrapping_sub(other.value))
    }
    pub(crate) fn overflowing_add(self, other: Self) -> (Self, bool) {
        self.assert_same_width(other);
        let overflowed = self
            .value
            .checked_add(other.value)
            .is_none_or(|sum| sum > Self::max(self.bits).value);
        (self.wrapping_add(other), overflowed)
    }
    pub(crate) fn cast(self, bits: u32) -> Self {
        Self::new(bits, self.value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn new_reduces_the_value_modulo_the_width() {
        // 19 = 16 + 3: only the low 4 bits survive
        assert_eq!(Uint::new(4, 19).value(), 3);
        assert_eq!(Uint::new(4, 19).bits(), 4);
        assert_eq!(Uint::new(1, 3).value(), 1);
        assert_eq!(Uint::new(128, u128::MAX).value(), u128::MAX);
    }

    #[test]
    #[should_panic(expected = "Uint width must be in 1..=128")]
    fn new_rejects_a_zero_width() {
        let _ = Uint::new(0, 0);
    }

    #[test]
    #[should_panic(expected = "Uint width must be in 1..=128")]
    fn new_rejects_widths_above_128() {
        let _ = Uint::new(129, 0);
    }

    #[test]
    fn constants_at_various_widths() {
        for bits in [1, 2, 6, 8, 13, 64, 127, 128] {
            assert_eq!(Uint::zero(bits).value(), 0);
            assert_eq!(Uint::one(bits).value(), 1);
            let expected_max = if bits == 128 {
                u128::MAX
            } else {
                (1u128 << bits) - 1
            };
            assert_eq!(Uint::max(bits).value(), expected_max, "bits = {bits}");
            assert_eq!(Uint::max(bits).bits(), bits);
        }
    }

    /// At 8 bits the model must agree with `u8`.
    #[test]
    fn arithmetic_matches_u8_at_8_bits() {
        let values: [u8; 7] = [0, 1, 2, 127, 128, 254, 255];
        for &a in &values {
            for &b in &values {
                let (ua, ub) = (Uint::new(8, a.into()), Uint::new(8, b.into()));
                assert_eq!(ua.wrapping_add(ub).value(), u128::from(a.wrapping_add(b)));
                assert_eq!(ua.wrapping_sub(ub).value(), u128::from(a.wrapping_sub(b)));
                let (sum, overflowed) = ua.overflowing_add(ub);
                let (expected_sum, expected_overflow) = a.overflowing_add(b);
                assert_eq!(sum.value(), u128::from(expected_sum), "{a} + {b}");
                assert_eq!(overflowed, expected_overflow, "{a} + {b}");
            }
        }
    }

    /// Widths without a Rust primitive wrap at their own modulus.
    #[test]
    fn arithmetic_wraps_at_odd_widths() {
        let max = Uint::max(6);
        let one = Uint::one(6);
        assert_eq!(max.wrapping_add(one), Uint::zero(6));
        assert_eq!(Uint::zero(6).wrapping_sub(one), max);
        assert_eq!(max.overflowing_add(one), (Uint::zero(6), true));
        assert_eq!(
            Uint::new(6, 62).overflowing_add(one),
            (Uint::new(6, 63), false)
        );
        // 128 bits: the checked addition itself overflows u128
        assert_eq!(
            Uint::max(128).overflowing_add(Uint::one(128)),
            (Uint::zero(128), true)
        );
    }

    #[test]
    #[should_panic(expected = "mismatched widths")]
    fn arithmetic_on_mismatched_widths_panics() {
        let _ = Uint::one(4).wrapping_add(Uint::one(8));
    }

    #[test]
    fn cast_truncates_when_narrowing_and_zero_extends_when_widening() {
        // 171 = 10 * 16 + 11
        let x = Uint::new(8, 171);
        assert_eq!(x.cast(4), Uint::new(4, 11));
        assert_eq!(x.cast(16), Uint::new(16, 171));
        assert_eq!(x.cast(8), x);
    }

    #[test]
    fn random_draws_fit_the_width() {
        let mut rng = StdRng::seed_from_u64(42);
        let draw = Uint::random(5);
        for _ in 0..1000 {
            let x = draw(&mut rng);
            assert_eq!(x.bits(), 5);
            assert!(x.value() <= Uint::max(5).value());
        }
        // and are not stuck on a single value
        let distinct: std::collections::HashSet<u128> =
            (0..1000).map(|_| draw(&mut rng).value()).collect();
        assert!(distinct.len() > 1);
    }
}
