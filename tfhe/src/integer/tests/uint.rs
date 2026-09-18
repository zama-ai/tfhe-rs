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
    // TODO make private and add getters ?
    pub(crate) bits: u32,
    pub(crate) value: u128,
}

impl Uint {
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
    pub(crate) fn max_value(bits: u32) -> Self {
        Self::new(bits, Self::mask(bits))
    }
    pub(crate) fn one(bits: u32) -> Self {
        Self::new(bits, 1)
    }

    /// `1 << (bits - 1)`: the single most significant bit.
    pub(crate) fn zero(bits: u32) -> Self {
        Self::new(bits, 0)
    }
    pub(crate) fn mask(bits: u32) -> u128 {
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
    pub(crate) fn check_same_width(self, other: Self) {
        assert_eq!(
            self.bits, other.bits,
            "Uint arithmetic on mismatched widths ({} vs {})",
            self.bits, other.bits
        );
    }
    pub(crate) fn wrapping_add(self, other: Self) -> Self {
        self.check_same_width(other);
        Self::new(self.bits, self.value.wrapping_add(other.value))
    }
    pub(crate) fn wrapping_sub(self, other: Self) -> Self {
        self.check_same_width(other);
        Self::new(self.bits, self.value.wrapping_sub(other.value))
    }
    pub(crate) fn overflowing_add(self, other: Self) -> (Self, bool) {
        self.check_same_width(other);
        let overflowed = self
            .value
            .checked_add(other.value)
            .is_none_or(|sum| sum > Self::mask(self.bits));
        (self.wrapping_add(other), overflowed)
    }
    pub(crate) fn cast(self, bits: u32) -> Self {
        Self::new(bits, self.value)
    }
}
