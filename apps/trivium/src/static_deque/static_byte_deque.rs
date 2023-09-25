//! This module implements the StaticByteDeque struct: a deque of bytes. The idea
//! is that this is a wrapper around StaticDeque, but StaticByteDeque has an additional
//! functionality: it can construct the "intermediate" bytes, made of parts of other bytes.
//! This is pretending to store bits, and allows accessing bits in chunks of 8 consecutive.

use crate::static_deque::StaticDeque;

use tfhe::FheUint8;

/// Internal trait specifying which operations are needed by StaticByteDeque
pub trait StaticByteDequeInput<OpOutput>:
    Clone
    + std::ops::Shr<u8, Output = OpOutput>
    + std::ops::Shl<u8, Output = OpOutput>
    + std::ops::BitOr<Output = OpOutput>
{
}
impl StaticByteDequeInput<u8> for u8 {}
impl StaticByteDequeInput<u8> for &u8 {}
impl StaticByteDequeInput<FheUint8> for FheUint8 {}
impl StaticByteDequeInput<FheUint8> for &FheUint8 {}

/// Here T must represent a type covering a byte, like u8 or FheUint8.
#[derive(Clone)]
pub struct StaticByteDeque<const N: usize, T> {
    deque: StaticDeque<N, T>,
}

impl<const N: usize, T> StaticByteDeque<N, T>
where
    T: StaticByteDequeInput<T>,
    for<'a> &'a T: StaticByteDequeInput<T>,
{
    /// Constructor always uses a fully initialized array, the first element of
    /// which is oldest, the last is newest
    pub fn new(_arr: [T; N]) -> Self {
        Self {
            deque: StaticDeque::<N, T>::new(_arr),
        }
    }

    /// Elements are pushed via a byte element (covering 8 underlying bits)
    pub fn push(&mut self, val: T) {
        self.deque.push(val)
    }

    /// computes n shift in a row
    pub fn n_shifts(&mut self, n: usize) {
        self.deque.n_shifts(n);
    }

    /// Getter for the internal memory
    #[allow(dead_code)]
    fn get_arr(&self) -> &[T; N] {
        self.deque.get_arr()
    }

    /// This returns a byte full of zeros, except maybe a one
    /// at the specified location, if it is present in the deque
    #[allow(dead_code)]
    fn bit(&self, i: usize) -> T
    where
        for<'a> &'a T: std::ops::BitAnd<u8, Output = T>,
    {
        let byte: &T = &self.deque[i / 8];
        let bit_selector: u8 = 1u8 << (i % 8);
        byte & bit_selector
    }

    /// This function reconstructs an intermediate byte if necessary
    pub fn byte(&self, i: usize) -> T {
        let byte: &T = &self.deque[i / 8];
        let bit_idx: u8 = (i % 8) as u8;

        if bit_idx == 0 {
            return byte.clone();
        }

        let byte_next: &T = &self.deque[i / 8 + 1];
        (byte << bit_idx) | (byte_next >> (8 - bit_idx))
    }
}

#[cfg(test)]
mod tests {
    use crate::static_deque::StaticByteDeque;

    #[test]
    fn byte_deque_test() {
        let mut deque = StaticByteDeque::<3, u8>::new([2, 64, 128]);
        deque.push(4);

        // Youngest: 4
        assert!(deque.bit(0) == 0);
        assert!(deque.bit(1) == 0);
        assert!(deque.bit(2) > 0);
        assert!(deque.bit(3) == 0);
        assert!(deque.bit(4) == 0);
        assert!(deque.bit(5) == 0);
        assert!(deque.bit(6) == 0);
        assert!(deque.bit(7) == 0);

        // second youngest: 128
        assert!(deque.bit(8) == 0);
        assert!(deque.bit(8 + 1) == 0);
        assert!(deque.bit(8 + 2) == 0);
        assert!(deque.bit(8 + 3) == 0);
        assert!(deque.bit(8 + 4) == 0);
        assert!(deque.bit(8 + 5) == 0);
        assert!(deque.bit(8 + 6) == 0);
        assert!(deque.bit(8 + 7) > 0);

        // oldest: 64
        assert!(deque.bit(16) == 0);
        assert!(deque.bit(16 + 1) == 0);
        assert!(deque.bit(16 + 2) == 0);
        assert!(deque.bit(16 + 3) == 0);
        assert!(deque.bit(16 + 4) == 0);
        assert!(deque.bit(16 + 5) == 0);
        assert!(deque.bit(16 + 6) > 0);
        assert!(deque.bit(16 + 7) == 0);

        assert_eq!(deque.byte(0), 4u8);
        assert_eq!(deque.byte(1), 9u8);
        assert_eq!(deque.byte(2), 18u8);
        assert_eq!(deque.byte(3), 36u8);
        assert_eq!(deque.byte(4), 72u8);
        assert_eq!(deque.byte(5), 144u8);
        assert_eq!(deque.byte(6), 32u8);
        assert_eq!(deque.byte(7), 64u8);
        assert_eq!(deque.byte(8), 128u8);
        assert_eq!(deque.byte(9), 0u8);
        assert_eq!(deque.byte(10), 1u8);
        assert_eq!(deque.byte(11), 2u8);
        assert_eq!(deque.byte(12), 4u8);
        assert_eq!(deque.byte(13), 8u8);
        assert_eq!(deque.byte(14), 16u8);
        assert_eq!(deque.byte(15), 32u8);
        assert_eq!(deque.byte(16), 64u8);
    }
}
