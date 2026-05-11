//! Fixed-size cyclic shift register used by Trivium/Kreyvium.

use core::ops::{Index, IndexMut};

/// Fixed-capacity cyclic shift register.
///
/// Indexed by age: `reg[0]` is the most recently pushed value, `reg[N-1]`
/// the oldest still present.
#[derive(Clone)]
pub(crate) struct ShiftRegister<const N: usize, T> {
    arr: Box<[T; N]>,
    cursor: usize,
}

impl<const N: usize, T> ShiftRegister<N, T> {
    /// `arr[0]` is treated as the oldest initial value, `arr[N-1]` as the newest.
    pub(crate) fn new(arr: Box<[T; N]>) -> Self {
        Self { arr, cursor: 0 }
    }

    /// Push a new element, overwriting the oldest. After push, the new value is at index 0.
    pub(crate) fn push(&mut self, val: T) {
        self.arr[self.cursor] = val;
        self.shift();
    }

    /// Rotate the buffer by one: what was oldest becomes newest. No data is copied
    /// and no value is dropped.
    pub(crate) fn shift(&mut self) {
        self.n_shifts(1);
    }

    /// Rotate by `n` positions in O(1) (cursor-only). Equivalent to calling
    /// shift `n` times.
    pub(crate) fn n_shifts(&mut self, n: usize) {
        self.cursor += n;
        self.cursor %= N;
    }

    #[cfg(test)]
    pub(crate) fn inner(&self) -> &[T; N] {
        &self.arr
    }
}

/// Indexed by age: `reg[0]` is the newest element, `reg[N-1]` the oldest.
/// Panics if `i >= N`.
impl<const N: usize, T> Index<usize> for ShiftRegister<N, T> {
    type Output = T;

    fn index(&self, i: usize) -> &T {
        assert!(i < N, "Index {i} too high for size {N}");
        &self.arr[(N + self.cursor - i - 1) % N]
    }
}

/// Indexed by age: `reg[0]` is the newest element, `reg[N-1]` the oldest.
/// Panics if `i >= N`.
impl<const N: usize, T> IndexMut<usize> for ShiftRegister<N, T> {
    fn index_mut(&mut self, i: usize) -> &mut T {
        assert!(i < N, "Index {i} too high for size {N}");
        &mut self.arr[(N + self.cursor - i - 1) % N]
    }
}

#[cfg(test)]
mod tests {
    use super::ShiftRegister;

    #[test]
    fn test_shift_register() {
        let a = [1, 2, 3, 4, 5, 6];

        let mut shift_register = ShiftRegister::new(Box::new(a));
        for i in 7..11 {
            shift_register.push(i);
        }
        assert_eq!(*shift_register.inner(), [7, 8, 9, 10, 5, 6]);

        for i in 11..15 {
            shift_register.push(i);
        }
        assert_eq!(*shift_register.inner(), [13, 14, 9, 10, 11, 12]);

        assert_eq!(shift_register[0], 14);
        assert_eq!(shift_register[1], 13);
        assert_eq!(shift_register[2], 12);
        assert_eq!(shift_register[3], 11);
        assert_eq!(shift_register[4], 10);
        assert_eq!(shift_register[5], 9);
    }

    #[test]
    fn test_shift_register_indexmut() {
        let a = [1, 2, 3, 4, 5, 6];

        let mut shift_register = ShiftRegister::new(Box::new(a));
        for i in 7..11 {
            shift_register.push(i);
        }
        assert_eq!(*shift_register.inner(), [7, 8, 9, 10, 5, 6]);

        for i in 11..15 {
            shift_register.push(i);
        }
        assert_eq!(*shift_register.inner(), [13, 14, 9, 10, 11, 12]);

        shift_register[1] = 100;

        assert_eq!(shift_register[0], 14);
        assert_eq!(shift_register[1], 100);
        assert_eq!(shift_register[2], 12);
        assert_eq!(shift_register[3], 11);
        assert_eq!(shift_register[4], 10);
        assert_eq!(shift_register[5], 9);
    }

    #[test]
    #[should_panic(expected = "Index 6 too high for size 6")]
    fn test_shift_register_index_fail() {
        let a = [1, 2, 3, 4, 5, 6];

        let shift_register = ShiftRegister::new(Box::new(a));
        let _ = shift_register[6];
    }
}
