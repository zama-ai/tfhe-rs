//! This module implements the StaticDeque struct: a deque utility whose size
//! is known at compile time. Construction, push, and indexing are publicly
//! available.

use core::ops::{Index, IndexMut};

/// StaticDeque: a struct implementing a deque whose size is known at compile time.
/// It has 2 members: the static array containing the data (never empty), and a cursor
/// equal to the index of the oldest element (and the next one to be overwritten).
#[derive(Clone)]
pub struct StaticDeque<const N: usize, T> {
    arr: [T; N],
    cursor: usize,
}

impl<const N: usize, T> StaticDeque<N, T> {
    /// Constructor always uses a fully initialized array, the first element of
    /// which is oldest, the last is newest
    pub fn new(_arr: [T; N]) -> Self {
        Self {
            arr: _arr,
            cursor: 0,
        }
    }

    /// Push a new element to the deque, overwriting the oldest at the same time.
    pub fn push(&mut self, val: T) {
        self.arr[self.cursor] = val;
        self.shift();
    }

    /// Shift: equivalent to pushing the oldest element
    pub fn shift(&mut self) {
        self.n_shifts(1);
    }

    /// computes n shift in a row
    pub fn n_shifts(&mut self, n: usize) {
        self.cursor += n;
        self.cursor %= N;
    }

    /// Getter for the internal memory
    #[allow(dead_code)]
    pub fn get_arr(&self) -> &[T; N] {
        &self.arr
    }
}

/// Index trait for the StaticDeque: 0 is the youngest element, N-1 is the oldest,
/// and above N will panic.
impl<const N: usize, T> Index<usize> for StaticDeque<N, T> {
    type Output = T;

    /// 0 is youngest
    fn index(&self, i: usize) -> &T {
        if i >= N {
            panic!("Index {i:?} too high for size {N:?}");
        }
        &self.arr[(N + self.cursor - i - 1) % N]
    }
}
/// IndexMut trait for the StaticDeque: 0 is the youngest element, N-1 is the oldest,
/// and above N will panic.
impl<const N: usize, T> IndexMut<usize> for StaticDeque<N, T> {
    /// 0 is youngest
    fn index_mut(&mut self, i: usize) -> &mut T {
        if i >= N {
            panic!("Index {i:?} too high for size {N:?}");
        }
        &mut self.arr[(N + self.cursor - i - 1) % N]
    }
}

#[cfg(test)]
mod tests {
    use crate::static_deque::StaticDeque;

    #[test]
    fn test_static_deque() {
        let a = [1, 2, 3, 4, 5, 6];

        let mut static_deque = StaticDeque::new(a);
        for i in 7..11 {
            static_deque.push(i);
        }
        assert_eq!(*static_deque.get_arr(), [7, 8, 9, 10, 5, 6]);

        for i in 11..15 {
            static_deque.push(i);
        }
        assert_eq!(*static_deque.get_arr(), [13, 14, 9, 10, 11, 12]);

        assert_eq!(static_deque[0], 14);
        assert_eq!(static_deque[1], 13);
        assert_eq!(static_deque[2], 12);
        assert_eq!(static_deque[3], 11);
        assert_eq!(static_deque[4], 10);
        assert_eq!(static_deque[5], 9);
    }

    #[test]
    fn test_static_deque_indexmut() {
        let a = [1, 2, 3, 4, 5, 6];

        let mut static_deque = StaticDeque::new(a);
        for i in 7..11 {
            static_deque.push(i);
        }
        assert_eq!(*static_deque.get_arr(), [7, 8, 9, 10, 5, 6]);

        for i in 11..15 {
            static_deque.push(i);
        }
        assert_eq!(*static_deque.get_arr(), [13, 14, 9, 10, 11, 12]);

        static_deque[1] = 100;

        assert_eq!(static_deque[0], 14);
        assert_eq!(static_deque[1], 100);
        assert_eq!(static_deque[2], 12);
        assert_eq!(static_deque[3], 11);
        assert_eq!(static_deque[4], 10);
        assert_eq!(static_deque[5], 9);
    }

    #[test]
    #[should_panic]
    fn test_static_deque_index_fail() {
        let a = [1, 2, 3, 4, 5, 6];

        let static_deque = StaticDeque::new(a);
        let _ = static_deque[6];
    }
}
