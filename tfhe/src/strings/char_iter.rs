use super::ciphertext::FheAsciiChar;
use rayon::iter::{IntoParallelIterator, IntoParallelRefIterator, ParallelIterator};

pub(super) type CharIter<'a> = OptionalEndSliceIter<'a, FheAsciiChar>;

pub(super) struct OptionalEndSliceIter<'a, T> {
    slice: &'a [T],
    last: Option<&'a T>,
}

impl<T> Clone for OptionalEndSliceIter<'_, T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for OptionalEndSliceIter<'_, T> {}

impl<'a, T> OptionalEndSliceIter<'a, T> {
    pub(super) fn len(&self) -> usize {
        self.slice.len() + if self.last.is_some() { 1 } else { 0 }
    }

    pub(super) fn new(slice: &'a [T], last: Option<&'a T>) -> Self {
        Self { slice, last }
    }
}

pub mod iter {
    use super::*;

    impl<'a, T> IntoIterator for OptionalEndSliceIter<'a, T> {
        type Item = &'a T;

        type IntoIter = OptionalEndSliceIterator<'a, T>;

        fn into_iter(self) -> Self::IntoIter {
            OptionalEndSliceIterator {
                slice_iter: self.slice.iter(),
                last: self.last,
            }
        }
    }
    pub struct OptionalEndSliceIterator<'a, T> {
        slice_iter: std::slice::Iter<'a, T>,
        last: Option<&'a T>,
    }

    impl<'a, T> Iterator for OptionalEndSliceIterator<'a, T> {
        type Item = &'a T;

        fn next(&mut self) -> Option<Self::Item> {
            if let Some(item) = self.slice_iter.next() {
                Some(item)
            } else {
                self.last.take()
            }
        }

        fn size_hint(&self) -> (usize, Option<usize>) {
            (self.len(), Some(self.len()))
        }
    }

    impl<T> DoubleEndedIterator for OptionalEndSliceIterator<'_, T> {
        fn next_back(&mut self) -> Option<Self::Item> {
            if let Some(last) = self.last.take() {
                Some(last)
            } else {
                self.slice_iter.next_back()
            }
        }
    }

    impl<T> ExactSizeIterator for OptionalEndSliceIterator<'_, T> {
        fn len(&self) -> usize {
            self.slice_iter.len() + if self.last.is_some() { 1 } else { 0 }
        }
    }

    #[test]
    fn test_iter() {
        {
            let a = OptionalEndSliceIter::new(&[0, 1, 2, 3], Some(&4));

            let mut b = a.into_iter();

            assert_eq!(b.next(), Some(&0));
            assert_eq!(b.next(), Some(&1));
            assert_eq!(b.next(), Some(&2));
            assert_eq!(b.next(), Some(&3));
            assert_eq!(b.next(), Some(&4));
            assert_eq!(b.next(), None);
        }
        {
            let a = OptionalEndSliceIter::new(&[0, 1, 2, 3], None);

            let mut b = a.into_iter();

            assert_eq!(b.next(), Some(&0));
            assert_eq!(b.next(), Some(&1));
            assert_eq!(b.next(), Some(&2));
            assert_eq!(b.next(), Some(&3));
            assert_eq!(b.next(), None);
        }
    }

    #[test]
    fn test_iter_back() {
        {
            let a = OptionalEndSliceIter::new(&[0, 1, 2, 3], Some(&4));

            let mut b = a.into_iter();

            assert_eq!(b.next_back(), Some(&4));
            assert_eq!(b.next_back(), Some(&3));
            assert_eq!(b.next_back(), Some(&2));
            assert_eq!(b.next_back(), Some(&1));
            assert_eq!(b.next_back(), Some(&0));
            assert_eq!(b.next_back(), None);
        }

        {
            let a = OptionalEndSliceIter::new(&[0, 1, 2, 3], None);

            let mut b = a.into_iter();

            assert_eq!(b.next_back(), Some(&3));
            assert_eq!(b.next_back(), Some(&2));
            assert_eq!(b.next_back(), Some(&1));
            assert_eq!(b.next_back(), Some(&0));
            assert_eq!(b.next_back(), None);
        }
    }

    #[test]
    fn test_iter_mix() {
        {
            let a = OptionalEndSliceIter::new(&[0, 1, 2, 3], Some(&4));

            let mut b = a.into_iter();

            assert_eq!(b.next_back(), Some(&4));
            assert_eq!(b.next(), Some(&0));
            assert_eq!(b.next_back(), Some(&3));
            assert_eq!(b.next(), Some(&1));
            assert_eq!(b.next_back(), Some(&2));
            assert_eq!(b.next(), None);
        }
        {
            let a = OptionalEndSliceIter::new(&[0, 1, 2, 3], None);

            let mut b = a.into_iter();

            assert_eq!(b.next_back(), Some(&3));
            assert_eq!(b.next(), Some(&0));
            assert_eq!(b.next_back(), Some(&2));
            assert_eq!(b.next(), Some(&1));
            assert_eq!(b.next_back(), None);
        }
    }
}

impl<'a> IntoParallelRefIterator<'a> for CharIter<'a> {
    type Item = &'a FheAsciiChar;

    type Iter = rayon::iter::Chain<
        rayon::slice::Iter<'a, FheAsciiChar>,
        rayon::option::IntoIter<&'a FheAsciiChar>,
    >;

    fn par_iter(&'a self) -> Self::Iter {
        self.slice.par_iter().chain(self.last.into_par_iter())
    }
}
