//! Module with traits pertaining to container manipulation.
//!
//! NB: This module is a duplication of tfhers/core_crypto/commons/traits.
//! Duplicated to keep genericty in Hpu backend code without circle dependence.
//! Warn: rustc see those traits as distincts one from tfhers

/// A trait to manipulate various immutable container types transparently.
pub trait Container: AsRef<[Self::Element]> {
    type Element;

    fn container_len(&self) -> usize {
        self.as_ref().len()
    }
}

/// A trait to manipulate various mutable container types transparently.
pub trait ContainerMut: Container + AsMut<[<Self as Container>::Element]> {}

impl<T> Container for [T] {
    type Element = T;
}

impl<T> ContainerMut for [T] {}

impl<T> Container for Vec<T> {
    type Element = T;
}

impl<T> ContainerMut for Vec<T> {}

impl<T> Container for &[T] {
    type Element = T;
}

impl<T> Container for &mut [T] {
    type Element = T;
}

impl<T> ContainerMut for &mut [T] {}

impl<T> Container for Box<[T]> {
    type Element = T;
}

impl<T> ContainerMut for Box<[T]> {}

pub trait Split: Sized {
    type Chunks: DoubleEndedIterator<Item = Self> + ExactSizeIterator<Item = Self>;

    #[allow(unused)]
    fn into_chunks(self, chunk_size: usize) -> Self::Chunks;
    #[allow(unused)]
    fn split_into(self, chunk_count: usize) -> Self::Chunks;
    #[allow(unused)]
    fn split_at(self, mid: usize) -> (Self, Self);
}

impl<'a, T> Split for &'a [T] {
    type Chunks = core::slice::ChunksExact<'a, T>;

    #[inline]
    fn into_chunks(self, chunk_size: usize) -> Self::Chunks {
        debug_assert_eq!(self.len() % chunk_size, 0);
        self.chunks_exact(chunk_size)
    }
    #[inline]
    fn split_into(self, chunk_count: usize) -> Self::Chunks {
        if chunk_count == 0 {
            debug_assert_eq!(self.len(), 0);
            self.chunks_exact(1)
        } else {
            debug_assert_eq!(self.len() % chunk_count, 0);
            self.chunks_exact(self.len() / chunk_count)
        }
    }
    #[inline]
    fn split_at(self, mid: usize) -> (Self, Self) {
        self.split_at(mid)
    }
}

impl<'a, T> Split for &'a mut [T] {
    type Chunks = core::slice::ChunksExactMut<'a, T>;

    #[inline]
    fn into_chunks(self, chunk_size: usize) -> Self::Chunks {
        debug_assert_eq!(self.len() % chunk_size, 0);
        self.chunks_exact_mut(chunk_size)
    }
    #[inline]
    fn split_into(self, chunk_count: usize) -> Self::Chunks {
        if chunk_count == 0 {
            debug_assert_eq!(self.len(), 0);
            self.chunks_exact_mut(1)
        } else {
            debug_assert_eq!(self.len() % chunk_count, 0);
            self.chunks_exact_mut(self.len() / chunk_count)
        }
    }
    #[inline]
    fn split_at(self, mid: usize) -> (Self, Self) {
        self.split_at_mut(mid)
    }
}
