use crate::array::helpers::range_bounds_to_exclusive_range;
use rayon::iter::plumbing::{Consumer, ProducerCallback, UnindexedConsumer};
use std::iter::FusedIterator;
use std::ops::{RangeBounds, RangeInclusive};

#[derive(Clone, Debug)]
pub struct DynDimensions {
    pub(crate) shape: Vec<usize>,
    pub(crate) strides: Vec<usize>,
}

impl DynDimensions {
    pub fn shape(&self) -> &[usize] {
        &self.shape
    }
    pub fn strides(&self) -> &[usize] {
        &self.strides
    }

    pub fn num_dim(&self) -> usize {
        self.shape.len()
    }

    pub fn flattened_len(&self) -> usize {
        self.shape.iter().copied().product()
    }

    pub fn get_slice_info<R>(&self, ranges: &[R]) -> Option<(Self, RangeInclusive<usize>)>
    where
        R: Clone + RangeBounds<usize>,
    {
        if ranges.len() != self.num_dim() {
            return None;
        }

        let mut new_shape = vec![0usize; ranges.len()];
        let flattened_len = self.flattened_len();
        let mut flat_start = 0;
        let mut flat_end = 0;

        for (i, (range, &shape_len)) in std::iter::zip(ranges.iter(), self.shape.iter()).enumerate()
        {
            let exclusive_range = range_bounds_to_exclusive_range(range.clone(), flattened_len);
            if exclusive_range.start >= shape_len || exclusive_range.end > shape_len {
                return None;
            }
            new_shape[i] = exclusive_range.len();
            flat_start += exclusive_range.start * self.strides[i];
            flat_end += (exclusive_range.end.saturating_sub(1)) * self.strides[i];
        }
        let new_dim = Self {
            shape: new_shape,
            strides: self.strides.clone(),
        };
        Some((new_dim, flat_start..=flat_end))
    }

    pub fn flatten_index(&self, index: &[usize]) -> Option<usize> {
        if index.len() != self.num_dim() {
            return None;
        }

        Some(
            index
                .iter()
                .zip(self.strides.iter())
                .map(|(&i, &stride)| i.wrapping_mul(stride))
                .sum(),
        )
    }
}

impl From<Vec<usize>> for DynDimensions {
    fn from(shape: Vec<usize>) -> Self {
        let mut strides = vec![1usize; shape.len()];
        if shape.len() > 1 {
            for i in (0..(shape.len() - 1)).rev() {
                strides[i] = strides[i + 1] * shape[i + 1];
            }
        }

        Self { shape, strides }
    }
}

/// Iterator that returns flat index (one-dimensional, i.e. a single usize)
/// over a multi-dimensional array.
#[derive(Clone, Debug)]
pub struct StridedIndexProducer {
    current_index: Vec<usize>,
    // Assumes row-major order, so the lowest stride is last (is it always true) ?
    dims: DynDimensions,
}
impl StridedIndexProducer {
    pub fn new(dims: DynDimensions) -> Self {
        Self {
            current_index: vec![0; dims.num_dim()],
            dims,
        }
    }

    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        let mut count = 0;

        // TODO find a nicer way
        let cloned_self = self.clone();
        for _ in cloned_self {
            count += 1;
        }

        count
    }

    pub fn current_index(&self) -> Option<usize> {
        if self.current_index[0] >= self.dims.shape[0] {
            return None;
        }

        // unwrap to catch bugs in the logic of this function
        let current_flat_index = self.dims.flatten_index(&self.current_index).unwrap();
        Some(current_flat_index)
    }

    fn forward(&mut self) {
        self.current_index[self.dims.num_dim() - 1] += 1;
        for dim_index in (1..self.dims.num_dim()).rev() {
            if self.current_index[dim_index] == self.dims.shape[dim_index] {
                self.current_index[dim_index] = 0;
                self.current_index[dim_index - 1] += 1;
            }
        }
    }

    fn backward(&self) {
        // It's required by rayon's trait bounds, but does not seems to
        // actually be used
        todo!("Backward iteration is not yet supported")
    }
}

impl Iterator for StridedIndexProducer {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        let current_flat_index = self.current_index()?;
        // Now, modify the current index to be the next one
        self.forward();

        Some(current_flat_index)
    }
}

impl DoubleEndedIterator for StridedIndexProducer {
    fn next_back(&mut self) -> Option<Self::Item> {
        let current_flat_index = self.current_index()?;

        // Now, modify the current index to be the previous one
        self.backward();

        Some(current_flat_index)
    }
}

impl FusedIterator for StridedIndexProducer {}

impl ExactSizeIterator for StridedIndexProducer {
    fn len(&self) -> usize {
        self.len()
    }
}

#[derive(Clone)]
pub struct StridedIter<'a, T> {
    index_producer: StridedIndexProducer,
    data: &'a [T],
}

impl<'a, T> StridedIter<'a, T> {
    pub fn new(data: &'a [T], dims: DynDimensions) -> Self {
        Self {
            index_producer: StridedIndexProducer::new(dims),
            data,
        }
    }
}

impl<'a, T> Iterator for StridedIter<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<Self::Item> {
        let current_flat_index = self.index_producer.next();
        self.data.get(current_flat_index?)
    }
}

impl<T> ExactSizeIterator for StridedIter<'_, T> {
    fn len(&self) -> usize {
        self.index_producer.len()
    }
}

impl<T> DoubleEndedIterator for StridedIter<'_, T> {
    fn next_back(&mut self) -> Option<Self::Item> {
        let current_flat_index = self.index_producer.next_back()?;
        self.data.get(current_flat_index)
    }
}

#[derive(Clone)]
pub struct CountedStridedIter<'a, T> {
    inner: StridedIter<'a, T>,
    // We cannot just have a single `remaining` counter
    // to support reverse iteration
    current_count: usize,
    max_count: usize,
}

impl<'a, T> CountedStridedIter<'a, T> {
    pub fn new(data: &'a [T], dims: DynDimensions, max_count: usize) -> Self {
        Self {
            inner: StridedIter::new(data, dims),
            current_count: 0,
            max_count,
        }
    }
}

impl<'a, T> Iterator for CountedStridedIter<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_count >= self.max_count {
            None
        } else {
            self.current_count += 1;
            // Unwrap to catch potential bugs
            Some(self.inner.next().unwrap())
        }
    }
}

impl<T> ExactSizeIterator for CountedStridedIter<'_, T> {
    fn len(&self) -> usize {
        self.max_count - self.current_count
    }
}

impl<T> DoubleEndedIterator for CountedStridedIter<'_, T> {
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.current_count == 0 {
            None
        } else {
            self.current_count -= 1;
            // Unwrap to catch potential bugs
            Some(self.inner.next_back().unwrap())
        }
    }
}

#[derive(Clone)]
pub struct ParStridedIter<'a, T> {
    inner: CountedStridedIter<'a, T>,
}

impl<'a, T> ParStridedIter<'a, T> {
    pub fn new(data: &'a [T], dims: DynDimensions) -> Self {
        let all = dims.flattened_len();
        Self {
            inner: CountedStridedIter::new(data, dims, all),
        }
    }
}

impl<'a, T> rayon::iter::ParallelIterator for ParStridedIter<'a, T>
where
    T: Send + Sync,
{
    type Item = &'a T;

    fn drive_unindexed<C>(self, consumer: C) -> C::Result
    where
        C: UnindexedConsumer<Self::Item>,
    {
        rayon::iter::plumbing::bridge(self, consumer)
    }

    fn opt_len(&self) -> Option<usize> {
        Some(self.inner.len())
    }
}

impl<T> rayon::iter::IndexedParallelIterator for ParStridedIter<'_, T>
where
    T: Send + Sync,
{
    fn len(&self) -> usize {
        self.inner.len()
    }

    fn drive<C: Consumer<Self::Item>>(self, consumer: C) -> C::Result {
        rayon::iter::plumbing::bridge(self, consumer)
    }

    fn with_producer<CB: ProducerCallback<Self::Item>>(self, callback: CB) -> CB::Output {
        let producer = ParStridedIterProducer {
            original_iter: self,
        };
        callback.callback(producer)
    }
}

#[derive(Clone)]
pub struct ParStridedIterProducer<'a, T> {
    original_iter: ParStridedIter<'a, T>,
}

impl<'a, T> rayon::iter::plumbing::Producer for ParStridedIterProducer<'a, T>
where
    T: Send + Sync,
{
    type Item = &'a T;
    type IntoIter = CountedStridedIter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.original_iter.inner
    }

    fn split_at(self, index: usize) -> (Self, Self) {
        let remaining = self.original_iter.inner.len();
        let StridedIter {
            index_producer,
            data,
        } = self.original_iter.inner.inner;

        let mut right_index_producer = index_producer.clone();
        for _ in 0..index {
            _ = right_index_producer.next().unwrap();
        }

        let (left_data, right_data) = (data, data);

        let left_index_producer = index_producer;
        let left_strided_iter = ParStridedIter {
            inner: CountedStridedIter {
                inner: StridedIter {
                    index_producer: left_index_producer,
                    data: left_data,
                },
                current_count: 0,
                max_count: index,
            },
        };

        let right_strided_iter = ParStridedIter {
            inner: CountedStridedIter {
                inner: StridedIter {
                    index_producer: right_index_producer,
                    data: right_data,
                },
                current_count: 0,
                max_count: remaining - index,
            },
        };

        let left = ParStridedIterProducer {
            original_iter: left_strided_iter,
        };

        let right = ParStridedIterProducer {
            original_iter: right_strided_iter,
        };

        (left, right)
    }
}

pub struct OffsettedStridedIterMut<'a, T> {
    flat_offset: usize,
    index_producer: StridedIndexProducer,
    current_count: usize,
    max_count: usize,
    inner: ::std::slice::IterMut<'a, T>,
}

impl<'a, T> Iterator for OffsettedStridedIterMut<'a, T> {
    type Item = &'a mut T;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_count == self.max_count {
            None
        } else {
            let relative_index = self
                .index_producer
                .next()
                .map(|idx| idx - self.flat_offset)?;

            // We would do slice[current_index],
            // However we have a slice::IterMut
            for _ in 0..relative_index.saturating_sub(1) {
                self.inner.next().unwrap();
            }

            self.current_count += 1;
            self.inner.next()
        }
    }
}

impl<T> DoubleEndedIterator for OffsettedStridedIterMut<'_, T> {
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.current_count == 0 {
            None
        } else {
            let relative_index = self
                .index_producer
                .next_back()
                .map(|idx| idx - self.flat_offset)?;

            for _ in 0..relative_index.saturating_sub(1) {
                self.inner.next_back().unwrap();
            }

            self.current_count -= 1;
            self.inner.next()
        }
    }
}

impl<T> ExactSizeIterator for OffsettedStridedIterMut<'_, T> {
    fn len(&self) -> usize {
        ExactSizeIterator::len(&self.index_producer)
    }
}

pub struct ParStridedIterMut<'a, T> {
    inner: OffsettedStridedIterMut<'a, T>,
}

impl<'a, T> ParStridedIterMut<'a, T> {
    pub fn new(slice: &'a mut [T], dims: DynDimensions) -> Self {
        let max_count = dims.flattened_len();
        Self {
            inner: OffsettedStridedIterMut {
                flat_offset: 0,
                index_producer: StridedIndexProducer::new(dims),
                current_count: 0,
                max_count,
                inner: slice.iter_mut(),
            },
        }
    }
}

impl<'a, T> rayon::iter::ParallelIterator for ParStridedIterMut<'a, T>
where
    T: Send,
{
    type Item = &'a mut T;

    fn drive_unindexed<C>(self, consumer: C) -> C::Result
    where
        C: UnindexedConsumer<Self::Item>,
    {
        rayon::iter::plumbing::bridge(self, consumer)
    }
}

impl<T> rayon::iter::IndexedParallelIterator for ParStridedIterMut<'_, T>
where
    T: Send,
{
    fn len(&self) -> usize {
        ExactSizeIterator::len(&self.inner.index_producer)
    }

    fn drive<C: Consumer<Self::Item>>(self, consumer: C) -> C::Result {
        rayon::iter::plumbing::bridge(self, consumer)
    }

    fn with_producer<CB: ProducerCallback<Self::Item>>(self, callback: CB) -> CB::Output {
        let producer = ParStridedIterMutProducer {
            flat_offset: self.inner.flat_offset,
            index_producer: self.inner.index_producer,
            data: self.inner.inner.into_slice(),
            current_count: self.inner.current_count,
            max_count: self.inner.max_count,
        };
        callback.callback(producer)
    }
}

pub struct ParStridedIterMutProducer<'a, T> {
    flat_offset: usize,
    index_producer: StridedIndexProducer,
    data: &'a mut [T],
    current_count: usize,
    max_count: usize,
}

impl<'a, T> rayon::iter::plumbing::Producer for ParStridedIterMutProducer<'a, T>
where
    T: Send,
{
    type Item = &'a mut T;
    type IntoIter = OffsettedStridedIterMut<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        OffsettedStridedIterMut {
            flat_offset: self.flat_offset,
            index_producer: self.index_producer,
            current_count: self.current_count,
            max_count: self.max_count,
            inner: self.data.iter_mut(),
        }
    }

    fn split_at(self, index: usize) -> (Self, Self) {
        let ParStridedIterMutProducer {
            flat_offset,
            index_producer,
            data,
            current_count,
            max_count,
        } = self;
        let remaining = max_count - current_count;

        let mut right_index_producer = index_producer.clone();
        for _ in 0..index {
            _ = right_index_producer.next().unwrap();
        }

        let split_index = right_index_producer.current_index().unwrap() - flat_offset;
        let (left_data, right_data) = data.split_at_mut(split_index);

        let left = Self {
            flat_offset,
            index_producer,
            data: left_data,
            current_count: 0,
            max_count: index,
        };

        let right = Self {
            flat_offset: flat_offset + split_index,
            index_producer: right_index_producer,
            data: right_data,
            current_count: 0,
            max_count: remaining - index,
        };

        (left, right)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::array::traits::TensorSlice;
    use rayon::iter::plumbing::Producer;
    use rayon::iter::ParallelIterator;

    #[test]
    fn test_strided_iter() {
        // For a 4x4 matrix
        //
        // [[ 0,  1,  2,  3]
        // [ 4,  5,  6,  7]
        // [ 8,  9, 10, 11]
        // [12, 13, 14, 15]]
        let data = (0..16).collect::<Vec<_>>();
        let dims = DynDimensions::from(vec![4, 4]);

        let expected_indices = (0..dims.flattened_len()).collect::<Vec<_>>();
        let indices = StridedIndexProducer::new(dims.clone()).collect::<Vec<_>>();
        assert_eq!(expected_indices, indices);

        let values = StridedIter::new(data.as_slice(), dims.clone())
            .copied()
            .collect::<Vec<_>>();
        assert_eq!(data, values);

        // We take the lower right 2x2 square as a slice
        //
        // [[ 0,  1,  2,  3]
        // [ 4,  5,  6,  7 ]
        // [ 8,  9, |10, 11|]
        // [12, 13, |14, 15|]]
        let (sub_dims, flat_range) = dims.get_slice_info(&[2..4, 2..4]).unwrap();
        assert_eq!(sub_dims.shape, &[2, 2]);
        assert_eq!(sub_dims.strides, dims.strides);
        assert_eq!(flat_range, 10..=15);
        let indices = StridedIndexProducer::new(sub_dims.clone()).collect::<Vec<_>>();
        assert_eq!(indices, &[0, 1, 4, 5]);

        let values = StridedIter::new(&data[flat_range.clone()], sub_dims.clone())
            .copied()
            .collect::<Vec<_>>();
        assert_eq!([10, 11, 14, 15].as_slice(), &values);

        let tensor_slice = TensorSlice::new(&data[flat_range], &sub_dims);
        let values = tensor_slice.iter().copied().collect::<Vec<_>>();
        assert_eq!([10, 11, 14, 15].as_slice(), &values);
    }

    #[test]
    fn test_par_strided_iter() {
        //[  0,  1 , 2,  3
        //   4,  5,  6,  7
        //   8,  9, 10, 11
        //  12, 13, 14, 15  ]
        let n_rows = 4;
        let n_cols = 4;
        let len = n_cols * n_rows;
        let data = (0..len as u32).collect::<Vec<_>>();
        assert_eq!(
            &data[..],
            &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
        );
        let dims = DynDimensions::from(vec![n_rows, n_cols]);
        let (sub_dims, flat_slice) = dims.get_slice_info(&[2..4, 2..4]).unwrap();

        assert_eq!(sub_dims.flattened_len(), 4);

        let sub_slice = &data[flat_slice];
        assert_eq!(sub_slice.len(), 6);

        let flat_indices = StridedIndexProducer::new(sub_dims.clone()).collect::<Vec<_>>();
        assert_eq!(&flat_indices, &[0, 1, 4, 5]);
        let values = StridedIter::new(sub_slice, sub_dims.clone())
            .copied()
            .collect::<Vec<_>>();
        assert_eq!(&values, &[10, 11, 14, 15]);

        let producer = ParStridedIterProducer {
            original_iter: ParStridedIter::new(sub_slice, sub_dims.clone()),
        };
        let (left, right) = producer.split_at(2);
        // Check the left
        {
            let left_iter = left.clone().into_iter();
            let left_values = left_iter.copied().collect::<Vec<_>>();
            assert_eq!(&left_values, &[10, 11]);

            // re-split
            let (ll, lr) = left.split_at(1);
            let left_values = ll.into_iter().copied().collect::<Vec<_>>();
            assert_eq!(&left_values, &[10]);

            let right_values = lr.into_iter().copied().collect::<Vec<_>>();
            assert_eq!(&right_values, &[11]);
        }

        // Check the right
        {
            let right_iter = right.clone().into_iter();
            let right_values = right_iter.copied().collect::<Vec<_>>();
            assert_eq!(&right_values, &[14, 15]);

            // re-split
            let (rl, rr) = right.split_at(1);
            let left_values = rl.into_iter().copied().collect::<Vec<_>>();
            assert_eq!(&left_values, &[14]);

            let right_values = rr.into_iter().copied().collect::<Vec<_>>();
            assert_eq!(&right_values, &[15]);
        }

        let values = ParStridedIter::new(sub_slice, sub_dims)
            .copied()
            .collect::<Vec<_>>();
        assert_eq!(&values, &[10, 11, 14, 15]);
    }
}
