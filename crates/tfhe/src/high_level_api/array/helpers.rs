use std::collections::Bound;
use std::ops::{Index, IndexMut, Range, RangeBounds};

pub(super) fn range_bounds_to_exclusive_range<R>(range: R, len: usize) -> Range<usize>
where
    R: RangeBounds<usize>,
{
    let start = match range.start_bound() {
        Bound::Included(start) => *start,
        Bound::Excluded(start) => *start + 1,
        Bound::Unbounded => 0,
    };
    let end = match range.end_bound() {
        Bound::Included(end) => *end + 1,
        Bound::Excluded(end) => *end,
        Bound::Unbounded => len,
    };

    start..end
}

pub(super) fn create_sub_slice_with_bound<C, T, R>(data: &C, range: R) -> &[T]
where
    C: AsRef<[T]> + ?Sized + Index<Range<usize>, Output = [T]>,
    R: RangeBounds<usize>,
{
    let range = range_bounds_to_exclusive_range(range, data.as_ref().len());
    data.index(range)
}

pub(super) fn create_sub_mut_slice_with_bound<C, T, R>(data: &mut C, range: R) -> &mut [T]
where
    C: AsRef<[T]> + ?Sized + IndexMut<Range<usize>, Output = [T]>,
    R: RangeBounds<usize>,
{
    let range = range_bounds_to_exclusive_range(range, data.as_ref().len());
    data.index_mut(range)
}
