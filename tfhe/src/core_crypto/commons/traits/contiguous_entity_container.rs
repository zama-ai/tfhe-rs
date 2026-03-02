//! Module with traits pertaining to efficient contiguous containers of complex entities
//! manipulation.

use super::create_from::*;
use rayon::prelude::*;
use std::ops::{Bound, RangeBounds};

type WrappingFunction<'data, Element, WrappingType> = fn(
    (
        &'data [Element],
        <WrappingType as CreateFrom<&'data [Element]>>::Metadata,
    ),
) -> WrappingType;

type ChunksWrappingLendingIterator<'data, Element, WrappingType> = std::iter::Map<
    std::iter::Zip<
        std::slice::Chunks<'data, Element>,
        core::iter::RepeatN<<WrappingType as CreateFrom<&'data [Element]>>::Metadata>,
    >,
    WrappingFunction<'data, Element, WrappingType>,
>;

type ChunksExactWrappingLendingIterator<'data, Element, WrappingType> = std::iter::Map<
    std::iter::Zip<
        std::slice::ChunksExact<'data, Element>,
        core::iter::RepeatN<<WrappingType as CreateFrom<&'data [Element]>>::Metadata>,
    >,
    WrappingFunction<'data, Element, WrappingType>,
>;

type ParallelChunksWrappingLendingIterator<'data, Element, WrappingType> = rayon::iter::Map<
    rayon::iter::Zip<
        rayon::slice::Chunks<'data, Element>,
        rayon::iter::RepeatN<<WrappingType as CreateFrom<&'data [Element]>>::Metadata>,
    >,
    WrappingFunction<'data, Element, WrappingType>,
>;

type ParallelChunksExactWrappingLendingIterator<'data, Element, WrappingType> = rayon::iter::Map<
    rayon::iter::Zip<
        rayon::slice::ChunksExact<'data, Element>,
        rayon::iter::RepeatN<<WrappingType as CreateFrom<&'data [Element]>>::Metadata>,
    >,
    WrappingFunction<'data, Element, WrappingType>,
>;

type WrappingFunctionMut<'data, Element, WrappingType> = fn(
    (
        &'data mut [Element],
        <WrappingType as CreateFrom<&'data mut [Element]>>::Metadata,
    ),
) -> WrappingType;

type ChunksWrappingLendingIteratorMut<'data, Element, WrappingType> = std::iter::Map<
    std::iter::Zip<
        std::slice::ChunksMut<'data, Element>,
        core::iter::RepeatN<<WrappingType as CreateFrom<&'data mut [Element]>>::Metadata>,
    >,
    WrappingFunctionMut<'data, Element, WrappingType>,
>;

type ChunksExactWrappingLendingIteratorMut<'data, Element, WrappingType> = std::iter::Map<
    std::iter::Zip<
        std::slice::ChunksExactMut<'data, Element>,
        core::iter::RepeatN<<WrappingType as CreateFrom<&'data mut [Element]>>::Metadata>,
    >,
    WrappingFunctionMut<'data, Element, WrappingType>,
>;

type ParallelChunksWrappingLendingIteratorMut<'data, Element, WrappingType> = rayon::iter::Map<
    rayon::iter::Zip<
        rayon::slice::ChunksMut<'data, Element>,
        rayon::iter::RepeatN<<WrappingType as CreateFrom<&'data mut [Element]>>::Metadata>,
    >,
    WrappingFunctionMut<'data, Element, WrappingType>,
>;

type ParallelChunksExactWrappingLendingIteratorMut<'data, Element, WrappingType> = rayon::iter::Map<
    rayon::iter::Zip<
        rayon::slice::ChunksExactMut<'data, Element>,
        rayon::iter::RepeatN<<WrappingType as CreateFrom<&'data mut [Element]>>::Metadata>,
    >,
    WrappingFunctionMut<'data, Element, WrappingType>,
>;

/// A trait to generically implement standard slice algorithms for contiguous entity containers.
///
/// Performance using contiguous containers can be dramatically better than "vec of vecs"
/// counterparts.
pub trait ContiguousEntityContainer: AsRef<[Self::Element]> {
    /// Plain Old Data type used to store data, e.g. u8/u16/u32/u64.
    type Element;

    /// Concrete type of the metadata used to create a [`Self::EntityView`].
    type EntityViewMetadata: Clone;

    /// Entity stored in the container that can be a complex type (like an
    /// [`LweCiphertext`](crate::core_crypto::entities::LweCiphertext)) using a reference to a
    /// container of [`Self::Element`] (e.g. u32/u64) to store its data.
    type EntityView<'this>: CreateFrom<&'this [Self::Element], Metadata = Self::EntityViewMetadata>
    where
        Self: 'this;

    /// Concrete type of the metadata used to create a [`Self::SelfView`].
    type SelfViewMetadata: Clone;

    /// Concrete immutable view type of the current container type, used to create sub containers.
    type SelfView<'this>: CreateFrom<&'this [Self::Element], Metadata = Self::SelfViewMetadata>
    where
        Self: 'this;

    /// Provide relevant metadata to convert [`Self::Element`] slices to wrapper/complex types.
    fn get_entity_view_creation_metadata(&self) -> Self::EntityViewMetadata;

    /// Provide the size of a single [`Self::EntityView`].
    fn get_entity_view_pod_size(&self) -> usize;

    /// Return the number of entities in the [`ContiguousEntityContainer`]
    fn entity_count(&self) -> usize {
        let entity_view_pod_size = self.get_entity_view_pod_size();
        let entity_count = self.as_ref().len() / entity_view_pod_size;
        entity_count
    }

    /// Return an iterator borrowing immutably from the current contiguous container which returns
    /// [`Self::EntityView`] entities.
    fn iter(&self) -> ChunksExactWrappingLendingIterator<'_, Self::Element, Self::EntityView<'_>> {
        let meta = self.get_entity_view_creation_metadata();
        let entity_count = self.entity_count();
        let entity_view_pod_size = self.get_entity_view_pod_size();
        self.as_ref()
            .chunks_exact(entity_view_pod_size)
            .zip(core::iter::repeat_n(meta, entity_count))
            .map(|(elt, meta)| Self::EntityView::<'_>::create_from(elt, meta))
    }

    /// Provide relevant metadata to create a container of the same type as [`Self`].
    fn get_self_view_creation_metadata(&self) -> Self::SelfViewMetadata;

    fn split_at(&self, mid: usize) -> (Self::SelfView<'_>, Self::SelfView<'_>) {
        // mid here is the number of ref_elements, we need to multiply by the size of a single
        // element to know where to split the underlying container

        let mid = mid.checked_mul(self.get_entity_view_pod_size()).unwrap();
        let self_meta = self.get_self_view_creation_metadata();

        let (container_left, container_right) = self.as_ref().split_at(mid);

        (
            Self::SelfView::<'_>::create_from(container_left, self_meta.clone()),
            Self::SelfView::<'_>::create_from(container_right, self_meta),
        )
    }

    fn get(&self, index: usize) -> Self::EntityView<'_> {
        // index here is the number of ref_elements, we need to multiply by the size of a single
        // element to know where to reference the underlying container

        let start = index.checked_mul(self.get_entity_view_pod_size()).unwrap();
        let stop = start + self.get_entity_view_pod_size();
        let meta = self.get_entity_view_creation_metadata();

        Self::EntityView::<'_>::create_from(&self.as_ref()[start..stop], meta)
    }

    fn get_sub<R: RangeBounds<usize>>(&self, range_bounds: R) -> Self::SelfView<'_> {
        let entity_start_bound = range_bounds.start_bound();
        let entity_start_index = match entity_start_bound {
            Bound::Included(&start) => start,
            Bound::Excluded(&start) => start + 1,
            Bound::Unbounded => 0,
        };

        let entity_stop_bound = range_bounds.end_bound();
        let entity_stop_index = match entity_stop_bound {
            Bound::Included(&stop) => stop + 1,
            Bound::Excluded(&stop) => stop,
            Bound::Unbounded => self.entity_count(),
        };

        let start_index = entity_start_index
            .checked_mul(self.get_entity_view_pod_size())
            .unwrap();
        let stop_index = entity_stop_index
            .checked_mul(self.get_entity_view_pod_size())
            .unwrap();

        let self_meta = self.get_self_view_creation_metadata();

        let sub_container = &self.as_ref()[start_index..stop_index];
        Self::SelfView::<'_>::create_from(sub_container, self_meta)
    }

    fn first(&self) -> Option<Self::EntityView<'_>> {
        let entity_count = self.entity_count();

        if entity_count == 0 {
            None
        } else {
            Some(self.get(0))
        }
    }

    fn last(&self) -> Option<Self::EntityView<'_>> {
        let entity_count = self.entity_count();

        if entity_count == 0 {
            None
        } else {
            Some(self.get(entity_count - 1))
        }
    }

    fn chunks(
        &self,
        chunk_size: usize,
    ) -> ChunksWrappingLendingIterator<'_, Self::Element, Self::SelfView<'_>> {
        let entity_count = self.entity_count();

        let entity_view_pod_size = self.get_entity_view_pod_size();
        let pod_chunk_size = entity_view_pod_size.checked_mul(chunk_size).unwrap();

        let meta = self.get_self_view_creation_metadata();
        self.as_ref()
            .chunks(pod_chunk_size)
            .zip(core::iter::repeat_n(meta, entity_count))
            .map(|(elt, meta)| Self::SelfView::<'_>::create_from(elt, meta))
    }

    fn chunks_exact(
        &self,
        chunk_size: usize,
    ) -> ChunksExactWrappingLendingIterator<'_, Self::Element, Self::SelfView<'_>> {
        let entity_count = self.entity_count();
        assert!(
            entity_count.is_multiple_of(chunk_size),
            "The current container has {entity_count} entities, which is not dividable by the \
            requested chunk_size: {chunk_size}, preventing chunks_exact from returning an iterator."
        );

        let entity_view_pod_size = self.get_entity_view_pod_size();
        let pod_chunk_size = entity_view_pod_size.checked_mul(chunk_size).unwrap();

        let meta = self.get_self_view_creation_metadata();
        self.as_ref()
            .chunks_exact(pod_chunk_size)
            .zip(core::iter::repeat_n(meta, entity_count))
            .map(|(elt, meta)| Self::SelfView::<'_>::create_from(elt, meta))
    }

    fn par_iter<'this>(
        &'this self,
    ) -> ParallelChunksExactWrappingLendingIterator<'this, Self::Element, Self::EntityView<'this>>
    where
        Self::Element: Sync,
        Self::EntityView<'this>: Send,
        Self::EntityViewMetadata: Send,
    {
        let meta = self.get_entity_view_creation_metadata();
        let entity_count = self.entity_count();
        let entity_view_pod_size = self.get_entity_view_pod_size();
        self.as_ref()
            .par_chunks_exact(entity_view_pod_size)
            .zip(rayon::iter::repeat_n(meta, entity_count))
            .map(|(elt, meta)| Self::EntityView::<'this>::create_from(elt, meta))
    }

    fn par_chunks<'this>(
        &'this self,
        chunk_size: usize,
    ) -> ParallelChunksWrappingLendingIterator<'this, Self::Element, Self::SelfView<'this>>
    where
        Self::Element: Sync,
        Self::SelfView<'this>: Send,
        Self::SelfViewMetadata: Send,
    {
        let entity_count = self.entity_count();

        let entity_view_pod_size = self.get_entity_view_pod_size();
        let pod_chunk_size = entity_view_pod_size.checked_mul(chunk_size).unwrap();

        let meta = self.get_self_view_creation_metadata();
        self.as_ref()
            .par_chunks(pod_chunk_size)
            .zip(rayon::iter::repeat_n(meta, entity_count))
            .map(|(elt, meta)| Self::SelfView::<'_>::create_from(elt, meta))
    }

    fn par_chunks_exact<'this>(
        &'this self,
        chunk_size: usize,
    ) -> ParallelChunksExactWrappingLendingIterator<'this, Self::Element, Self::SelfView<'this>>
    where
        Self::Element: Sync,
        Self::SelfView<'this>: Send,
        Self::SelfViewMetadata: Send,
    {
        let entity_count = self.entity_count();
        assert!(
            entity_count.is_multiple_of(chunk_size),
            "The current container has {entity_count} entities, which is not dividable by the \
            requested chunk_size: {chunk_size}, preventing chunks_exact from returning an iterator."
        );

        let entity_view_pod_size = self.get_entity_view_pod_size();
        let pod_chunk_size = entity_view_pod_size.checked_mul(chunk_size).unwrap();

        let meta = self.get_self_view_creation_metadata();
        self.as_ref()
            .par_chunks_exact(pod_chunk_size)
            .zip(rayon::iter::repeat_n(meta, entity_count))
            .map(|(elt, meta)| Self::SelfView::<'_>::create_from(elt, meta))
    }
}

pub trait ContiguousEntityContainerMut: ContiguousEntityContainer + AsMut<[Self::Element]> {
    /// Mutable entity stored in the container that can be a complex type (like an LWE ciphertext)
    /// using a reference to a container of Plain Old Data (e.g. u32/u64) to store its data.
    ///
    /// The assumption here is that views and mut views use the same metadata to be created.
    type EntityMutView<'this>: CreateFrom<
        &'this mut [Self::Element],
        Metadata = Self::EntityViewMetadata,
    >
    where
        Self: 'this;

    /// Concrete mutable view type of the current container type, used to create sub containers.
    ///
    /// The assumption here is that views and mut views use the same metadata to be created.
    type SelfMutView<'this>: CreateFrom<
        &'this mut [Self::Element],
        Metadata = Self::SelfViewMetadata,
    >
    where
        Self: 'this;

    /// Return an iterator borrowing mutably from the current contiguous container which returns
    /// [`Self::EntityMutView`] entities.
    fn iter_mut(
        &mut self,
    ) -> ChunksExactWrappingLendingIteratorMut<'_, Self::Element, Self::EntityMutView<'_>> {
        let meta = self.get_entity_view_creation_metadata();
        let entity_count = self.entity_count();
        let entity_view_pod_size = self.get_entity_view_pod_size();
        self.as_mut()
            .chunks_exact_mut(entity_view_pod_size)
            .zip(core::iter::repeat_n(meta, entity_count))
            .map(|(elt, meta)| Self::EntityMutView::<'_>::create_from(elt, meta))
    }

    fn split_at_mut(&mut self, mid: usize) -> (Self::SelfMutView<'_>, Self::SelfMutView<'_>) {
        // mid here is the number of ref_elements, we need to multiply by the size of a single
        // element to know where to split the underlying container

        let mid = mid * self.get_entity_view_pod_size();
        let self_meta = self.get_self_view_creation_metadata();

        let (container_left, container_right) = self.as_mut().split_at_mut(mid);

        (
            Self::SelfMutView::<'_>::create_from(container_left, self_meta.clone()),
            Self::SelfMutView::<'_>::create_from(container_right, self_meta),
        )
    }

    fn get_mut(&mut self, index: usize) -> Self::EntityMutView<'_> {
        // index here is the number of ref_elements, we need to multiply by the size of a single
        // element to know where to reference the underlying container

        let start = index * self.get_entity_view_pod_size();
        let stop = start + self.get_entity_view_pod_size();
        let meta = self.get_entity_view_creation_metadata();

        Self::EntityMutView::<'_>::create_from(&mut self.as_mut()[start..stop], meta)
    }

    fn get_sub_mut<R: RangeBounds<usize>>(&mut self, range_bounds: R) -> Self::SelfMutView<'_> {
        let entity_start_bound = range_bounds.start_bound();
        let entity_start_index = match entity_start_bound {
            Bound::Included(&start) => start,
            Bound::Excluded(&start) => start + 1,
            Bound::Unbounded => 0,
        };

        let entity_stop_bound = range_bounds.end_bound();
        let entity_stop_index = match entity_stop_bound {
            Bound::Included(&stop) => stop + 1,
            Bound::Excluded(&stop) => stop,
            Bound::Unbounded => self.entity_count(),
        };

        let start_index = entity_start_index
            .checked_mul(self.get_entity_view_pod_size())
            .unwrap();
        let stop_index = entity_stop_index
            .checked_mul(self.get_entity_view_pod_size())
            .unwrap();

        let self_meta = self.get_self_view_creation_metadata();

        let sub_container = &mut self.as_mut()[start_index..stop_index];
        Self::SelfMutView::<'_>::create_from(sub_container, self_meta)
    }

    fn last_mut(&mut self) -> Option<Self::EntityMutView<'_>> {
        let entity_count = self.entity_count();

        if entity_count == 0 {
            None
        } else {
            Some(self.get_mut(entity_count - 1))
        }
    }

    fn chunks_mut(
        &mut self,
        chunk_size: usize,
    ) -> ChunksWrappingLendingIteratorMut<'_, Self::Element, Self::SelfMutView<'_>> {
        let entity_count = self.entity_count();

        let entity_view_pod_size = self.get_entity_view_pod_size();
        let pod_chunk_size = entity_view_pod_size.checked_mul(chunk_size).unwrap();

        let meta = self.get_self_view_creation_metadata();
        self.as_mut()
            .chunks_mut(pod_chunk_size)
            .zip(core::iter::repeat_n(meta, entity_count))
            .map(|(elt, meta)| Self::SelfMutView::<'_>::create_from(elt, meta))
    }

    fn chunks_exact_mut(
        &mut self,
        chunk_size: usize,
    ) -> ChunksExactWrappingLendingIteratorMut<'_, Self::Element, Self::SelfMutView<'_>> {
        let entity_count = self.entity_count();
        assert!(
            entity_count.is_multiple_of(chunk_size),
            "The current container has {entity_count} entities, which is not dividable by the \
            requested chunk_size: {chunk_size}, preventing chunks_exact_mut from returning an \
            iterator."
        );

        let entity_view_pod_size = self.get_entity_view_pod_size();
        let pod_chunk_size = entity_view_pod_size.checked_mul(chunk_size).unwrap();

        let meta = self.get_self_view_creation_metadata();
        self.as_mut()
            .chunks_exact_mut(pod_chunk_size)
            .zip(core::iter::repeat_n(meta, entity_count))
            .map(|(elt, meta)| Self::SelfMutView::<'_>::create_from(elt, meta))
    }

    fn reverse(&mut self) {
        let entity_view_pod_size = self.get_entity_view_pod_size();
        let container = self.as_mut();

        container.reverse();

        for entity_slot in self.as_mut().chunks_exact_mut(entity_view_pod_size) {
            entity_slot.reverse();
        }
    }

    fn par_iter_mut<'this>(
        &'this mut self,
    ) -> ParallelChunksExactWrappingLendingIteratorMut<
        'this,
        Self::Element,
        Self::EntityMutView<'this>,
    >
    where
        Self::Element: Sync + Send,
        Self::EntityMutView<'this>: Send,
        Self::EntityViewMetadata: Send,
    {
        let meta = self.get_entity_view_creation_metadata();
        let entity_count = self.entity_count();
        let entity_view_pod_size = self.get_entity_view_pod_size();
        self.as_mut()
            .par_chunks_exact_mut(entity_view_pod_size)
            .zip(rayon::iter::repeat_n(meta, entity_count))
            .map(|(elt, meta)| Self::EntityMutView::<'this>::create_from(elt, meta))
    }

    fn par_chunks_mut<'this>(
        &'this mut self,
        chunk_size: usize,
    ) -> ParallelChunksWrappingLendingIteratorMut<'this, Self::Element, Self::SelfMutView<'this>>
    where
        Self::Element: Sync + Send,
        Self::SelfMutView<'this>: Send,
        Self::SelfViewMetadata: Send,
    {
        let entity_count = self.entity_count();

        let entity_view_pod_size = self.get_entity_view_pod_size();
        let pod_chunk_size = entity_view_pod_size.checked_mul(chunk_size).unwrap();

        let meta = self.get_self_view_creation_metadata();
        self.as_mut()
            .par_chunks_mut(pod_chunk_size)
            .zip(rayon::iter::repeat_n(meta, entity_count))
            .map(|(elt, meta)| Self::SelfMutView::<'_>::create_from(elt, meta))
    }

    fn par_chunks_exact_mut<'this>(
        &'this mut self,
        chunk_size: usize,
    ) -> ParallelChunksExactWrappingLendingIteratorMut<'this, Self::Element, Self::SelfMutView<'this>>
    where
        Self::Element: Sync + Send,
        Self::SelfMutView<'this>: Send,
        Self::SelfViewMetadata: Send,
    {
        let entity_count = self.entity_count();
        assert!(
            entity_count.is_multiple_of(chunk_size),
            "The current container has {entity_count} entities, which is not dividable by the \
            requested chunk_size: {chunk_size}, preventing chunks_exact from returning an iterator."
        );

        let entity_view_pod_size = self.get_entity_view_pod_size();
        let pod_chunk_size = entity_view_pod_size.checked_mul(chunk_size).unwrap();

        let meta = self.get_self_view_creation_metadata();
        self.as_mut()
            .par_chunks_exact_mut(pod_chunk_size)
            .zip(rayon::iter::repeat_n(meta, entity_count))
            .map(|(elt, meta)| Self::SelfMutView::<'_>::create_from(elt, meta))
    }
}
