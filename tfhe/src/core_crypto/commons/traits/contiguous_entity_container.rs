use super::create_from::*;
use rayon::prelude::*;

type WrappingFunction<'data, Element, WrappingType> = fn(
    (
        &'data [Element],
        <WrappingType as CreateFrom<&'data [Element]>>::Metadata,
    ),
) -> WrappingType;

type WrappingLendingIterator<'data, Element, WrappingType> = std::iter::Map<
    std::iter::Zip<
        std::slice::Chunks<'data, Element>,
        itertools::RepeatN<<WrappingType as CreateFrom<&'data [Element]>>::Metadata>,
    >,
    WrappingFunction<'data, Element, WrappingType>,
>;

type ParallelWrappingLendingIterator<'data, Element, WrappingType> = rayon::iter::Map<
    rayon::iter::Zip<
        rayon::slice::Chunks<'data, Element>,
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

type WrappingLendingIteratorMut<'data, Element, WrappingType> = std::iter::Map<
    std::iter::Zip<
        std::slice::ChunksMut<'data, Element>,
        itertools::RepeatN<<WrappingType as CreateFrom<&'data mut [Element]>>::Metadata>,
    >,
    WrappingFunctionMut<'data, Element, WrappingType>,
>;

type ParallelWrappingLendingIteratorMut<'data, Element, WrappingType> = rayon::iter::Map<
    rayon::iter::Zip<
        rayon::slice::ChunksMut<'data, Element>,
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
    type EntityViewMetadata: Clone + Copy;

    /// Entity stored in the container that can be a complex type (like an
    /// [`LweCiphertext`](crate::core_crypto::entities::LweCiphertext)) using a reference to a
    /// container of [`Self::Element`] (e.g. u32/u64) to store its data.
    type EntityView<'this>: CreateFrom<&'this [Self::Element], Metadata = Self::EntityViewMetadata>
    where
        Self: 'this;

    /// Concrete type of the metadata used to create a [`Self::SelfView`].
    type SelfViewMetadata: Clone + Copy;

    /// Concrete immutable view type of the current container type, used to create sub containers.
    type SelfView<'this>: CreateFrom<&'this [Self::Element], Metadata = Self::SelfViewMetadata>
    where
        Self: 'this;

    /// Provide relevant metadata to convert [`Self::Element`] slices to wrapper/complex types.
    fn get_entity_view_creation_metadata(&self) -> Self::EntityViewMetadata;

    /// Provide the size of a single [`Self::EntityView`].
    fn get_entity_view_pod_size(&self) -> usize;

    /// Return an iterator borrowing immutably from the current contiguous container which returns
    /// [`Self::EntityView`] entities.
    fn iter(&self) -> WrappingLendingIterator<'_, Self::Element, Self::EntityView<'_>> {
        let meta = self.get_entity_view_creation_metadata();
        let entity_view_pod_size = self.get_entity_view_pod_size();
        let entity_count = self.as_ref().len() / entity_view_pod_size;
        self.as_ref()
            .chunks(entity_view_pod_size)
            .zip(itertools::repeat_n(meta, entity_count))
            .map(|(elt, meta)| Self::EntityView::<'_>::create_from(elt, meta))
    }

    /// Provide relevant metadata to create a container of the same type as [`Self`].
    fn get_self_view_creation_metadata(&self) -> Self::SelfViewMetadata;

    fn split_at(&self, mid: usize) -> (Self::SelfView<'_>, Self::SelfView<'_>) {
        // mid here is the number of ref_elements, we need to multiply by the size of a single
        // element to know where to split the underlying container

        let mid = mid * self.get_entity_view_pod_size();
        let self_meta = self.get_self_view_creation_metadata();

        let (container_left, container_right) = self.as_ref().split_at(mid);

        (
            Self::SelfView::<'_>::create_from(container_left, self_meta),
            Self::SelfView::<'_>::create_from(container_right, self_meta),
        )
    }

    fn get(&self, index: usize) -> Self::EntityView<'_> {
        // index here is the number of ref_elements, we need to multiply by the size of a single
        // element to know where to reference the underlying container

        let start = index * self.get_entity_view_pod_size();
        let stop = start + self.get_entity_view_pod_size();
        let meta = self.get_entity_view_creation_metadata();

        Self::EntityView::<'_>::create_from(&self.as_ref()[start..stop], meta)
    }

    fn chunks_exact(
        &self,
        chunk_size: usize,
    ) -> WrappingLendingIterator<'_, Self::Element, Self::SelfView<'_>> {
        let entity_view_pod_size = self.get_entity_view_pod_size();

        let entity_count = self.as_ref().len() / entity_view_pod_size;
        assert!(
            entity_count % chunk_size == 0,
            "The current container has {entity_count} entities, which is not dividable by the \
            requested chunk_size: {chunk_size}, preventing chunks_exact from returning an iterator."
        );

        let pod_chunk_size = entity_view_pod_size * chunk_size;

        let meta = self.get_self_view_creation_metadata();
        self.as_ref()
            .chunks(pod_chunk_size)
            .zip(itertools::repeat_n(meta, entity_count))
            .map(|(elt, meta)| Self::SelfView::<'_>::create_from(elt, meta))
    }

    fn par_iter<'this>(
        &'this self,
    ) -> ParallelWrappingLendingIterator<'this, Self::Element, Self::EntityView<'this>>
    where
        Self::Element: Sync,
        Self::EntityView<'this>: Send,
        Self::EntityViewMetadata: Send,
    {
        let meta = self.get_entity_view_creation_metadata();
        let entity_view_pod_size = self.get_entity_view_pod_size();
        let entity_count = self.as_ref().len() / entity_view_pod_size;
        self.as_ref()
            .par_chunks(entity_view_pod_size)
            .zip(rayon::iter::repeatn(meta, entity_count))
            .map(|(elt, meta)| Self::EntityView::<'this>::create_from(elt, meta))
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
    ) -> WrappingLendingIteratorMut<'_, Self::Element, Self::EntityMutView<'_>> {
        let meta = self.get_entity_view_creation_metadata();
        let entity_view_pod_size = self.get_entity_view_pod_size();
        let entity_count = self.as_ref().len() / entity_view_pod_size;
        self.as_mut()
            .chunks_mut(entity_view_pod_size)
            .zip(itertools::repeat_n(meta, entity_count))
            .map(|(elt, meta)| Self::EntityMutView::<'_>::create_from(elt, meta))
    }

    fn split_at_mut(&mut self, mid: usize) -> (Self::SelfMutView<'_>, Self::SelfMutView<'_>) {
        // mid here is the number of ref_elements, we need to multiply by the size of a single
        // element to know where to split the underlying container

        let mid = mid * self.get_entity_view_pod_size();
        let self_meta = self.get_self_view_creation_metadata();

        let (container_left, container_right) = self.as_mut().split_at_mut(mid);

        (
            Self::SelfMutView::<'_>::create_from(container_left, self_meta),
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

    fn chunks_exact_mut(
        &mut self,
        chunk_size: usize,
    ) -> WrappingLendingIteratorMut<'_, Self::Element, Self::SelfMutView<'_>> {
        let entity_view_pod_size = self.get_entity_view_pod_size();

        let entity_count = self.as_ref().len() / entity_view_pod_size;
        assert!(
            entity_count % chunk_size == 0,
            "The current container has {entity_count} entities, which is not dividable by the \
            requested chunk_size: {chunk_size}, preventing chunks_exact_mut from returning an \
            iterator."
        );

        let pod_chunk_size = entity_view_pod_size * chunk_size;

        let meta = self.get_self_view_creation_metadata();
        self.as_mut()
            .chunks_mut(pod_chunk_size)
            .zip(itertools::repeat_n(meta, entity_count))
            .map(|(elt, meta)| Self::SelfMutView::<'_>::create_from(elt, meta))
    }

    fn par_iter_mut<'this>(
        &'this mut self,
    ) -> ParallelWrappingLendingIteratorMut<'this, Self::Element, Self::EntityMutView<'this>>
    where
        Self::Element: Sync + Send,
        Self::EntityMutView<'this>: Send,
        Self::EntityViewMetadata: Send,
    {
        let meta = self.get_entity_view_creation_metadata();
        let entity_view_pod_size = self.get_entity_view_pod_size();
        let entity_count = self.as_ref().len() / entity_view_pod_size;
        self.as_mut()
            .par_chunks_mut(entity_view_pod_size)
            .zip(rayon::iter::repeatn(meta, entity_count))
            .map(|(elt, meta)| Self::EntityMutView::<'this>::create_from(elt, meta))
    }
}
