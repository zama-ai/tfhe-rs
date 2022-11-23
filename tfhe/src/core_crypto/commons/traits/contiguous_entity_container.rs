use super::create_from::*;

type WrappingFunction<'data, PODElement, WrappingType> = fn(
    (
        &'data [PODElement],
        <WrappingType as CreateFrom<&'data [PODElement]>>::Metadata,
    ),
) -> WrappingType;

type WrappingLendingIterator<'data, PODElement, WrappingType> = std::iter::Map<
    std::iter::Zip<
        std::slice::Chunks<'data, PODElement>,
        std::iter::Repeat<<WrappingType as CreateFrom<&'data [PODElement]>>::Metadata>,
    >,
    WrappingFunction<'data, PODElement, WrappingType>,
>;

// This is required as at the moment it's not possible to reverse a zip containing a repeat, though
// it is perfectly legal to zip a reversed repeat
type RevWrappingLendingIterator<'data, PODElement, WrappingType> = std::iter::Map<
    std::iter::Zip<
        std::iter::Rev<std::slice::Chunks<'data, PODElement>>,
        std::iter::Repeat<<WrappingType as CreateFrom<&'data [PODElement]>>::Metadata>,
    >,
    WrappingFunction<'data, PODElement, WrappingType>,
>;

type WrappingFunctionMut<'data, PODElement, WrappingType> = fn(
    (
        &'data mut [PODElement],
        <WrappingType as CreateFrom<&'data mut [PODElement]>>::Metadata,
    ),
) -> WrappingType;

type WrappingLendingIteratorMut<'data, PODElement, WrappingType> = std::iter::Map<
    std::iter::Zip<
        std::slice::ChunksMut<'data, PODElement>,
        std::iter::Repeat<<WrappingType as CreateFrom<&'data mut [PODElement]>>::Metadata>,
    >,
    WrappingFunctionMut<'data, PODElement, WrappingType>,
>;

// This is required as at the moment it's not possible to reverse a zip containing a repeat, though
// it is perfectly legal to zip a reversed repeat
type RevWrappingLendingIteratorMut<'data, PODElement, WrappingType> = std::iter::Map<
    std::iter::Zip<
        std::iter::Rev<std::slice::ChunksMut<'data, PODElement>>,
        std::iter::Repeat<<WrappingType as CreateFrom<&'data mut [PODElement]>>::Metadata>,
    >,
    WrappingFunctionMut<'data, PODElement, WrappingType>,
>;

pub trait ContiguousEntityContainer: AsRef<[Self::PODElement]> {
    /// Plain Old Data type used to store data, e.g. u8/u16/u32/u64
    type PODElement;

    /// Concrete type of the metadata used to create an ElementView
    type ElementViewMetadata: Clone + Copy;

    /// Element of the container that can be a complex type (like an LWE ciphertext) using a
    /// reference to a container of Plain Old Data (e.g. u32/u64) to store its data
    type ElementView<'this>: CreateFrom<
        &'this [Self::PODElement],
        Metadata = Self::ElementViewMetadata,
    >
    where
        Self: 'this;

    /// Concrete type of the metadata used to create a view from the container from Self
    type SelfViewMetadata: Clone + Copy;

    type SelfView<'this>: CreateFrom<&'this [Self::PODElement], Metadata = Self::SelfViewMetadata>
    where
        Self: 'this;

    /// Function providing relevant metadata to convert PODEelement slices to wrapper/complex types
    fn get_element_view_creation_metadata(&self) -> Self::ElementViewMetadata;

    fn get_element_view_pod_size(&self) -> usize;

    fn iter(&self) -> WrappingLendingIterator<'_, Self::PODElement, Self::ElementView<'_>> {
        let meta = self.get_element_view_creation_metadata();
        let element_view_pod_size = self.get_element_view_pod_size();
        self.as_ref()
            .chunks(element_view_pod_size)
            .zip(std::iter::repeat(meta))
            .map(|(elt, meta)| Self::ElementView::<'_>::create_from(elt, meta))
    }

    fn rev_iter(&self) -> RevWrappingLendingIterator<'_, Self::PODElement, Self::ElementView<'_>> {
        let meta = self.get_element_view_creation_metadata();
        let element_view_pod_size = self.get_element_view_pod_size();
        self.as_ref()
            .chunks(element_view_pod_size)
            .rev()
            .zip(std::iter::repeat(meta))
            .map(|(elt, meta)| Self::ElementView::<'_>::create_from(elt, meta))
    }

    fn get_self_view_creation_metadata(&self) -> Self::SelfViewMetadata;

    fn split_at(&self, mid: usize) -> (Self::SelfView<'_>, Self::SelfView<'_>) {
        // mid here is the number of ref_elements, we need to multiply by the size of a single
        // element to know where to split the underlying container

        let mid = mid * self.get_element_view_pod_size();
        let self_meta = self.get_self_view_creation_metadata();

        let (container_left, container_right) = self.as_ref().split_at(mid);

        (
            Self::SelfView::<'_>::create_from(container_left, self_meta),
            Self::SelfView::<'_>::create_from(container_right, self_meta),
        )
    }
}

pub trait ContiguousEntityContainerMut:
    ContiguousEntityContainer + AsMut<[Self::PODElement]>
{
    /// The assumption here is that views and mut views use the same metadata to be created
    type ElementMutView<'this>: CreateFrom<
        &'this mut [Self::PODElement],
        Metadata = Self::ElementViewMetadata,
    >
    where
        Self: 'this;

    /// The assumption here is that views and mut views use the same metadata to be created
    type SelfMutView<'this>: CreateFrom<
        &'this mut [Self::PODElement],
        Metadata = Self::SelfViewMetadata,
    >
    where
        Self: 'this;

    fn iter_mut(
        &mut self,
    ) -> WrappingLendingIteratorMut<'_, Self::PODElement, Self::ElementMutView<'_>> {
        let meta = self.get_element_view_creation_metadata();
        let element_mut_view_pod_size = self.get_element_view_pod_size();
        self.as_mut()
            .chunks_mut(element_mut_view_pod_size)
            .zip(std::iter::repeat(meta))
            .map(|(elt, meta)| Self::ElementMutView::<'_>::create_from(elt, meta))
    }

    fn rev_iter_mut(
        &mut self,
    ) -> RevWrappingLendingIteratorMut<'_, Self::PODElement, Self::ElementMutView<'_>> {
        let meta = self.get_element_view_creation_metadata();
        let element_mut_view_pod_size = self.get_element_view_pod_size();
        self.as_mut()
            .chunks_mut(element_mut_view_pod_size)
            .rev()
            .zip(std::iter::repeat(meta))
            .map(|(elt, meta)| Self::ElementMutView::<'_>::create_from(elt, meta))
    }

    fn split_at_mut(&mut self, mid: usize) -> (Self::SelfMutView<'_>, Self::SelfMutView<'_>) {
        // mid here is the number of ref_elements, we need to multiply by the size of a single
        // element to know where to split the underlying container

        let mid = mid * self.get_element_view_pod_size();
        let self_meta = self.get_self_view_creation_metadata();

        let (container_left, container_right) = self.as_mut().split_at_mut(mid);

        (
            Self::SelfMutView::<'_>::create_from(container_left, self_meta),
            Self::SelfMutView::<'_>::create_from(container_right, self_meta),
        )
    }
}
