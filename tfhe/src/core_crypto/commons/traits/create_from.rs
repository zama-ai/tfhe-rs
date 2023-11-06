//! Module with primitives pertaining to generic entity creations.

/// Trait to be able to create structs in contexts where the concrete type may not be known ahead of
/// time.
pub trait CreateFrom<T> {
    /// Concrete type containing enough information to instantiate a new T.
    type Metadata: Clone + Copy;

    /// Instantiate a new T using the associated metadata type.
    fn create_from(from: T, meta: Self::Metadata) -> Self;
}

/// A dummy placeholder type that can be used in traits requiring [`CreateFrom`] if using an actual
/// type does not make sense.
pub struct DummyCreateFrom {}

impl<'data, T> CreateFrom<&'data [T]> for DummyCreateFrom {
    type Metadata = ();

    #[inline]
    fn create_from(_: &'data [T], _: Self::Metadata) -> Self {
        Self {}
    }
}

impl<'data, T> CreateFrom<&'data mut [T]> for DummyCreateFrom {
    type Metadata = ();

    #[inline]
    fn create_from(_: &'data mut [T], _: Self::Metadata) -> Self {
        Self {}
    }
}
