/// Trait to be able to create structs in contexts where the concrete type may not be known ahead of
/// time.
pub trait CreateFrom<T> {
    type Metadata: Clone + Copy;

    fn create_from(from: T, meta: Self::Metadata) -> Self;
}
