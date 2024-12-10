//! How to perform conversion from one version to the next.

/// This trait should be implemented for each version of the original type that is not the current
/// one. The upgrade method is called in chains until we get to the last version of the type.
pub trait Upgrade<T> {
    type Error: std::error::Error + Send + Sync + 'static;
    fn upgrade(self) -> Result<T, Self::Error>;
}
