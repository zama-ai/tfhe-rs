use crate::core_crypto::commons::traits::*;

/// A plaintext (encoded) value.
#[derive(Debug, Copy, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Plaintext<T>(pub T);

impl<'data, T> CreateFrom<&'data [T]> for Plaintext<&'data T> {
    type Metadata = ();

    #[inline]
    fn create_from(from: &[T], _: Self::Metadata) -> Plaintext<&T> {
        Plaintext(&from[0])
    }
}

impl<'data, T> CreateFrom<&'data mut [T]> for Plaintext<&'data mut T> {
    type Metadata = ();

    #[inline]
    fn create_from(from: &mut [T], _: Self::Metadata) -> Plaintext<&mut T> {
        Plaintext(&mut from[0])
    }
}

impl<T> From<Plaintext<&T>> for Plaintext<T>
where
    T: Copy,
{
    fn from(plaintext_ref: Plaintext<&T>) -> Plaintext<T> {
        Plaintext(*plaintext_ref.0)
    }
}

impl<T> From<Plaintext<&mut T>> for Plaintext<T>
where
    T: Copy,
{
    fn from(plaintext_ref: Plaintext<&mut T>) -> Plaintext<T> {
        Plaintext(*plaintext_ref.0)
    }
}
