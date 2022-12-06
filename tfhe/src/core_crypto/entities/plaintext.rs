use crate::core_crypto::commons::traits::*;

/// A plaintext (encoded) value. This may contain a reference, in that case it can be converted to a
/// plaintext containing the actual value via a call to `into`.
///
/// ```
/// use tfhe::core_crypto::entities::*;
///
/// # pub fn main() {
///
/// pub fn takes_plaintext(plain: Plaintext<u64>) {
///     println!("{plain:?}");
/// }
///
/// let encoded_msg = 3u64 << 60;
///
/// let normal_plaintext = Plaintext(encoded_msg);
/// takes_plaintext(normal_plaintext);
///
/// // A plaintext containing a reference can be returned by iterators for example, here is how
/// // to convert them painlessly.
/// let ref_plaintext = Plaintext(&encoded_msg);
/// takes_plaintext(ref_plaintext.into());
/// # }
/// ```
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
