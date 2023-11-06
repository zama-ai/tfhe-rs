//! Module containing the definition of the Cleartext.

use crate::core_crypto::commons::traits::*;

/// A cleartext, not encoded, value.
#[derive(Debug, Copy, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Cleartext<T: Numeric>(pub T);
/// An immutable reference to a cleartext value.
///
/// Can be converted to a cleartext via a call to `into`
/// ```
/// use tfhe::core_crypto::entities::*;
///
/// pub fn takes_cleartext(clear: Cleartext<u64>) {
///     println!("{clear:?}");
/// }
///
/// let encoded_msg = 3u64 << 60;
///
/// // A cleartext containing a reference can be returned by iterators for example, here is how
/// // to convert them painlessly.
/// let ref_cleartext = CleartextRef(&encoded_msg);
/// takes_cleartext(ref_cleartext.into());
/// ```
pub struct CleartextRef<'data, T: Numeric>(pub &'data T);
/// A mutable reference to a cleartext (encoded) value.
///
/// Can be converted to a cleartext via a call to `into`
/// ```
/// use tfhe::core_crypto::entities::*;
///
/// pub fn takes_cleartext(clear: Cleartext<u64>) {
///     println!("{clear:?}");
/// }
///
/// let mut encoded_msg = 3u64 << 60;
///
/// // A cleartext containing a reference can be returned by iterators for example, here is how
/// // to convert them painlessly.
/// let ref_cleartext = CleartextRefMut(&mut encoded_msg);
/// takes_cleartext(ref_cleartext.into());
/// ```
pub struct CleartextRefMut<'data, T: Numeric>(pub &'data mut T);

impl<'data, T: Numeric> CreateFrom<&'data [T]> for CleartextRef<'data, T> {
    type Metadata = ();

    #[inline]
    fn create_from(from: &[T], _: Self::Metadata) -> CleartextRef<'_, T> {
        CleartextRef(&from[0])
    }
}

impl<'data, T: Numeric> CreateFrom<&'data mut [T]> for CleartextRefMut<'data, T> {
    type Metadata = ();

    #[inline]
    fn create_from(from: &mut [T], _: Self::Metadata) -> CleartextRefMut<'_, T> {
        CleartextRefMut(&mut from[0])
    }
}

impl<T: Numeric + Copy> From<CleartextRef<'_, T>> for Cleartext<T> {
    fn from(cleartext_ref: CleartextRef<T>) -> Self {
        Self(*cleartext_ref.0)
    }
}

impl<T: Numeric + Copy> From<CleartextRefMut<'_, T>> for Cleartext<T> {
    fn from(cleartext_ref: CleartextRefMut<T>) -> Self {
        Self(*cleartext_ref.0)
    }
}
