//! Module containing the definition of the Plaintext.

use tfhe_versionable::Versionize;

use crate::core_crypto::backward_compatibility::entities::plaintext::PlaintextVersions;
use crate::core_crypto::commons::traits::*;

/// A plaintext (encoded) value.
#[derive(Debug, Copy, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(PlaintextVersions)]
pub struct Plaintext<T: Numeric>(pub T);
/// An immutable reference to a plaintext (encoded) value.
///
/// Can be converted to a plaintext via a call to `into`
/// ```rust
/// use tfhe::core_crypto::entities::*;
///
/// pub fn takes_plaintext(plain: Plaintext<u64>) {
///     println!("{plain:?}");
/// }
///
/// let encoded_msg = 3u64 << 60;
///
/// // A plaintext containing a reference can be returned by iterators for example, here is how
/// // to convert them painlessly.
/// let ref_plaintext = PlaintextRef(&encoded_msg);
/// takes_plaintext(ref_plaintext.into());
/// ```
pub struct PlaintextRef<'data, T: Numeric>(pub &'data T);
/// A mutable reference to a plaintext (encoded) value.
///
/// Can be converted to a plaintext via a call to `into`
/// ```rust
/// use tfhe::core_crypto::entities::*;
///
/// pub fn takes_plaintext(plain: Plaintext<u64>) {
///     println!("{plain:?}");
/// }
///
/// let mut encoded_msg = 3u64 << 60;
///
/// // A plaintext containing a reference can be returned by iterators for example, here is how
/// // to convert them painlessly.
/// let ref_plaintext = PlaintextRefMut(&mut encoded_msg);
/// takes_plaintext(ref_plaintext.into());
/// ```
pub struct PlaintextRefMut<'data, T: Numeric>(pub &'data mut T);

impl<'data, T: Numeric> CreateFrom<&'data [T]> for PlaintextRef<'data, T> {
    type Metadata = ();

    #[inline]
    fn create_from(from: &[T], _: Self::Metadata) -> PlaintextRef<'_, T> {
        PlaintextRef(&from[0])
    }
}

impl<'data, T: Numeric> CreateFrom<&'data mut [T]> for PlaintextRefMut<'data, T> {
    type Metadata = ();

    #[inline]
    fn create_from(from: &mut [T], _: Self::Metadata) -> PlaintextRefMut<'_, T> {
        PlaintextRefMut(&mut from[0])
    }
}

impl<T: Numeric + Copy> From<PlaintextRef<'_, T>> for Plaintext<T> {
    fn from(plaintext_ref: PlaintextRef<T>) -> Self {
        Self(*plaintext_ref.0)
    }
}

impl<T: Numeric + Copy> From<PlaintextRefMut<'_, T>> for Plaintext<T> {
    fn from(plaintext_ref: PlaintextRefMut<T>) -> Self {
        Self(*plaintext_ref.0)
    }
}
