use crate::core_crypto::commons::math::random::Seed;

/// Types that can be converted into a byte seed for the OPRF functions.
///
/// This trait abstracts over the two common ways to specify a seed for the
/// `generate_oblivious_pseudo_random*` family of functions across the
/// `shortint`, `integer` and high-level APIs:
///
/// - a [`Seed`] (a wrapper around `u128`), and
/// - any byte-like reference such as `&[u8]`, `&[u8; N]`, `&Vec<u8>` or more generally `&T` where
///   `T: AsRef<[u8]>`.
pub trait OprfSeed {
    type Bytes: AsRef<[u8]>;

    fn into_bytes(self) -> Self::Bytes;
}

impl OprfSeed for Seed {
    type Bytes = [u8; 16];

    fn into_bytes(self) -> [u8; 16] {
        self.0.to_le_bytes()
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> OprfSeed for &'a T {
    type Bytes = &'a [u8];

    fn into_bytes(self) -> &'a [u8] {
        self.as_ref()
    }
}
