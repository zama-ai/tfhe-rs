/*
 * Construction of the Box<[Ciphertext; N]> buffers carrying the cipher state
 * ----------------------------------------------------------------------------------------------- */

use rayon::prelude::*;
use tfhe::shortint::prelude::*;

/// Builds a buffer of `N` ciphertexts.
///
/// Collecting into a `Box<[T]>` and converting to `Box<[T; N]>` keeps the buffer on the heap from
/// the start, the conversion being a pointer reinterpretation. Collecting into `[T; N]` would
/// instead move every element into a stack array, and `Box::new(array)` would build that array
/// before copying it back out.
pub(crate) fn boxed_array_from_fn<const N: usize>(
    f: impl FnMut(usize) -> Ciphertext,
) -> Box<[Ciphertext; N]> {
    (0..N).map(f).collect::<Box<[_]>>().try_into().unwrap()
}

/// Rayon counterpart of [`boxed_array_from_fn`].
pub(crate) fn par_boxed_array_from_fn<const N: usize>(
    f: impl Fn(usize) -> Ciphertext + Send + Sync,
) -> Box<[Ciphertext; N]> {
    (0..N)
        .into_par_iter()
        .map(f)
        .collect::<Box<[_]>>()
        .try_into()
        .unwrap()
}
