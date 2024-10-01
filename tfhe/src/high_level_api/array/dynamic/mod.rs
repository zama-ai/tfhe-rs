//! This module contains the implementations
//! where the location of the values and computations can be changed/selected at runtime

pub(crate) mod booleans;
mod signed;
mod unsigned;

#[cfg(test)]
pub use signed::DynIntBackend;
pub use signed::{FheIntArray, FheIntSlice, FheIntSliceMut};

#[cfg(test)]
pub use unsigned::DynUintBackend;
pub use unsigned::{FheUintArray, FheUintSlice, FheUintSliceMut};

#[cfg(test)]
pub use booleans::DynFheBoolArrayBackend;
pub use booleans::{FheBoolArray, FheBoolSlice, FheBoolSliceMut};
