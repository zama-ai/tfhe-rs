pub(crate) mod booleans;
pub(crate) mod integers;
#[cfg(test)]
pub use booleans::GpuFheBoolArrayBackend;
pub use booleans::{GpuFheBoolArray, GpuFheBoolSlice, GpuFheBoolSliceMut};
pub use integers::{
    GpuFheIntArray, GpuFheIntSlice, GpuFheIntSliceMut, GpuFheUintArray, GpuFheUintSlice,
    GpuFheUintSliceMut,
};
