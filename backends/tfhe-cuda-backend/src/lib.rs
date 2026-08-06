#[allow(warnings)]
pub mod bindings;
pub mod cuda_bind;
pub mod ffi;

use bindings::{CudaRadixCiphertextFFI, VecCudaRadixCiphertextFFI};

impl VecCudaRadixCiphertextFFI {
    // Construct the boundary vec descriptor from a slice of FFI ciphertexts.
    // The caller must keep the slice alive for the duration of the FFI call —
    // enforced only informally, since the FFI call itself is already `unsafe`.
    pub fn from_ciphertexts(ffi_cts: &[CudaRadixCiphertextFFI]) -> Self {
        Self {
            ptr: ffi_cts.as_ptr() as *mut CudaRadixCiphertextFFI,
            num_ciphertexts: ffi_cts.len() as u32,
        }
    }
}
