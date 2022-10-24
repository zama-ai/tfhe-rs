//! Module providing some common `C` FFI utilities for key serialization and deserialization.

use crate::c_api::utils::*;
use std::os::raw::c_int;

#[repr(C)]
pub struct Buffer {
    pointer: *mut u8,
    length: usize,
}

#[repr(C)]
pub struct BufferView {
    pointer: *const u8,
    length: usize,
}

impl From<Vec<u8>> for Buffer {
    fn from(a: Vec<u8>) -> Self {
        let a = a.leak();

        Self {
            pointer: a.as_mut_ptr(),
            length: a.len(),
        }
    }
}

impl From<BufferView> for &[u8] {
    fn from(bf: BufferView) -> &'static [u8] {
        unsafe { std::slice::from_raw_parts(bf.pointer, bf.length) }
    }
}

impl From<&[u8]> for BufferView {
    fn from(a: &[u8]) -> Self {
        Self {
            pointer: a.as_ptr(),
            length: a.len(),
        }
    }
}

/// Deallocate the memory pointed to by a [`Buffer`].
///
/// The [`Buffer`] `pointer` is set to `NULL` and `length` is set to `0` to signal it was freed in
/// addition to the function's return code.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn destroy_buffer(buffer: *mut Buffer) -> c_int {
    catch_panic(|| {
        let buffer = get_mut_checked(buffer).unwrap();

        let pointer = get_mut_checked(buffer.pointer).unwrap();
        let length = buffer.length;

        // Reconstruct a vector that will be dropped so that the memory gets freed
        Vec::from_raw_parts(pointer, length, length);

        buffer.length = 0;
        buffer.pointer = std::ptr::null_mut();
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of [`destroy_buffer`].
#[no_mangle]
pub unsafe extern "C" fn destroy_buffer_unchecked(buffer: *mut Buffer) -> c_int {
    catch_panic(|| {
        let buffer = &mut (*buffer);

        let pointer = &mut (*buffer.pointer);
        let length = buffer.length;

        // Reconstruct a vector that will be dropped so that the memory gets freed
        Vec::from_raw_parts(pointer, length, length);

        buffer.length = 0;
        buffer.pointer = std::ptr::null_mut();
    })
}
