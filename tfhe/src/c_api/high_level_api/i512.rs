use crate::c_api::utils::*;
use std::os::raw::c_int;

#[derive(Copy, Clone)]
#[repr(C)]
pub struct I512 {
    words: [u64; 8],
}

impl From<crate::integer::bigint::I512> for I512 {
    fn from(value: crate::integer::bigint::I512) -> Self {
        Self { words: value.0 }
    }
}

impl From<I512> for crate::integer::bigint::I512 {
    fn from(value: I512) -> Self {
        Self(value.words)
    }
}

/// Creates a I512 from little endian bytes
///
/// len must be 64
#[no_mangle]
pub unsafe extern "C" fn I512_from_little_endian_bytes(
    input: *const u8,
    len: usize,
    result: *mut I512,
) -> c_int {
    catch_panic(|| {
        let mut inner = crate::integer::bigint::I512::default();

        let input = std::slice::from_raw_parts(input, len);
        inner.copy_from_le_byte_slice(input);

        *result = I512::from(inner);
    })
}

/// Creates a I512 from big endian bytes
///
/// len must be 64
#[no_mangle]
pub unsafe extern "C" fn I512_from_big_endian_bytes(
    input: *const u8,
    len: usize,
    result: *mut I512,
) -> c_int {
    catch_panic(|| {
        let mut inner = crate::integer::bigint::I512::default();

        let input = std::slice::from_raw_parts(input, len);
        inner.copy_from_be_byte_slice(input);

        *result = I512::from(inner);
    })
}

/// len must be 64
#[no_mangle]
pub unsafe extern "C" fn I512_little_endian_bytes(
    input: I512,
    result: *mut u8,
    len: usize,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        let bytes = std::slice::from_raw_parts_mut(result, len);
        crate::integer::bigint::I512::from(input).copy_to_le_byte_slice(bytes);
    })
}

/// len must be 64
#[no_mangle]
pub unsafe extern "C" fn I512_big_endian_bytes(input: I512, result: *mut u8, len: usize) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        let bytes = std::slice::from_raw_parts_mut(result, len);
        crate::integer::bigint::I512::from(input).copy_to_be_byte_slice(bytes);
    })
}
