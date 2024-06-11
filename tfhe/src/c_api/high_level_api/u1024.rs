use crate::c_api::utils::*;
use std::os::raw::c_int;

#[derive(Copy, Clone)]
#[repr(C)]
pub struct U1024 {
    words: [u64; 16],
}

impl From<crate::integer::bigint::U1024> for U1024 {
    fn from(value: crate::integer::bigint::U1024) -> Self {
        Self { words: value.0 }
    }
}

impl From<U1024> for crate::integer::bigint::U1024 {
    fn from(value: U1024) -> Self {
        Self(value.words)
    }
}

/// Creates a U1024 from little endian bytes
///
/// len must be 128
#[no_mangle]
pub unsafe extern "C" fn U1024_from_little_endian_bytes(
    input: *const u8,
    len: usize,
    result: *mut U1024,
) -> c_int {
    catch_panic(|| {
        let mut inner = crate::integer::bigint::U1024::default();

        let input = std::slice::from_raw_parts(input, len);
        inner.copy_from_le_byte_slice(input);

        *result = U1024::from(inner);
    })
}

/// Creates a U1024 from big endian bytes
///
/// len must be 128
#[no_mangle]
pub unsafe extern "C" fn U1024_from_big_endian_bytes(
    input: *const u8,
    len: usize,
    result: *mut U1024,
) -> c_int {
    catch_panic(|| {
        let mut inner = crate::integer::bigint::U1024::default();

        let input = std::slice::from_raw_parts(input, len);
        inner.copy_from_be_byte_slice(input);

        *result = U1024::from(inner);
    })
}

/// len must be 128
#[no_mangle]
pub unsafe extern "C" fn U1024_little_endian_bytes(
    input: U1024,
    result: *mut u8,
    len: usize,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        let bytes = std::slice::from_raw_parts_mut(result, len);
        crate::integer::bigint::U1024::from(input).copy_to_le_byte_slice(bytes);
    })
}

/// len must be 128
#[no_mangle]
pub unsafe extern "C" fn U1024_big_endian_bytes(
    input: U1024,
    result: *mut u8,
    len: usize,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        let bytes = std::slice::from_raw_parts_mut(result, len);
        crate::integer::bigint::U1024::from(input).copy_to_be_byte_slice(bytes);
    })
}
