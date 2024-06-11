use crate::c_api::utils::*;
use std::os::raw::c_int;

#[derive(Copy, Clone)]
#[repr(C)]
pub struct U512 {
    words: [u64; 8],
}

impl From<crate::integer::bigint::U512> for U512 {
    fn from(value: crate::integer::bigint::U512) -> Self {
        Self { words: value.0 }
    }
}

impl From<U512> for crate::integer::bigint::U512 {
    fn from(value: U512) -> Self {
        Self(value.words)
    }
}

/// Creates a U512 from little endian bytes
///
/// len must be 64
#[no_mangle]
pub unsafe extern "C" fn U512_from_little_endian_bytes(
    input: *const u8,
    len: usize,
    result: *mut U512,
) -> c_int {
    catch_panic(|| {
        let mut inner = crate::integer::bigint::U512::default();

        let input = std::slice::from_raw_parts(input, len);
        inner.copy_from_le_byte_slice(input);

        *result = U512::from(inner);
    })
}

/// Creates a U512 from big endian bytes
///
/// len must be 64
#[no_mangle]
pub unsafe extern "C" fn U512_from_big_endian_bytes(
    input: *const u8,
    len: usize,
    result: *mut U512,
) -> c_int {
    catch_panic(|| {
        let mut inner = crate::integer::bigint::U512::default();

        let input = std::slice::from_raw_parts(input, len);
        inner.copy_from_be_byte_slice(input);

        *result = U512::from(inner);
    })
}

/// len must be 64
#[no_mangle]
pub unsafe extern "C" fn U512_little_endian_bytes(
    input: U512,
    result: *mut u8,
    len: usize,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        let bytes = std::slice::from_raw_parts_mut(result, len);
        crate::integer::bigint::U512::from(input).copy_to_le_byte_slice(bytes);
    })
}

/// len must be 64
#[no_mangle]
pub unsafe extern "C" fn U512_big_endian_bytes(input: U512, result: *mut u8, len: usize) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        let bytes = std::slice::from_raw_parts_mut(result, len);
        crate::integer::bigint::U512::from(input).copy_to_be_byte_slice(bytes);
    })
}
