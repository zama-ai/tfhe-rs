use crate::c_api::utils::*;
use std::os::raw::c_int;

#[derive(Copy, Clone)]
#[repr(C)]
pub struct I2048 {
    words: [u64; 32],
}

impl From<crate::integer::bigint::I2048> for I2048 {
    fn from(value: crate::integer::bigint::I2048) -> Self {
        Self { words: value.0 }
    }
}

impl From<I2048> for crate::integer::bigint::I2048 {
    fn from(value: I2048) -> Self {
        Self(value.words)
    }
}

/// Creates a I2048 from little endian bytes
///
/// len must be 256
#[no_mangle]
pub unsafe extern "C" fn I2048_from_little_endian_bytes(
    input: *const u8,
    len: usize,
    result: *mut I2048,
) -> c_int {
    catch_panic(|| {
        let mut inner = crate::integer::bigint::I2048::default();

        let input = std::slice::from_raw_parts(input, len);
        inner.copy_from_le_byte_slice(input);

        *result = I2048::from(inner);
    })
}

/// Creates a I2048 from big endian bytes
///
/// len must be 256
#[no_mangle]
pub unsafe extern "C" fn I2048_from_big_endian_bytes(
    input: *const u8,
    len: usize,
    result: *mut I2048,
) -> c_int {
    catch_panic(|| {
        let mut inner = crate::integer::bigint::I2048::default();

        let input = std::slice::from_raw_parts(input, len);
        inner.copy_from_be_byte_slice(input);

        *result = I2048::from(inner);
    })
}

/// len must be 256
#[no_mangle]
pub unsafe extern "C" fn I2048_little_endian_bytes(
    input: I2048,
    result: *mut u8,
    len: usize,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        let bytes = std::slice::from_raw_parts_mut(result, len);
        crate::integer::bigint::I2048::from(input).copy_to_le_byte_slice(bytes);
    })
}

/// len must be 256
#[no_mangle]
pub unsafe extern "C" fn I2048_big_endian_bytes(
    input: I2048,
    result: *mut u8,
    len: usize,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        let bytes = std::slice::from_raw_parts_mut(result, len);
        crate::integer::bigint::I2048::from(input).copy_to_be_byte_slice(bytes);
    })
}
