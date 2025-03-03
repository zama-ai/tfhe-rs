use crate::c_api::utils::*;
use std::os::raw::c_int;

/// w0, w1, w2, w3 are words in little endian order
/// using two's complement representation
#[repr(C)]
#[derive(Copy, Clone)]
pub struct I256 {
    pub w0: u64,
    pub w1: u64,
    pub w2: u64,
    pub w3: u64,
}

impl From<crate::integer::I256> for I256 {
    fn from(value: crate::integer::I256) -> Self {
        Self {
            w0: value.0[0],
            w1: value.0[1],
            w2: value.0[2],
            w3: value.0[3],
        }
    }
}

impl From<I256> for crate::integer::I256 {
    fn from(value: I256) -> Self {
        Self([value.w0, value.w1, value.w2, value.w3])
    }
}

/// Creates a I256 from little endian bytes
///
/// len must be 32
#[no_mangle]
pub unsafe extern "C" fn i256_from_little_endian_bytes(
    input: *const u8,
    len: usize,
    result: *mut I256,
) -> c_int {
    catch_panic(|| {
        let mut inner = crate::integer::I256::default();

        let input = std::slice::from_raw_parts(input, len);
        inner.copy_from_le_byte_slice(input);

        *result = I256::from(inner);
    })
}

/// Creates a I256 from big endian bytes
///
/// len must be 32
#[no_mangle]
pub unsafe extern "C" fn i256_from_big_endian_bytes(
    input: *const u8,
    len: usize,
    result: *mut I256,
) -> c_int {
    catch_panic(|| {
        let mut inner = crate::integer::I256::default();

        let input = std::slice::from_raw_parts(input, len);
        inner.copy_from_be_byte_slice(input);

        *result = I256::from(inner);
    })
}

/// len must be 32
#[no_mangle]
pub unsafe extern "C" fn i256_little_endian_bytes(
    input: I256,
    result: *mut u8,
    len: usize,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        let bytes = std::slice::from_raw_parts_mut(result, len);
        crate::integer::I256::from(input).copy_to_le_byte_slice(bytes);
    })
}

/// len must be 32
#[no_mangle]
pub unsafe extern "C" fn i256_big_endian_bytes(input: I256, result: *mut u8, len: usize) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        let bytes = std::slice::from_raw_parts_mut(result, len);
        crate::integer::I256::from(input).copy_to_be_byte_slice(bytes);
    })
}
