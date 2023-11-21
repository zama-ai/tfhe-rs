use crate::c_api::utils::*;
use std::os::raw::c_int;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct U256 {
    pub w0: u64,
    pub w1: u64,
    pub w2: u64,
    pub w3: u64,
}

impl From<crate::integer::U256> for U256 {
    fn from(value: crate::integer::U256) -> Self {
        Self {
            w0: value.0[0],
            w1: value.0[1],
            w2: value.0[2],
            w3: value.0[3],
        }
    }
}

impl From<U256> for crate::integer::U256 {
    fn from(value: U256) -> Self {
        Self([value.w0, value.w1, value.w2, value.w3])
    }
}

/// Creates a U256 from little endian bytes
///
/// len must be 32
#[no_mangle]
pub unsafe extern "C" fn u256_from_little_endian_bytes(
    input: *const u8,
    len: usize,
    result: *mut U256,
) -> c_int {
    catch_panic(|| {
        let mut inner = crate::integer::U256::default();

        let input = std::slice::from_raw_parts(input, len);
        inner.copy_from_le_byte_slice(input);

        *result = U256::from(inner);
    })
}

/// Creates a U256 from big endian bytes
///
/// len must be 32
#[no_mangle]
pub unsafe extern "C" fn u256_from_big_endian_bytes(
    input: *const u8,
    len: usize,
    result: *mut U256,
) -> c_int {
    catch_panic(|| {
        let mut inner = crate::integer::U256::default();

        let input = std::slice::from_raw_parts(input, len);
        inner.copy_from_be_byte_slice(input);

        *result = U256::from(inner);
    })
}

/// len must be 32
#[no_mangle]
pub unsafe extern "C" fn u256_little_endian_bytes(
    input: U256,
    result: *mut u8,
    len: usize,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        let bytes = std::slice::from_raw_parts_mut(result, len);
        crate::integer::U256::from(input).copy_to_le_byte_slice(bytes);
    })
}

/// len must be 32
#[no_mangle]
pub unsafe extern "C" fn u256_big_endian_bytes(input: U256, result: *mut u8, len: usize) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        let bytes = std::slice::from_raw_parts_mut(result, len);
        crate::integer::U256::from(input).copy_to_be_byte_slice(bytes);
    })
}
