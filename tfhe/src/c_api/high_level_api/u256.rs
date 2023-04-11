use crate::c_api::utils::*;
use std::os::raw::c_int;

pub struct U256(pub(in crate::c_api) crate::integer::U256);

impl_destroy_on_type!(U256);

/// w0 is the least significant, w4 is the most significant
#[no_mangle]
pub unsafe extern "C" fn u256_from_u64_words(
    w0: u64,
    w1: u64,
    w2: u64,
    w3: u64,
    result: *mut *mut U256,
) -> c_int {
    catch_panic(|| {
        let inner = crate::integer::U256::from((w0, w1, w2, w3));
        *result = Box::into_raw(Box::new(U256(inner)));
    })
}

/// w0 is the least significant, w4 is the most significant
#[no_mangle]
pub unsafe extern "C" fn u256_to_u64_words(
    input: *const U256,
    w0: *mut u64,
    w1: *mut u64,
    w2: *mut u64,
    w3: *mut u64,
) -> c_int {
    catch_panic(|| {
        let input = get_ref_checked(input).unwrap();

        check_ptr_is_non_null_and_aligned(w0).unwrap();
        check_ptr_is_non_null_and_aligned(w1).unwrap();
        check_ptr_is_non_null_and_aligned(w2).unwrap();
        check_ptr_is_non_null_and_aligned(w3).unwrap();

        *w0 = input.0 .0[0];
        *w1 = input.0 .0[1];
        *w2 = input.0 .0[2];
        *w3 = input.0 .0[3];
    })
}

/// Creates a U256 from little endian bytes
///
/// len must be 32
#[no_mangle]
pub unsafe extern "C" fn u256_from_little_endian_bytes(
    input: *const u8,
    len: usize,
    result: *mut *mut U256,
) -> c_int {
    catch_panic(|| {
        let mut inner = crate::integer::U256::default();

        let input = std::slice::from_raw_parts(input, len);
        inner.copy_from_le_byte_slice(input);

        *result = Box::into_raw(Box::new(U256(inner)));
    })
}

/// Creates a U256 from big endian bytes
///
/// len must be 32
#[no_mangle]
pub unsafe extern "C" fn u256_from_big_endian_bytes(
    input: *const u8,
    len: usize,
    result: *mut *mut U256,
) -> c_int {
    catch_panic(|| {
        let mut inner = crate::integer::U256::default();

        let input = std::slice::from_raw_parts(input, len);
        inner.copy_from_be_byte_slice(input);

        *result = Box::into_raw(Box::new(U256(inner)));
    })
}

/// len must be 32
#[no_mangle]
pub unsafe extern "C" fn u256_little_endian_bytes(
    input: *const U256,
    result: *mut u8,
    len: usize,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();
        let input = get_ref_checked(input).unwrap();

        let bytes = std::slice::from_raw_parts_mut(result, len);
        input.0.copy_to_le_byte_slice(bytes);
    })
}

/// len must be 32
#[no_mangle]
pub unsafe extern "C" fn u256_big_endian_bytes(
    input: *const U256,
    result: *mut u8,
    len: usize,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();
        let input = get_ref_checked(input).unwrap();

        let bytes = std::slice::from_raw_parts_mut(result, len);
        input.0.copy_to_be_byte_slice(bytes);
    })
}
