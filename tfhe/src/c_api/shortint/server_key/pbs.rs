use crate::c_api::utils::*;
use std::os::raw::c_int;

use super::{ShortintCiphertext, ShortintServerKey};

// This is the accepted way to declare a pointer to a C function/callback in cbindgen
pub type LookupTableCallback = Option<extern "C" fn(u64) -> u64>;
pub type BivariateLookupTableCallback = Option<extern "C" fn(u64, u64) -> u64>;

pub struct ShortintPBSLookupTable(
    pub(in crate::c_api) crate::shortint::server_key::LookupTableOwned,
);
pub struct ShortintBivariatePBSLookupTable(
    pub(in crate::c_api) crate::shortint::server_key::BivariateLookupTableOwned,
);

#[no_mangle]
pub unsafe extern "C" fn shortint_server_key_generate_pbs_lookup_table(
    server_key: *const ShortintServerKey,
    lookup_table_callback: LookupTableCallback,
    result: *mut *mut ShortintPBSLookupTable,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let lookup_table_callback = lookup_table_callback.unwrap();

        let server_key = get_ref_checked(server_key).unwrap();

        // Closure is required as extern "C" fn does not implement the Fn trait
        #[allow(clippy::redundant_closure)]
        let heap_allocated_lookup_table = Box::new(ShortintPBSLookupTable(
            server_key
                .0
                .generate_lookup_table(|x: u64| lookup_table_callback(x)),
        ));

        *result = Box::into_raw(heap_allocated_lookup_table);
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_server_key_programmable_bootstrap(
    server_key: *const ShortintServerKey,
    lookup_table: *const ShortintPBSLookupTable,
    ct_in: *const ShortintCiphertext,
    result: *mut *mut ShortintCiphertext,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let server_key = get_ref_checked(server_key).unwrap();
        let lookup_table = get_ref_checked(lookup_table).unwrap();
        let ct_in = get_ref_checked(ct_in).unwrap();

        let res = server_key.0.apply_lookup_table(&ct_in.0, &lookup_table.0);

        let heap_allocated_result = Box::new(ShortintCiphertext(res));

        *result = Box::into_raw(heap_allocated_result);
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_server_key_programmable_bootstrap_assign(
    server_key: *const ShortintServerKey,
    lookup_table: *const ShortintPBSLookupTable,
    ct_in_and_result: *mut ShortintCiphertext,
) -> c_int {
    catch_panic(|| {
        let server_key = get_ref_checked(server_key).unwrap();
        let lookup_table = get_ref_checked(lookup_table).unwrap();
        let ct_in_and_result = get_mut_checked(ct_in_and_result).unwrap();

        server_key
            .0
            .apply_lookup_table_assign(&mut ct_in_and_result.0, &lookup_table.0);
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_server_key_generate_bivariate_pbs_lookup_table(
    server_key: *const ShortintServerKey,
    lookup_table_callback: BivariateLookupTableCallback,
    result: *mut *mut ShortintBivariatePBSLookupTable,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let lookup_table_callback = lookup_table_callback.unwrap();

        let server_key = get_ref_checked(server_key).unwrap();

        // Closure is required as extern "C" fn does not implement the Fn trait
        #[allow(clippy::redundant_closure)]
        let heap_allocated_lookup_table = Box::new(ShortintBivariatePBSLookupTable(
            server_key
                .0
                .generate_lookup_table_bivariate(|x: u64, y: u64| lookup_table_callback(x, y)),
        ));

        *result = Box::into_raw(heap_allocated_lookup_table);
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_server_key_bivariate_programmable_bootstrap(
    server_key: *const ShortintServerKey,
    lookup_table: *const ShortintBivariatePBSLookupTable,
    ct_left: *const ShortintCiphertext,
    ct_right: *const ShortintCiphertext,
    result: *mut *mut ShortintCiphertext,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let server_key = get_ref_checked(server_key).unwrap();
        let lookup_table = get_ref_checked(lookup_table).unwrap();
        let ct_left = get_ref_checked(ct_left).unwrap();
        let ct_right = get_ref_checked(ct_right).unwrap();

        let res =
            server_key
                .0
                .apply_lookup_table_bivariate(&ct_left.0, &ct_right.0, &lookup_table.0);

        let heap_allocated_result = Box::new(ShortintCiphertext(res));

        *result = Box::into_raw(heap_allocated_result);
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_server_key_bivariate_programmable_bootstrap_assign(
    server_key: *const ShortintServerKey,
    lookup_table: *const ShortintBivariatePBSLookupTable,
    ct_left_and_result: *mut ShortintCiphertext,
    ct_right: *mut ShortintCiphertext,
) -> c_int {
    catch_panic(|| {
        let server_key = get_ref_checked(server_key).unwrap();
        let lookup_table = get_ref_checked(lookup_table).unwrap();
        let ct_left_and_result = get_mut_checked(ct_left_and_result).unwrap();
        let ct_right = get_mut_checked(ct_right).unwrap();
        server_key.0.apply_lookup_table_bivariate_assign(
            &mut ct_left_and_result.0,
            &mut ct_right.0,
            &lookup_table.0,
        );
    })
}
