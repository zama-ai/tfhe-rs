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
pub unsafe extern "C" fn shortint_server_key_generate_pbs_accumulator(
    server_key: *const ShortintServerKey,
    accumulator_callback: LookupTableCallback,
    result: *mut *mut ShortintPBSLookupTable,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let accumulator_callback = accumulator_callback.unwrap();

        let server_key = get_ref_checked(server_key).unwrap();

        // Closure is required as extern "C" fn does not implement the Fn trait
        #[allow(clippy::redundant_closure)]
        let heap_allocated_accumulator = Box::new(ShortintPBSLookupTable(
            server_key
                .0
                .generate_accumulator(|x: u64| accumulator_callback(x)),
        ));

        *result = Box::into_raw(heap_allocated_accumulator);
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_server_key_programmable_bootstrap(
    server_key: *const ShortintServerKey,
    accumulator: *const ShortintPBSLookupTable,
    ct_in: *const ShortintCiphertext,
    result: *mut *mut ShortintCiphertext,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let server_key = get_ref_checked(server_key).unwrap();
        let accumulator = get_ref_checked(accumulator).unwrap();
        let ct_in = get_ref_checked(ct_in).unwrap();

        let res = server_key.0.apply_lookup_table(&ct_in.0, &accumulator.0);

        let heap_allocated_result = Box::new(ShortintCiphertext(res));

        *result = Box::into_raw(heap_allocated_result);
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_server_key_programmable_bootstrap_assign(
    server_key: *const ShortintServerKey,
    accumulator: *const ShortintPBSLookupTable,
    ct_in_and_result: *mut ShortintCiphertext,
) -> c_int {
    catch_panic(|| {
        let server_key = get_ref_checked(server_key).unwrap();
        let accumulator = get_ref_checked(accumulator).unwrap();
        let ct_in_and_result = get_mut_checked(ct_in_and_result).unwrap();

        server_key
            .0
            .apply_lookup_table_assign(&mut ct_in_and_result.0, &accumulator.0);
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_server_key_generate_bivariate_pbs_accumulator(
    server_key: *const ShortintServerKey,
    accumulator_callback: BivariateLookupTableCallback,
    result: *mut *mut ShortintBivariatePBSLookupTable,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let accumulator_callback = accumulator_callback.unwrap();

        let server_key = get_ref_checked(server_key).unwrap();

        // Closure is required as extern "C" fn does not implement the Fn trait
        #[allow(clippy::redundant_closure)]
        let heap_allocated_accumulator = Box::new(ShortintBivariatePBSLookupTable(
            server_key
                .0
                .generate_accumulator_bivariate(|x: u64, y: u64| accumulator_callback(x, y)),
        ));

        *result = Box::into_raw(heap_allocated_accumulator);
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_server_key_bivariate_programmable_bootstrap(
    server_key: *const ShortintServerKey,
    accumulator: *const ShortintBivariatePBSLookupTable,
    ct_left: *const ShortintCiphertext,
    ct_right: *mut ShortintCiphertext,
    result: *mut *mut ShortintCiphertext,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let server_key = get_ref_checked(server_key).unwrap();
        let accumulator = get_ref_checked(accumulator).unwrap();
        let ct_left = get_ref_checked(ct_left).unwrap();
        let ct_right = get_mut_checked(ct_right).unwrap();

        let res = crate::shortint::engine::ShortintEngine::with_thread_local_mut(|engine| {
            engine
                .smart_apply_lookup_table_bivariate(
                    &server_key.0,
                    &ct_left.0,
                    &mut ct_right.0,
                    &accumulator.0,
                )
                .unwrap()
        });

        let heap_allocated_result = Box::new(ShortintCiphertext(res));

        *result = Box::into_raw(heap_allocated_result);
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_server_key_bivariate_programmable_bootstrap_assign(
    server_key: *const ShortintServerKey,
    accumulator: *const ShortintBivariatePBSLookupTable,
    ct_left_and_result: *mut ShortintCiphertext,
    ct_right: *mut ShortintCiphertext,
) -> c_int {
    catch_panic(|| {
        let server_key = get_ref_checked(server_key).unwrap();
        let accumulator = get_ref_checked(accumulator).unwrap();
        let ct_left_and_result = get_mut_checked(ct_left_and_result).unwrap();
        let ct_right = get_mut_checked(ct_right).unwrap();

        crate::shortint::engine::ShortintEngine::with_thread_local_mut(|engine| {
            engine
                .smart_apply_lookup_table_bivariate_assign(
                    &server_key.0,
                    &mut ct_left_and_result.0,
                    &mut ct_right.0,
                    &accumulator.0,
                )
                .unwrap()
        });
    })
}
