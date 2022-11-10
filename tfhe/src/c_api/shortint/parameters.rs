use crate::c_api::utils::*;
use crate::core_crypto::prelude::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
    StandardDev,
};
use std::os::raw::c_int;

use crate::shortint;

pub struct ShortintParameters(pub(in crate::c_api) shortint::parameters::Parameters);

#[no_mangle]
pub unsafe extern "C" fn shortint_get_parameters(
    message_bits: u32,
    carry_bits: u32,
    result: *mut *mut ShortintParameters,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();
        let params: Option<_> = match (message_bits, carry_bits) {
            (1, 0) => Some(crate::shortint::parameters::PARAM_MESSAGE_1_CARRY_0),
            (1, 1) => Some(crate::shortint::parameters::PARAM_MESSAGE_1_CARRY_1),
            (2, 0) => Some(crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_0),
            (1, 2) => Some(crate::shortint::parameters::PARAM_MESSAGE_1_CARRY_2),
            (2, 1) => Some(crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_1),
            (3, 0) => Some(crate::shortint::parameters::PARAM_MESSAGE_3_CARRY_0),
            (1, 3) => Some(crate::shortint::parameters::PARAM_MESSAGE_1_CARRY_3),
            (2, 2) => Some(crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2),
            (3, 1) => Some(crate::shortint::parameters::PARAM_MESSAGE_3_CARRY_1),
            (4, 0) => Some(crate::shortint::parameters::PARAM_MESSAGE_4_CARRY_0),
            (1, 4) => Some(crate::shortint::parameters::PARAM_MESSAGE_1_CARRY_4),
            (2, 3) => Some(crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_3),
            (3, 2) => Some(crate::shortint::parameters::PARAM_MESSAGE_3_CARRY_2),
            (4, 1) => Some(crate::shortint::parameters::PARAM_MESSAGE_4_CARRY_1),
            (5, 0) => Some(crate::shortint::parameters::PARAM_MESSAGE_5_CARRY_0),
            (1, 5) => Some(crate::shortint::parameters::PARAM_MESSAGE_1_CARRY_5),
            (2, 4) => Some(crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_4),
            (3, 3) => Some(crate::shortint::parameters::PARAM_MESSAGE_3_CARRY_3),
            (4, 2) => Some(crate::shortint::parameters::PARAM_MESSAGE_4_CARRY_2),
            (5, 1) => Some(crate::shortint::parameters::PARAM_MESSAGE_5_CARRY_1),
            (6, 0) => Some(crate::shortint::parameters::PARAM_MESSAGE_6_CARRY_0),
            (1, 6) => Some(crate::shortint::parameters::PARAM_MESSAGE_1_CARRY_6),
            (2, 5) => Some(crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_5),
            (3, 4) => Some(crate::shortint::parameters::PARAM_MESSAGE_3_CARRY_4),
            (4, 3) => Some(crate::shortint::parameters::PARAM_MESSAGE_4_CARRY_3),
            (5, 2) => Some(crate::shortint::parameters::PARAM_MESSAGE_5_CARRY_2),
            (6, 1) => Some(crate::shortint::parameters::PARAM_MESSAGE_6_CARRY_1),
            (7, 0) => Some(crate::shortint::parameters::PARAM_MESSAGE_7_CARRY_0),
            (1, 7) => Some(crate::shortint::parameters::PARAM_MESSAGE_1_CARRY_7),
            (2, 6) => Some(crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_6),
            (3, 5) => Some(crate::shortint::parameters::PARAM_MESSAGE_3_CARRY_5),
            (4, 4) => Some(crate::shortint::parameters::PARAM_MESSAGE_4_CARRY_4),
            (5, 3) => Some(crate::shortint::parameters::PARAM_MESSAGE_5_CARRY_3),
            (6, 2) => Some(crate::shortint::parameters::PARAM_MESSAGE_6_CARRY_2),
            (7, 1) => Some(crate::shortint::parameters::PARAM_MESSAGE_7_CARRY_1),
            (8, 0) => Some(crate::shortint::parameters::PARAM_MESSAGE_8_CARRY_0),
            _ => None,
        };

        match params {
            Some(params) => {
                let params = Box::new(ShortintParameters(params));
                *result = Box::into_raw(params);
            }
            None => *result = std::ptr::null_mut(),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_create_parameters(
    lwe_dimension: usize,
    glwe_dimension: usize,
    polynomial_size: usize,
    lwe_modular_std_dev: f64,
    glwe_modular_std_dev: f64,
    pbs_base_log: usize,
    pbs_level: usize,
    ks_base_log: usize,
    ks_level: usize,
    pfks_level: usize,
    pfks_base_log: usize,
    pfks_modular_std_dev: f64,
    cbs_level: usize,
    cbs_base_log: usize,
    message_modulus: usize,
    carry_modulus: usize,
    result: *mut *mut ShortintParameters,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let heap_allocated_parameters =
            Box::new(ShortintParameters(shortint::parameters::Parameters {
                lwe_dimension: LweDimension(lwe_dimension),
                glwe_dimension: GlweDimension(glwe_dimension),
                polynomial_size: PolynomialSize(polynomial_size),
                lwe_modular_std_dev: StandardDev(lwe_modular_std_dev),
                glwe_modular_std_dev: StandardDev(glwe_modular_std_dev),
                pbs_base_log: DecompositionBaseLog(pbs_base_log),
                pbs_level: DecompositionLevelCount(pbs_level),
                ks_base_log: DecompositionBaseLog(ks_base_log),
                ks_level: DecompositionLevelCount(ks_level),
                pfks_level: DecompositionLevelCount(pfks_level),
                pfks_base_log: DecompositionBaseLog(pfks_base_log),
                pfks_modular_std_dev: StandardDev(pfks_modular_std_dev),
                cbs_level: DecompositionLevelCount(cbs_level),
                cbs_base_log: DecompositionBaseLog(cbs_base_log),
                message_modulus: crate::shortint::parameters::MessageModulus(message_modulus),
                carry_modulus: crate::shortint::parameters::CarryModulus(carry_modulus),
            }));

        *result = Box::into_raw(heap_allocated_parameters);
    })
}
