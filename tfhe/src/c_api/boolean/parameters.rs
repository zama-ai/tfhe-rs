use crate::c_api::utils::*;
use crate::core_crypto::commons::dispersion::StandardDev;
use crate::core_crypto::commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
};
use std::os::raw::c_int;

use crate::boolean;

pub struct BooleanParameters(pub(in crate::c_api) boolean::parameters::BooleanParameters);

#[no_mangle]
pub unsafe extern "C" fn boolean_get_parameters(
    boolean_parameters_set: c_int,
    result: *mut *mut BooleanParameters,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        let boolean_parameters_set_as_enum =
            BooleanParametersSet::try_from(boolean_parameters_set).unwrap();

        let boolean_parameters = Box::new(BooleanParameters::from(boolean_parameters_set_as_enum));

        *result = Box::into_raw(boolean_parameters);
    })
}

#[no_mangle]
pub unsafe extern "C" fn boolean_create_parameters(
    lwe_dimension: usize,
    glwe_dimension: usize,
    polynomial_size: usize,
    lwe_modular_std_dev: f64,
    glwe_modular_std_dev: f64,
    pbs_base_log: usize,
    pbs_level: usize,
    ks_base_log: usize,
    ks_level: usize,
    result_parameters: *mut *mut BooleanParameters,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result_parameters).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result_parameters = std::ptr::null_mut();

        let heap_allocated_parameters =
            Box::new(BooleanParameters(boolean::parameters::BooleanParameters {
                lwe_dimension: LweDimension(lwe_dimension),
                glwe_dimension: GlweDimension(glwe_dimension),
                polynomial_size: PolynomialSize(polynomial_size),
                lwe_modular_std_dev: StandardDev(lwe_modular_std_dev),
                glwe_modular_std_dev: StandardDev(glwe_modular_std_dev),
                pbs_base_log: DecompositionBaseLog(pbs_base_log),
                pbs_level: DecompositionLevelCount(pbs_level),
                ks_base_log: DecompositionBaseLog(ks_base_log),
                ks_level: DecompositionLevelCount(ks_level),
            }));

        *result_parameters = Box::into_raw(heap_allocated_parameters);
    })
}

pub(in crate::c_api) enum BooleanParametersSet {
    DefaultParameters,
    TfheLibParameters,
}

pub const BOOLEAN_PARAMETERS_SET_DEFAULT_PARAMETERS: c_int = 0;
pub const BOOLEAN_PARAMETERS_SET_TFHE_LIB_PARAMETERS: c_int = 1;

impl TryFrom<c_int> for BooleanParametersSet {
    type Error = String;

    fn try_from(value: c_int) -> Result<Self, Self::Error> {
        match value {
            BOOLEAN_PARAMETERS_SET_DEFAULT_PARAMETERS => {
                Ok(BooleanParametersSet::DefaultParameters)
            }
            BOOLEAN_PARAMETERS_SET_TFHE_LIB_PARAMETERS => {
                Ok(BooleanParametersSet::TfheLibParameters)
            }
            _ => Err(format!(
                "Invalid value '{value}' for BooleansParametersSet, use \
                BOOLEAN_PARAMETERS_SET constants"
            )),
        }
    }
}

impl From<BooleanParametersSet> for BooleanParameters {
    fn from(boolean_parameters_set: BooleanParametersSet) -> Self {
        match boolean_parameters_set {
            BooleanParametersSet::DefaultParameters => {
                BooleanParameters(boolean::parameters::DEFAULT_PARAMETERS)
            }
            BooleanParametersSet::TfheLibParameters => {
                BooleanParameters(boolean::parameters::TFHE_LIB_PARAMETERS)
            }
        }
    }
}
