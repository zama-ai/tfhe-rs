use crate::core_crypto::commons::dispersion::StandardDev;
use crate::core_crypto::commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
};

#[repr(C)]
#[derive(Copy, Clone)]
pub struct BooleanParameters {
    pub lwe_dimension: usize,
    pub glwe_dimension: usize,
    pub polynomial_size: usize,
    pub lwe_modular_std_dev: f64,
    pub glwe_modular_std_dev: f64,
    pub pbs_base_log: usize,
    pub pbs_level: usize,
    pub ks_base_log: usize,
    pub ks_level: usize,
}

impl From<BooleanParameters> for crate::boolean::parameters::BooleanParameters {
    fn from(c_params: BooleanParameters) -> Self {
        Self {
            lwe_dimension: LweDimension(c_params.lwe_dimension),
            glwe_dimension: GlweDimension(c_params.glwe_dimension),
            polynomial_size: PolynomialSize(c_params.polynomial_size),
            lwe_modular_std_dev: StandardDev(c_params.lwe_modular_std_dev),
            glwe_modular_std_dev: StandardDev(c_params.glwe_modular_std_dev),
            pbs_base_log: DecompositionBaseLog(c_params.pbs_base_log),
            pbs_level: DecompositionLevelCount(c_params.pbs_level),
            ks_base_log: DecompositionBaseLog(c_params.ks_base_log),
            ks_level: DecompositionLevelCount(c_params.ks_level),
        }
    }
}

impl From<crate::boolean::parameters::BooleanParameters> for BooleanParameters {
    fn from(rust_params: crate::boolean::parameters::BooleanParameters) -> Self {
        Self::convert(rust_params)
    }
}

impl BooleanParameters {
    const fn convert(rust_params: crate::boolean::parameters::BooleanParameters) -> Self {
        Self {
            lwe_dimension: rust_params.lwe_dimension.0,
            glwe_dimension: rust_params.glwe_dimension.0,
            polynomial_size: rust_params.polynomial_size.0,
            lwe_modular_std_dev: rust_params.lwe_modular_std_dev.0,
            glwe_modular_std_dev: rust_params.glwe_modular_std_dev.0,
            pbs_base_log: rust_params.pbs_base_log.0,
            pbs_level: rust_params.pbs_level.0,
            ks_base_log: rust_params.ks_base_log.0,
            ks_level: rust_params.ks_level.0,
        }
    }
}

#[no_mangle]
pub static BOOLEAN_PARAMETERS_SET_DEFAULT_PARAMETERS: BooleanParameters =
    BooleanParameters::convert(crate::boolean::parameters::DEFAULT_PARAMETERS);

#[no_mangle]
pub static BOOLEAN_PARAMETERS_SET_TFHE_LIB_PARAMETERS: BooleanParameters =
    BooleanParameters::convert(crate::boolean::parameters::TFHE_LIB_PARAMETERS);
