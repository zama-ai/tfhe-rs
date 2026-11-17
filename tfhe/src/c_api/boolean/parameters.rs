use crate::c_api::core_crypto::DynamicDistribution;
use crate::core_crypto::commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
};

#[repr(C)]
#[derive(Copy, Clone)]
pub enum BooleanEncryptionKeyChoice {
    BooleanEncryptionKeyChoiceBig,
    BooleanEncryptionKeyChoiceSmall,
}

impl From<BooleanEncryptionKeyChoice>
    for crate::core_crypto::commons::parameters::EncryptionKeyChoice
{
    fn from(value: BooleanEncryptionKeyChoice) -> Self {
        match value {
            BooleanEncryptionKeyChoice::BooleanEncryptionKeyChoiceBig => Self::Big,
            BooleanEncryptionKeyChoice::BooleanEncryptionKeyChoiceSmall => Self::Small,
        }
    }
}

impl BooleanEncryptionKeyChoice {
    // From::from cannot be marked as const, so we have to have
    // our own function
    const fn convert(rust_choice: crate::shortint::EncryptionKeyChoice) -> Self {
        match rust_choice {
            crate::core_crypto::commons::parameters::EncryptionKeyChoice::Big => {
                Self::BooleanEncryptionKeyChoiceBig
            }
            crate::core_crypto::commons::parameters::EncryptionKeyChoice::Small => {
                Self::BooleanEncryptionKeyChoiceSmall
            }
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct BooleanParameters {
    pub lwe_dimension: usize,
    pub glwe_dimension: usize,
    pub polynomial_size: usize,
    pub lwe_noise_distribution: DynamicDistribution,
    pub glwe_noise_distribution: DynamicDistribution,
    pub pbs_base_log: usize,
    pub pbs_level: usize,
    pub ks_base_log: usize,
    pub ks_level: usize,
    pub encryption_key_choice: BooleanEncryptionKeyChoice,
}

impl TryFrom<BooleanParameters> for crate::boolean::parameters::BooleanParameters {
    type Error = &'static str;

    fn try_from(c_params: BooleanParameters) -> Result<Self, Self::Error> {
        let BooleanParameters {
            lwe_dimension,
            glwe_dimension,
            polynomial_size,
            lwe_noise_distribution,
            glwe_noise_distribution,
            pbs_base_log,
            pbs_level,
            ks_base_log,
            ks_level,
            encryption_key_choice,
        } = c_params;

        Ok(Self {
            lwe_dimension: LweDimension(lwe_dimension),
            glwe_dimension: GlweDimension(glwe_dimension),
            polynomial_size: PolynomialSize(polynomial_size),
            lwe_noise_distribution: lwe_noise_distribution.try_into()?,
            glwe_noise_distribution: glwe_noise_distribution.try_into()?,
            pbs_base_log: DecompositionBaseLog(pbs_base_log),
            pbs_level: DecompositionLevelCount(pbs_level),
            ks_base_log: DecompositionBaseLog(ks_base_log),
            ks_level: DecompositionLevelCount(ks_level),
            encryption_key_choice: encryption_key_choice.into(),
        })
    }
}

impl From<crate::boolean::parameters::BooleanParameters> for BooleanParameters {
    fn from(rust_params: crate::boolean::parameters::BooleanParameters) -> Self {
        Self::convert(rust_params)
    }
}

impl BooleanParameters {
    const fn convert(rust_params: crate::boolean::parameters::BooleanParameters) -> Self {
        let crate::boolean::parameters::BooleanParameters {
            lwe_dimension,
            glwe_dimension,
            polynomial_size,
            lwe_noise_distribution,
            glwe_noise_distribution,
            pbs_base_log,
            pbs_level,
            ks_base_log,
            ks_level,
            encryption_key_choice,
        } = rust_params;

        Self {
            lwe_dimension: lwe_dimension.0,
            glwe_dimension: glwe_dimension.0,
            polynomial_size: polynomial_size.0,
            lwe_noise_distribution: lwe_noise_distribution.convert_to_c(),
            glwe_noise_distribution: glwe_noise_distribution.convert_to_c(),
            pbs_base_log: pbs_base_log.0,
            pbs_level: pbs_level.0,
            ks_base_log: ks_base_log.0,
            ks_level: ks_level.0,
            encryption_key_choice: BooleanEncryptionKeyChoice::convert(encryption_key_choice),
        }
    }
}

#[no_mangle]
pub static BOOLEAN_PARAMETERS_SET_DEFAULT_PARAMETERS: BooleanParameters =
    BooleanParameters::convert(crate::boolean::parameters::DEFAULT_PARAMETERS);

#[no_mangle]
pub static BOOLEAN_PARAMETERS_SET_TFHE_LIB_PARAMETERS: BooleanParameters =
    BooleanParameters::convert(crate::boolean::parameters::PARAMETERS_ERROR_PROB_2_POW_MINUS_165);

#[no_mangle]
pub static BOOLEAN_PARAMETERS_SET_DEFAULT_PARAMETERS_KS_PBS: BooleanParameters =
    BooleanParameters::convert(crate::boolean::parameters::DEFAULT_PARAMETERS_KS_PBS);

#[no_mangle]
pub static BOOLEAN_PARAMETERS_SET_TFHE_LIB_PARAMETERS_KS_PBS: BooleanParameters =
    BooleanParameters::convert(
        crate::boolean::parameters::PARAMETERS_ERROR_PROB_2_POW_MINUS_165_KS_PBS,
    );
