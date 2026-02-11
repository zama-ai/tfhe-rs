use crate::core_crypto::gpu::vec::CudaVec;
use crate::core_crypto::gpu::{convert_lwe_programmable_bootstrap_key_async, CudaStreams};
use crate::core_crypto::prelude::{
    lwe_bootstrap_key_size, Container, DecompositionBaseLog, DecompositionLevelCount,
    GlweDimension, LweBootstrapKey, LweDimension, PolynomialSize, UnsignedInteger,
};
use crate::shortint::server_key::ModulusSwitchConfiguration;

#[derive(Clone, Debug)]
pub enum CudaModulusSwitchNoiseReductionConfiguration {
    Centered,
}

impl CudaModulusSwitchNoiseReductionConfiguration {
    pub fn from_modulus_switch_configuration<Scalar>(
        modulus_switch_noise_reduction_key: &ModulusSwitchConfiguration<Scalar>,
    ) -> crate::Result<Option<Self>>
    where
        Scalar: UnsignedInteger,
    {
        match modulus_switch_noise_reduction_key {
            ModulusSwitchConfiguration::Standard => Ok(None),
            ModulusSwitchConfiguration::DriftTechniqueNoiseReduction(_) => Err(crate::error!(
                "GPU does not support drift noise reduction technique"
            )),
            ModulusSwitchConfiguration::CenteredMeanNoiseReduction => Ok(Some(Self::Centered)),
        }
    }
}

/// A structure representing a vector of GLWE ciphertexts with 64 bits of precision on the GPU.
#[derive(Debug)]
#[allow(dead_code)]
pub struct CudaLweBootstrapKey {
    // Pointers to GPU data
    pub(crate) d_vec: CudaVec<f64>,
    // Lwe dimension
    pub(crate) input_lwe_dimension: LweDimension,
    // Glwe dimension
    pub(crate) glwe_dimension: GlweDimension,
    // Polynomial size
    pub(crate) polynomial_size: PolynomialSize,
    // Base log
    pub(crate) decomp_base_log: DecompositionBaseLog,
    // Decomposition level count
    pub(crate) decomp_level_count: DecompositionLevelCount,
    // Pointer to the noise reduction key
    pub(crate) ms_noise_reduction_configuration:
        Option<CudaModulusSwitchNoiseReductionConfiguration>,
}

#[allow(dead_code)]
impl CudaLweBootstrapKey {
    pub fn from_lwe_bootstrap_key<InputBskCont: Container>(
        bsk: &LweBootstrapKey<InputBskCont>,
        ms_noise_reduction_configuration: Option<CudaModulusSwitchNoiseReductionConfiguration>,
        streams: &CudaStreams,
    ) -> Self
    where
        InputBskCont::Element: UnsignedInteger,
    {
        let input_lwe_dimension = bsk.input_lwe_dimension();
        let polynomial_size = bsk.polynomial_size();
        let decomp_level_count = bsk.decomposition_level_count();
        let decomp_base_log = bsk.decomposition_base_log();
        let glwe_dimension = bsk.glwe_size().to_glwe_dimension();
        let double_count = if size_of::<InputBskCont::Element>() == 16 {
            2
        } else {
            1
        };

        // Allocate memory
        let mut d_vec = CudaVec::<f64>::new_multi_gpu(
            lwe_bootstrap_key_size(
                input_lwe_dimension,
                glwe_dimension.to_glwe_size(),
                polynomial_size,
                decomp_level_count,
            ) * double_count,
            streams,
        );
        // Copy to the GPU

        unsafe {
            convert_lwe_programmable_bootstrap_key_async(
                streams,
                &mut d_vec,
                bsk.as_ref(),
                input_lwe_dimension,
                glwe_dimension,
                decomp_level_count,
                polynomial_size,
                decomp_base_log,
            );
        }

        streams.synchronize();
        Self {
            d_vec,
            input_lwe_dimension,
            glwe_dimension,
            polynomial_size,
            decomp_base_log,
            decomp_level_count,
            ms_noise_reduction_configuration,
        }
    }

    pub(crate) fn input_lwe_dimension(&self) -> LweDimension {
        self.input_lwe_dimension
    }

    pub(crate) fn output_lwe_dimension(&self) -> LweDimension {
        LweDimension(self.glwe_dimension.0 * self.polynomial_size.0)
    }

    pub(crate) fn glwe_dimension(&self) -> GlweDimension {
        self.glwe_dimension
    }

    pub(crate) fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    pub(crate) fn decomp_base_log(&self) -> DecompositionBaseLog {
        self.decomp_base_log
    }
    pub(crate) fn decomp_level_count(&self) -> DecompositionLevelCount {
        self.decomp_level_count
    }
}
