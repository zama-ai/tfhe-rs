use crate::core_crypto::commons::dispersion::DispersionParameter;
use crate::core_crypto::gpu::vec::CudaVec;
use crate::core_crypto::gpu::{
    convert_lwe_programmable_bootstrap_key_async, CudaModulusSwitchNoiseReductionKeyFFI,
    CudaStreams,
};
use crate::core_crypto::prelude::{
    lwe_bootstrap_key_size, Container, DecompositionBaseLog, DecompositionLevelCount,
    GlweDimension, LweBootstrapKey, LweDimension, NoiseEstimationMeasureBound, PolynomialSize,
    RSigmaFactor, UnsignedInteger, Variance,
};
use crate::shortint::server_key::ModulusSwitchNoiseReductionKey;
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct CudaModulusSwitchDriftNoiseReductionKey {
    pub modulus_switch_zeros: CudaVec<u64>,
    pub ms_bound: NoiseEstimationMeasureBound,
    pub ms_r_sigma_factor: RSigmaFactor,
    pub ms_input_variance: Variance,
    pub num_zeros: u32,
}
#[derive(Clone, Debug)]
pub enum CudaModulusSwitchNoiseReductionConfiguration {
    Drift(CudaModulusSwitchDriftNoiseReductionKey),
    Centered,
}

impl CudaModulusSwitchNoiseReductionConfiguration {
    pub fn from_modulus_switch_noise_reduction_key(
        ms_noise_red_key: &ModulusSwitchNoiseReductionKey<u64>,
        streams: &CudaStreams,
    ) -> Self {
        let h_input = ms_noise_red_key
            .modulus_switch_zeros
            .as_view()
            .into_container();
        let lwe_ciphertext_count = ms_noise_red_key.modulus_switch_zeros.lwe_ciphertext_count();

        let mut d_zeros_vec = CudaVec::new_multi_gpu(
            ms_noise_red_key.modulus_switch_zeros.lwe_size().0 * lwe_ciphertext_count.0,
            streams,
        );

        unsafe {
            d_zeros_vec.copy_from_cpu_multi_gpu_async(h_input, streams);
        }

        streams.synchronize();
        Self::Drift(CudaModulusSwitchDriftNoiseReductionKey {
            modulus_switch_zeros: d_zeros_vec,
            num_zeros: ms_noise_red_key
                .modulus_switch_zeros
                .lwe_ciphertext_count()
                .0 as u32,
            ms_bound: ms_noise_red_key.ms_bound,
            ms_r_sigma_factor: ms_noise_red_key.ms_r_sigma_factor,
            ms_input_variance: ms_noise_red_key.ms_input_variance,
        })
    }
}

pub fn prepare_cuda_ms_noise_reduction_key_ffi(
    input_ms_key: Option<&CudaModulusSwitchDriftNoiseReductionKey>,
    modulus: f64,
) -> CudaModulusSwitchNoiseReductionKeyFFI {
    input_ms_key.map_or(
        CudaModulusSwitchNoiseReductionKeyFFI {
            ptr: std::ptr::null_mut(),
            num_zeros: 0,
            ms_bound: 0.0,
            ms_r_sigma: 0.0,
            ms_input_variance: 0.0,
        },
        |ms_key| CudaModulusSwitchNoiseReductionKeyFFI {
            ptr: ms_key.modulus_switch_zeros.ptr.as_ptr(),
            num_zeros: ms_key.num_zeros,
            ms_bound: ms_key.ms_bound.0,
            ms_r_sigma: ms_key.ms_r_sigma_factor.0,
            ms_input_variance: ms_key.ms_input_variance.get_modular_variance(modulus).value,
        },
    )
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
