use crate::core_crypto::gpu::entities::lwe_bootstrap_key::CudaBskParams;
use crate::core_crypto::gpu::vec::CudaVec;
use crate::core_crypto::gpu::{
    convert_lwe_multi_bit_programmable_bootstrap_key_async, CudaStreams,
};
use crate::core_crypto::prelude::{
    lwe_multi_bit_bootstrap_key_size, Container, DecompositionBaseLog, DecompositionLevelCount,
    GlweDimension, LweBskGroupingFactor, LweDimension, LweMultiBitBootstrapKey, PolynomialSize,
    UnsignedInteger,
};
use tfhe_cuda_backend::bindings::{CudaLweBootstrapKeyParamsFFI, PBS_TYPE_MULTI_BIT};

/// A structure representing a vector of GLWE ciphertexts with 64 bits of precision on the GPU.
#[derive(Debug)]
pub struct CudaLweMultiBitBootstrapKey<Scalar: UnsignedInteger> {
    // Pointers to GPU data
    pub(crate) d_vec: CudaVec<Scalar>,
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
    // Grouping factor
    pub(crate) grouping_factor: LweBskGroupingFactor,
}

impl<Scalar: UnsignedInteger> CudaLweMultiBitBootstrapKey<Scalar> {
    pub fn from_lwe_multi_bit_bootstrap_key<InputBskCont: Container<Element = Scalar>>(
        bsk: &LweMultiBitBootstrapKey<InputBskCont>,
        streams: &CudaStreams,
    ) -> Self {
        let input_lwe_dimension = bsk.input_lwe_dimension();
        let polynomial_size = bsk.polynomial_size();
        let decomp_level_count = bsk.decomposition_level_count();
        let decomp_base_log = bsk.decomposition_base_log();
        let glwe_dimension = bsk.glwe_size().to_glwe_dimension();
        let grouping_factor = bsk.grouping_factor();

        // Allocate memory
        let mut d_vec = CudaVec::<InputBskCont::Element>::new_multi_gpu(
            lwe_multi_bit_bootstrap_key_size(
                input_lwe_dimension,
                glwe_dimension.to_glwe_size(),
                polynomial_size,
                decomp_level_count,
                grouping_factor,
            )
            .unwrap(),
            streams,
        );
        // Copy to the GPU
        unsafe {
            convert_lwe_multi_bit_programmable_bootstrap_key_async(
                streams,
                &mut d_vec,
                bsk.as_ref(),
                input_lwe_dimension,
                glwe_dimension,
                decomp_level_count,
                polynomial_size,
                grouping_factor,
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
            grouping_factor,
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

    pub(crate) fn grouping_factor(&self) -> LweBskGroupingFactor {
        self.grouping_factor
    }
}

impl<Scalar: UnsignedInteger> CudaBskParams for CudaLweMultiBitBootstrapKey<Scalar> {
    fn params_ffi(&self) -> CudaLweBootstrapKeyParamsFFI {
        CudaLweBootstrapKeyParamsFFI {
            input_lwe_dimension: u32::try_from(self.input_lwe_dimension.0).unwrap(),
            glwe_dimension: u32::try_from(self.glwe_dimension.0).unwrap(),
            polynomial_size: u32::try_from(self.polynomial_size.0).unwrap(),
            base_log: u32::try_from(self.decomp_base_log.0).unwrap(),
            level_count: u32::try_from(self.decomp_level_count.0).unwrap(),
            big_lwe_dimension: u32::try_from(
                self.glwe_dimension
                    .to_equivalent_lwe_dimension(self.polynomial_size)
                    .0,
            )
            .unwrap(),
            pbs_type: PBS_TYPE_MULTI_BIT,
            grouping_factor: u32::try_from(self.grouping_factor.0).unwrap(),
        }
    }
}
