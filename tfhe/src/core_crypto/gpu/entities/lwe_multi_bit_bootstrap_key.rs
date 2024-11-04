use crate::core_crypto::gpu::vec::CudaVec;
use crate::core_crypto::gpu::{
    convert_lwe_multi_bit_programmable_bootstrap_key_async, CudaStreams,
};
use crate::core_crypto::prelude::{
    lwe_multi_bit_bootstrap_key_size, Container, ContiguousEntityContainerMut,
    DecompositionBaseLog, DecompositionLevelCount, GgswCiphertextList, GlweDimension,
    LweBskGroupingFactor, LweDimension, LweMultiBitBootstrapKey, PolynomialSize, UnsignedInteger,
};

/// A structure representing a vector of GLWE ciphertexts with 64 bits of precision on the GPU.
#[derive(Debug)]
pub struct CudaLweMultiBitBootstrapKey {
    // Pointers to GPU data
    pub(crate) d_vec: CudaVec<u64>,
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

impl CudaLweMultiBitBootstrapKey {
    pub fn from_lwe_multi_bit_bootstrap_key<InputBskCont: Container>(
        bsk: &LweMultiBitBootstrapKey<InputBskCont>,
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
        let grouping_factor = bsk.grouping_factor();

        // Allocate memory
        let mut d_vec = CudaVec::<u64>::new_multi_gpu(
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

        // HACK: for now the GPU has a level order that is not consistent with the CPU, so we copy
        // the key here and update the level order.
        let mut bsk_as_ggsw_list = GgswCiphertextList::from_container(
            bsk.as_ref().to_vec(),
            bsk.glwe_size(),
            bsk.polynomial_size(),
            bsk.decomposition_base_log(),
            bsk.decomposition_level_count(),
            bsk.ciphertext_modulus(),
        );

        for mut ggsw in bsk_as_ggsw_list.iter_mut() {
            // Invert level to match the expected order for GPU
            ggsw.reverse();
        }

        // Copy to the GPU
        unsafe {
            convert_lwe_multi_bit_programmable_bootstrap_key_async(
                streams,
                &mut d_vec,
                bsk_as_ggsw_list.as_ref(),
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
