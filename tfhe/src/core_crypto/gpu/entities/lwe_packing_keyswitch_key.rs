use crate::core_crypto::gpu::vec::CudaVec;
use crate::core_crypto::gpu::{convert_lwe_keyswitch_key_async, CudaStreams};
use crate::core_crypto::prelude::{
    lwe_packing_keyswitch_key_input_key_element_encrypted_size, CiphertextModulus,
    DecompositionBaseLog, DecompositionLevelCount, GlweSize, LweDimension,
    LwePackingKeyswitchKeyOwned, PolynomialSize, UnsignedInteger,
};

#[derive(Debug)]
pub struct CudaLwePackingKeyswitchKey<T: UnsignedInteger> {
    pub(crate) d_vec: CudaVec<T>,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    output_glwe_size: GlweSize,
    output_polynomial_size: PolynomialSize,
    ciphertext_modulus: CiphertextModulus<T>,
}

impl<T: UnsignedInteger> CudaLwePackingKeyswitchKey<T> {
    pub fn from_lwe_packing_keyswitch_key(
        h_ksk: &LwePackingKeyswitchKeyOwned<T>,
        streams: &CudaStreams,
    ) -> Self {
        let decomp_base_log = h_ksk.decomposition_base_log();
        let decomp_level_count = h_ksk.decomposition_level_count();
        let output_glwe_size = h_ksk.output_key_glwe_dimension().to_glwe_size();
        let output_polynomial_size = h_ksk.output_polynomial_size();
        let ciphertext_modulus = h_ksk.ciphertext_modulus();

        // Allocate memory
        let mut d_vec = CudaVec::<T>::new_multi_gpu(h_ksk.as_ref().len(), streams);

        unsafe {
            convert_lwe_keyswitch_key_async(streams, &mut d_vec, h_ksk.as_ref());
        }

        streams.synchronize();

        Self {
            d_vec,
            decomp_base_log,
            decomp_level_count,
            output_glwe_size,
            output_polynomial_size,
            ciphertext_modulus,
        }
    }

    pub(crate) fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.decomp_base_log
    }
    pub(crate) fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.decomp_level_count
    }

    pub(crate) fn output_glwe_size(&self) -> GlweSize {
        self.output_glwe_size
    }
    pub(crate) fn ciphertext_modulus(&self) -> CiphertextModulus<T> {
        self.ciphertext_modulus
    }
    pub(crate) fn output_polynomial_size(&self) -> PolynomialSize {
        self.output_polynomial_size
    }
    pub fn input_key_lwe_dimension(&self) -> LweDimension {
        LweDimension(
            self.d_vec.len
                / lwe_packing_keyswitch_key_input_key_element_encrypted_size(
                    self.decomp_level_count,
                    self.output_glwe_size,
                    self.output_polynomial_size,
                ),
        )
    }
}
