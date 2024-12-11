//! Module containing the definition of the [`CudaLweKeyswitchKey`].

use crate::core_crypto::gpu::vec::CudaVec;
use crate::core_crypto::gpu::{
    convert_lwe_keyswitch_key_async, CiphertextModulus, CudaStreams, DecompositionBaseLog,
    DecompositionLevelCount,
};
use crate::core_crypto::prelude::{
    lwe_keyswitch_key_input_key_element_encrypted_size, LweKeyswitchKeyOwned, LweSize,
    UnsignedInteger,
};

#[allow(dead_code)]
pub struct CudaLweKeyswitchKey<T: UnsignedInteger> {
    pub(crate) d_vec: CudaVec<T>,
    input_lwe_size: LweSize,
    output_lwe_size: LweSize,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    ciphertext_modulus: CiphertextModulus<T>,
}

impl<T: UnsignedInteger> CudaLweKeyswitchKey<T> {
    pub fn from_lwe_keyswitch_key(h_ksk: &LweKeyswitchKeyOwned<T>, streams: &CudaStreams) -> Self {
        let decomp_base_log = h_ksk.decomposition_base_log();
        let decomp_level_count = h_ksk.decomposition_level_count();
        let input_lwe_size = h_ksk.input_key_lwe_dimension().to_lwe_size();
        let output_lwe_size = h_ksk.output_key_lwe_dimension().to_lwe_size();
        let ciphertext_modulus = h_ksk.ciphertext_modulus();

        // Allocate memory
        let mut d_vec = CudaVec::<T>::new_multi_gpu(
            input_lwe_size.to_lwe_dimension().0
                * lwe_keyswitch_key_input_key_element_encrypted_size(
                    decomp_level_count,
                    output_lwe_size,
                ),
            streams,
        );

        unsafe {
            convert_lwe_keyswitch_key_async(streams, &mut d_vec, h_ksk.as_ref());
        }

        streams.synchronize();

        Self {
            d_vec,
            input_lwe_size,
            output_lwe_size,
            decomp_base_log,
            decomp_level_count,
            ciphertext_modulus,
        }
    }

    pub(crate) fn input_key_lwe_size(&self) -> LweSize {
        self.input_lwe_size
    }

    pub(crate) fn output_key_lwe_size(&self) -> LweSize {
        self.output_lwe_size
    }

    pub(crate) fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.decomp_base_log
    }
    pub(crate) fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.decomp_level_count
    }
}
