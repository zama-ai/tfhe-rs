//! This module defines the [`CudaLweCompactCiphertextList`],
//! a CUDA variant of the `LweCompactCiphertextList`.

use crate::core_crypto::gpu::vec::CudaVec;
use crate::core_crypto::gpu::{CudaLweList, CudaStreams};
use crate::core_crypto::prelude::{
    lwe_compact_ciphertext_list_size, CiphertextModulus, Container, LweCiphertextCount,
    LweCompactCiphertextList, LweDimension, UnsignedInteger,
};

pub struct CudaLweCompactCiphertextList<T: UnsignedInteger>(pub CudaLweList<T>);

impl<T: UnsignedInteger> CudaLweCompactCiphertextList<T> {
    pub fn duplicate(&self, streams: &CudaStreams) -> Self {
        Self(self.0.duplicate(streams))
    }

    pub fn from_d_vec(
        d_vec: CudaVec<T>,
        lwe_ciphertext_count: LweCiphertextCount,
        lwe_dimension: LweDimension,
        ciphertext_modulus: CiphertextModulus<T>,
    ) -> Self {
        assert_eq!(
            d_vec.len(),
            lwe_ciphertext_count.0 * lwe_dimension.to_lwe_size().0
        );
        Self(CudaLweList {
            d_vec,
            lwe_ciphertext_count,
            lwe_dimension,
            ciphertext_modulus,
        })
    }

    pub fn from_lwe_compact_ciphertext_list<C: Container<Element = T>>(
        h_ct: &LweCompactCiphertextList<C>,
        streams: &CudaStreams,
    ) -> Self {
        let res = unsafe { Self::from_lwe_compact_ciphertext_list_async(h_ct, streams) };
        streams.synchronize();
        res
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronized
    pub unsafe fn from_lwe_compact_ciphertext_list_async<C: Container<Element = T>>(
        h_ct: &LweCompactCiphertextList<C>,
        streams: &CudaStreams,
    ) -> Self {
        let lwe_dimension = h_ct.lwe_size().to_lwe_dimension();
        let lwe_ciphertext_count = h_ct.lwe_ciphertext_count();
        let ciphertext_modulus = h_ct.ciphertext_modulus();

        // Copy to the GPU
        let h_input = h_ct.as_ref();
        let expected_container_len =
            lwe_compact_ciphertext_list_size(lwe_dimension, lwe_ciphertext_count);
        assert_eq!(
            h_input.container_len(),
            expected_container_len,
            "Expected container for be of length {}, got length {}",
            expected_container_len,
            h_input.container_len()
        );

        let mut d_vec = CudaVec::new_async(expected_container_len, streams, 0);
        d_vec.copy_from_cpu_async(h_input.as_ref(), streams, 0);
        let cuda_lwe_list = CudaLweList {
            d_vec,
            lwe_ciphertext_count,
            lwe_dimension,
            ciphertext_modulus,
        };
        Self(cuda_lwe_list)
    }

    pub fn to_lwe_compact_ciphertext_list(
        &self,
        streams: &CudaStreams,
    ) -> LweCompactCiphertextList<Vec<T>> {
        let lwe_dimension = self.0.lwe_dimension;
        let lwe_ciphertext_count = self.0.lwe_ciphertext_count;
        let ciphertext_modulus = self.0.ciphertext_modulus;

        let expected_container_len =
            lwe_compact_ciphertext_list_size(lwe_dimension, lwe_ciphertext_count);
        assert_eq!(
            self.0.d_vec.len, expected_container_len,
            "Expected container for be of length {}, got length {}",
            expected_container_len, self.0.d_vec.len
        );

        let mut container: Vec<T> = vec![T::ZERO; expected_container_len];

        unsafe {
            self.0
                .d_vec
                .copy_to_cpu_async(container.as_mut_slice(), streams, 0);
        }
        streams.synchronize();

        LweCompactCiphertextList::from_container(
            container,
            lwe_dimension.to_lwe_size(),
            lwe_ciphertext_count,
            ciphertext_modulus,
        )
    }
}
