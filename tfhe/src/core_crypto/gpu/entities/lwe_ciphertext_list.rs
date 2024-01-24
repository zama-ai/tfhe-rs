use crate::core_crypto::gpu::vec::CudaVec;
use crate::core_crypto::gpu::{CudaLweList, CudaStream};
use crate::core_crypto::prelude::{
    CiphertextModulus, Container, LweCiphertext, LweCiphertextCount, LweCiphertextList,
    LweDimension, LweSize, UnsignedInteger,
};

/// A structure representing a vector of LWE ciphertexts with 64 bits of precision on the GPU.
#[derive(Debug)]
pub struct CudaLweCiphertextList<T: UnsignedInteger>(pub(crate) CudaLweList<T>);

#[allow(dead_code)]
impl<T: UnsignedInteger> CudaLweCiphertextList<T> {
    pub fn new(
        lwe_dimension: LweDimension,
        lwe_ciphertext_count: LweCiphertextCount,
        ciphertext_modulus: CiphertextModulus<T>,
        stream: &CudaStream,
    ) -> Self {
        // Allocate memory in the device
        let d_vec = unsafe {
            stream.malloc_async((lwe_dimension.to_lwe_size().0 * lwe_ciphertext_count.0) as u32)
        };
        stream.synchronize();

        let cuda_lwe_list = CudaLweList {
            d_vec,
            lwe_ciphertext_count,
            lwe_dimension,
            ciphertext_modulus,
        };

        Self(cuda_lwe_list)
    }

    pub fn from_lwe_ciphertext_list<C: Container<Element = T>>(
        h_ct: &LweCiphertextList<C>,
        stream: &CudaStream,
    ) -> Self {
        let lwe_dimension = h_ct.lwe_size().to_lwe_dimension();
        let lwe_ciphertext_count = h_ct.lwe_ciphertext_count();
        let ciphertext_modulus = h_ct.ciphertext_modulus();

        // Copy to the GPU
        let h_input = h_ct.as_view().into_container();
        let mut d_vec = unsafe {
            stream.malloc_async((lwe_dimension.to_lwe_size().0 * lwe_ciphertext_count.0) as u32)
        };
        unsafe {
            stream.copy_to_gpu_async(&mut d_vec, h_input.as_ref());
            stream.synchronize();
        }
        let cuda_lwe_list = CudaLweList {
            d_vec,
            lwe_ciphertext_count,
            lwe_dimension,
            ciphertext_modulus,
        };
        Self(cuda_lwe_list)
    }

    pub fn from_cuda_vec(
        d_vec: CudaVec<T>,
        lwe_ciphertext_count: LweCiphertextCount,
        ciphertext_modulus: CiphertextModulus<T>,
    ) -> Self {
        let lwe_dimension = LweSize(d_vec.len() / lwe_ciphertext_count.0).to_lwe_dimension();
        let cuda_lwe_list = CudaLweList {
            d_vec,
            lwe_ciphertext_count,
            lwe_dimension,
            ciphertext_modulus,
        };
        Self(cuda_lwe_list)
    }

    pub fn to_lwe_ciphertext_list(&self, stream: &CudaStream) -> LweCiphertextList<Vec<T>> {
        let lwe_ct_size = self.0.lwe_ciphertext_count.0 * self.0.lwe_dimension.to_lwe_size().0;
        let mut container: Vec<T> = vec![T::ZERO; lwe_ct_size];

        unsafe {
            stream.copy_to_cpu_async(container.as_mut_slice(), &self.0.d_vec);
            stream.synchronize();
        }

        LweCiphertextList::from_container(
            container,
            self.lwe_dimension().to_lwe_size(),
            self.ciphertext_modulus(),
        )
    }

    pub fn from_lwe_ciphertext<C: Container<Element = T>>(
        h_ct: &LweCiphertext<C>,
        stream: &CudaStream,
    ) -> Self {
        let lwe_dimension = h_ct.lwe_size().to_lwe_dimension();
        let lwe_ciphertext_count = LweCiphertextCount(1);
        let ciphertext_modulus = h_ct.ciphertext_modulus();

        // Copy to the GPU
        let mut d_vec = unsafe { stream.malloc_async((lwe_dimension.to_lwe_size().0) as u32) };
        unsafe {
            stream.copy_to_gpu_async(&mut d_vec, h_ct.as_ref());
        }
        stream.synchronize();

        let cuda_lwe_list = CudaLweList {
            d_vec,
            lwe_ciphertext_count,
            lwe_dimension,
            ciphertext_modulus,
        };
        Self(cuda_lwe_list)
    }

    pub fn into_lwe_ciphertext(&self, stream: &CudaStream) -> LweCiphertext<Vec<T>> {
        let lwe_ct_size = self.0.lwe_dimension.to_lwe_size().0;
        let mut container: Vec<T> = vec![T::ZERO; lwe_ct_size];

        unsafe {
            stream.copy_to_cpu_async(container.as_mut_slice(), &self.0.d_vec);
        }
        stream.synchronize();

        LweCiphertext::from_container(container, self.ciphertext_modulus())
    }

    /// ```rust
    /// use tfhe::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
    /// use tfhe::core_crypto::gpu::{CudaDevice, CudaStream};
    /// use tfhe::core_crypto::prelude::{LweCiphertextCount, LweCiphertextList};
    /// use tfhe::integer::gpu::ciphertext::CudaRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_gpu;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    /// use tfhe::shortint::CiphertextModulus;
    ///
    /// let gpu_index = 0;
    /// let device = CudaDevice::new(gpu_index);
    /// let mut stream = CudaStream::new_unchecked(device);
    ///
    /// let lwe_size = PARAM_MESSAGE_2_CARRY_2_KS_PBS.lwe_dimension.to_lwe_size();
    /// let ciphertext_modulus = PARAM_MESSAGE_2_CARRY_2_KS_PBS.ciphertext_modulus;
    /// let lwe_ciphertext_count = LweCiphertextCount(2);
    ///
    /// // Create a new LweCiphertextList
    /// let lwe_list = LweCiphertextList::new(0u64, lwe_size, lwe_ciphertext_count, ciphertext_modulus);
    ///
    /// // Copy to GPU
    /// let d_lwe_list = CudaLweCiphertextList::from_lwe_ciphertext_list(&lwe_list, &mut stream);
    /// let d_lwe_list_copied = d_lwe_list.duplicate(&mut stream);
    ///
    /// let lwe_list_copied = d_lwe_list_copied.to_lwe_ciphertext_list(&mut stream);
    ///
    /// assert_eq!(lwe_list, lwe_list_copied);
    /// ```
    pub fn duplicate(&self, stream: &CudaStream) -> Self {
        let lwe_dimension = self.lwe_dimension();
        let lwe_ciphertext_count = self.lwe_ciphertext_count();
        let ciphertext_modulus = self.ciphertext_modulus();

        // Copy to the GPU
        let mut d_vec = unsafe { stream.malloc_async(self.0.d_vec.len() as u32) };
        unsafe {
            stream.copy_gpu_to_gpu_async(&mut d_vec, &self.0.d_vec);
        }
        stream.synchronize();

        let cuda_lwe_list = CudaLweList {
            d_vec,
            lwe_ciphertext_count,
            lwe_dimension,
            ciphertext_modulus,
        };
        Self(cuda_lwe_list)
    }

    pub(crate) fn lwe_dimension(&self) -> LweDimension {
        self.0.lwe_dimension
    }

    pub(crate) fn lwe_ciphertext_count(&self) -> LweCiphertextCount {
        self.0.lwe_ciphertext_count
    }

    pub(crate) fn ciphertext_modulus(&self) -> CiphertextModulus<T> {
        self.0.ciphertext_modulus
    }
}
