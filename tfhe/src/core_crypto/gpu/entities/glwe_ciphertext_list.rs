use crate::core_crypto::gpu::{CudaGlweList, CudaStream};
use crate::core_crypto::prelude::{
    glwe_ciphertext_size, CiphertextModulus, Container, GlweCiphertext, GlweCiphertextCount,
    GlweCiphertextList, GlweDimension, PolynomialSize, UnsignedInteger,
};

/// A structure representing a vector of GLWE ciphertexts with 64 bits of precision on the GPU.
#[derive(Debug)]
pub struct CudaGlweCiphertextList<T: UnsignedInteger>(pub(crate) CudaGlweList<T>);

#[allow(dead_code)]
impl<T: UnsignedInteger> CudaGlweCiphertextList<T> {
    pub fn new(
        glwe_dimension: GlweDimension,
        polynomial_size: PolynomialSize,
        glwe_ciphertext_count: GlweCiphertextCount,
        ciphertext_modulus: CiphertextModulus<T>,
        stream: &CudaStream,
    ) -> Self {
        // Allocate memory in the device
        let d_vec = stream.malloc_async(
            (glwe_ciphertext_size(glwe_dimension.to_glwe_size(), polynomial_size)
                * glwe_ciphertext_count.0) as u32,
        );

        let cuda_glwe_list = CudaGlweList {
            d_vec,
            glwe_ciphertext_count,
            glwe_dimension,
            polynomial_size,
            ciphertext_modulus,
        };

        Self(cuda_glwe_list)
    }

    pub fn from_glwe_ciphertext_list<C: Container<Element = T>>(
        h_ct: &GlweCiphertextList<C>,
        stream: &CudaStream,
    ) -> Self {
        let glwe_dimension = h_ct.glwe_size().to_glwe_dimension();
        let glwe_ciphertext_count = h_ct.glwe_ciphertext_count();
        let polynomial_size = h_ct.polynomial_size();
        let ciphertext_modulus = h_ct.ciphertext_modulus();

        let mut d_vec = stream.malloc_async(
            (glwe_ciphertext_size(glwe_dimension.to_glwe_size(), polynomial_size)
                * glwe_ciphertext_count.0) as u32,
        );

        // Copy to the GPU
        stream.copy_to_gpu_async(&mut d_vec, h_ct.as_ref());

        let cuda_glwe_list = CudaGlweList {
            d_vec,
            glwe_ciphertext_count,
            glwe_dimension,
            polynomial_size,
            ciphertext_modulus,
        };

        Self(cuda_glwe_list)
    }

    pub(crate) fn to_glwe_ciphertext_list(
        &self,
        stream: &CudaStream,
    ) -> GlweCiphertextList<Vec<T>> {
        let glwe_ct_size = self.0.glwe_ciphertext_count.0
            * glwe_ciphertext_size(self.0.glwe_dimension.to_glwe_size(), self.0.polynomial_size);
        let mut container: Vec<T> = vec![T::ZERO; glwe_ct_size];

        stream.copy_to_cpu_async(container.as_mut_slice(), &self.0.d_vec);
        stream.synchronize();

        GlweCiphertextList::from_container(
            container,
            self.glwe_dimension().to_glwe_size(),
            self.polynomial_size(),
            self.ciphertext_modulus(),
        )
    }

    pub fn from_glwe_ciphertext<C: Container<Element = T>>(
        h_ct: &GlweCiphertext<C>,
        stream: &CudaStream,
    ) -> Self {
        let glwe_dimension = h_ct.glwe_size().to_glwe_dimension();
        let glwe_ciphertext_count = GlweCiphertextCount(1);
        let polynomial_size = h_ct.polynomial_size();
        let ciphertext_modulus = h_ct.ciphertext_modulus();

        let mut d_vec = stream.malloc_async(
            (glwe_ciphertext_size(glwe_dimension.to_glwe_size(), polynomial_size)
                * glwe_ciphertext_count.0) as u32,
        );

        // Copy to the GPU
        let h_input = h_ct.as_view().into_container();
        stream.copy_to_gpu_async(&mut d_vec, h_input.as_ref());

        let cuda_glwe_list = CudaGlweList {
            d_vec,
            glwe_ciphertext_count,
            glwe_dimension,
            polynomial_size,
            ciphertext_modulus,
        };

        Self(cuda_glwe_list)
    }

    pub(crate) fn glwe_dimension(&self) -> GlweDimension {
        self.0.glwe_dimension
    }

    pub(crate) fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size
    }

    pub(crate) fn glwe_ciphertext_count(&self) -> GlweCiphertextCount {
        self.0.glwe_ciphertext_count
    }

    pub(crate) fn ciphertext_modulus(&self) -> CiphertextModulus<T> {
        self.0.ciphertext_modulus
    }
}
