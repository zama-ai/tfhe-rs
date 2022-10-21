use crate::core_crypto::backends::cuda::engines::{CudaEngine, CudaError};
use crate::core_crypto::backends::cuda::implementation::entities::CudaGlweCiphertextVector64;
use crate::core_crypto::prelude::GlweCiphertextVectorMutView64;
use crate::core_crypto::specification::engines::{
    GlweCiphertextVectorDiscardingConversionEngine, GlweCiphertextVectorDiscardingConversionError,
};

impl From<CudaError> for GlweCiphertextVectorDiscardingConversionError<CudaError> {
    fn from(err: CudaError) -> Self {
        Self::Engine(err)
    }
}

/// # Description
/// Convert a GLWE ciphertext vector with 64 bits of precision from GPU to CPU.
/// This conversion is not necessary to run the bootstrap on the GPU.
/// It is implemented for testing purposes only.
impl
    GlweCiphertextVectorDiscardingConversionEngine<
        CudaGlweCiphertextVector64,
        GlweCiphertextVectorMutView64<'_>,
    > for CudaEngine
{
    /// # Example
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(3);
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = vec![3_u64 << 50; 6];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let h_key: GlweSecretKey64 =
    ///     default_engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let h_plaintext_vector: PlaintextVector64 =
    ///     default_engine.create_plaintext_vector_from(&input)?;
    /// let mut h_ciphertext_vector: GlweCiphertextVector64 =
    ///     default_engine.encrypt_glwe_ciphertext_vector(&h_key, &h_plaintext_vector, noise)?;
    /// let glwe_ciphertext_count = h_ciphertext_vector.glwe_ciphertext_count();
    ///
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_ciphertext_vector: CudaGlweCiphertextVector64 =
    ///     cuda_engine.convert_glwe_ciphertext_vector(&h_ciphertext_vector)?;
    /// ///
    /// // Prepares the output container
    /// let mut h_raw_output_ciphertext_vector =
    ///     vec![0_u64; (glwe_dimension.0 + 1) * polynomial_size.0 * glwe_ciphertext_count.0];
    /// let mut h_view_output_ciphertext_vector: GlweCiphertextVectorMutView64 = default_engine
    ///     .create_glwe_ciphertext_vector_from(
    ///         h_raw_output_ciphertext_vector.as_mut_slice(),
    ///         glwe_dimension,
    ///         polynomial_size,
    ///     )?;
    ///
    /// cuda_engine.discard_convert_glwe_ciphertext_vector(
    ///     &mut h_view_output_ciphertext_vector,
    ///     &d_ciphertext_vector,
    /// )?;
    ///
    /// assert_eq!(
    ///     h_view_output_ciphertext_vector.glwe_dimension(),
    ///     glwe_dimension
    /// );
    /// assert_eq!(
    ///     h_view_output_ciphertext_vector.glwe_ciphertext_count(),
    ///     glwe_ciphertext_count
    /// );
    /// assert_eq!(
    ///     h_view_output_ciphertext_vector.polynomial_size(),
    ///     polynomial_size
    /// );
    /// ///
    /// // Extracts the internal container
    /// let h_raw_input_ciphertext_vector: Vec<u64> =
    ///     default_engine.consume_retrieve_glwe_ciphertext_vector(h_ciphertext_vector)?;
    /// let h_raw_output_ciphertext_vector: &[u64] =
    ///     default_engine.consume_retrieve_glwe_ciphertext_vector(h_view_output_ciphertext_vector)?;
    ///
    /// assert_eq!(
    ///     h_raw_input_ciphertext_vector,
    ///     h_raw_output_ciphertext_vector.to_vec()
    /// );
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_convert_glwe_ciphertext_vector(
        &mut self,
        output: &mut GlweCiphertextVectorMutView64,
        input: &CudaGlweCiphertextVector64,
    ) -> Result<(), GlweCiphertextVectorDiscardingConversionError<CudaError>> {
        unsafe { self.discard_convert_glwe_ciphertext_vector_unchecked(output, input) };
        Ok(())
    }

    unsafe fn discard_convert_glwe_ciphertext_vector_unchecked(
        &mut self,
        output: &mut GlweCiphertextVectorMutView64,
        input: &CudaGlweCiphertextVector64,
    ) {
        // Copy the data from GPU 0 back to the CPU
        let stream = &self.streams[0];
        let output_container = output.0.tensor.as_mut_container();
        stream.copy_to_cpu::<u64>(output_container, input.0.d_vecs.first().unwrap());
    }
}
