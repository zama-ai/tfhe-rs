use crate::core_crypto::backends::cuda::engines::{CudaEngine, CudaError};
use crate::core_crypto::backends::cuda::implementation::entities::CudaGlweCiphertext64;
use crate::core_crypto::prelude::{
    GlweCiphertextDiscardingConversionError, GlweCiphertextMutView64,
};
use crate::core_crypto::specification::engines::GlweCiphertextDiscardingConversionEngine;

/// # Description
/// Convert a GLWE ciphertext vector with 64 bits of precision from GPU 0 to a view on the CPU.
impl GlweCiphertextDiscardingConversionEngine<CudaGlweCiphertext64, GlweCiphertextMutView64<'_>>
    for CudaEngine
{
    /// # Example
    /// ```
    /// use tfhe::core_crypto::prelude::{
    ///     GlweCiphertextCount, GlweDimension, PolynomialSize, Variance, *,
    /// };
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// use std::borrow::{Borrow, BorrowMut};
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// use tfhe::core_crypto::commons::numeric::CastInto;
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(3);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u64 << 20; 3];
    /// let noise = Variance(2_f64.powf(-50.));
    ///
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let h_key: GlweSecretKey64 =
    ///     default_engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let h_plaintext_vector: PlaintextVector64 =
    ///     default_engine.create_plaintext_vector_from(&input)?;
    /// let mut h_ciphertext: GlweCiphertext64 =
    ///     default_engine.encrypt_glwe_ciphertext(&h_key, &h_plaintext_vector, noise)?;
    ///
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_ciphertext: CudaGlweCiphertext64 = cuda_engine.convert_glwe_ciphertext(&h_ciphertext)?;
    ///
    /// let mut h_raw_output_ciphertext =
    ///     vec![0_u64; glwe_dimension.to_glwe_size().0 * polynomial_size.0];
    /// let mut h_view_output_ciphertext: GlweCiphertextMutView64 = default_engine
    ///     .create_glwe_ciphertext_from(h_raw_output_ciphertext.as_mut_slice(), polynomial_size)?;
    ///
    /// cuda_engine
    ///     .discard_convert_glwe_ciphertext(h_view_output_ciphertext.borrow_mut(), &d_ciphertext)?;
    ///
    /// // Extracts the internal container
    /// let h_raw_ciphertext: Vec<u64> =
    ///     default_engine.consume_retrieve_glwe_ciphertext(h_ciphertext)?;
    /// let h_raw_output_ciphertext: &[u64] =
    ///     default_engine.consume_retrieve_glwe_ciphertext(h_view_output_ciphertext)?;
    ///
    /// assert_eq!(d_ciphertext.glwe_dimension(), glwe_dimension);
    /// assert_eq!(d_ciphertext.polynomial_size(), polynomial_size);
    ///
    /// assert_eq!(h_raw_ciphertext, h_raw_output_ciphertext.to_vec());
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_convert_glwe_ciphertext(
        &mut self,
        output: &mut GlweCiphertextMutView64,
        input: &CudaGlweCiphertext64,
    ) -> Result<(), GlweCiphertextDiscardingConversionError<CudaError>> {
        GlweCiphertextDiscardingConversionError::perform_generic_checks(output, input)?;
        unsafe { self.discard_convert_glwe_ciphertext_unchecked(output, input) };
        Ok(())
    }

    unsafe fn discard_convert_glwe_ciphertext_unchecked(
        &mut self,
        output: &mut GlweCiphertextMutView64,
        input: &CudaGlweCiphertext64,
    ) {
        // Copy the data from GPU 0 back to the CPU
        let stream = &self.streams[0];
        stream.copy_to_cpu::<u64>(output.0.tensor.as_mut_container(), &input.0.d_vec);
    }
}
