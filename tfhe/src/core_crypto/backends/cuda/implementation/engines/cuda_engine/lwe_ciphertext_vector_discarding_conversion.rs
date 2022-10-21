use crate::core_crypto::backends::cuda::implementation::engines::{CudaEngine, CudaError};
use crate::core_crypto::backends::cuda::implementation::entities::{
    CudaLweCiphertextVector32, CudaLweCiphertextVector64,
};
use crate::core_crypto::backends::cuda::private::crypto::lwe::list::discard_copy_lwe_ciphertext_vector_from_gpu_to_cpu;
use crate::core_crypto::prelude::{LweCiphertextVectorMutView32, LweCiphertextVectorMutView64};
use crate::core_crypto::specification::engines::{
    LweCiphertextVectorDiscardingConversionEngine, LweCiphertextVectorDiscardingConversionError,
};

impl From<CudaError> for LweCiphertextVectorDiscardingConversionError<CudaError> {
    fn from(err: CudaError) -> Self {
        Self::Engine(err)
    }
}

/// # Description
/// Convert an LWE ciphertext vector with 32 bits of precision from GPU to a view on CPU.
/// The data from each GPU is copied into a part of an LweCiphertextVectorMutView32 on the CPU.
impl
    LweCiphertextVectorDiscardingConversionEngine<
        CudaLweCiphertextVector32,
        LweCiphertextVectorMutView32<'_>,
    > for CudaEngine
{
    /// # Example
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// use std::borrow::BorrowMut;
    /// let lwe_dimension = LweDimension(6);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u32 << 20; 3];
    /// let noise = Variance(2_f64.powf(-50.));
    ///
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let h_key: LweSecretKey32 = default_engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let h_plaintext_vector: PlaintextVector32 =
    ///     default_engine.create_plaintext_vector_from(&input)?;
    /// let mut h_ciphertext_vector: LweCiphertextVector32 =
    ///     default_engine.encrypt_lwe_ciphertext_vector(&h_key, &h_plaintext_vector, noise)?;
    ///
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_ciphertext_vector: CudaLweCiphertextVector32 =
    ///     cuda_engine.convert_lwe_ciphertext_vector(&h_ciphertext_vector)?;
    /// let lwe_ciphertext_count = d_ciphertext_vector.lwe_ciphertext_count();
    /// let lwe_size = d_ciphertext_vector.lwe_dimension().to_lwe_size();
    ///
    /// // Prepares the output container
    /// let mut h_raw_output_ciphertext_vector = vec![0_u32; lwe_size.0 * lwe_ciphertext_count.0];
    /// let mut h_view_output_ciphertext_vector: LweCiphertextVectorMutView32 = default_engine
    ///     .create_lwe_ciphertext_vector_from(
    ///         h_raw_output_ciphertext_vector.as_mut_slice(),
    ///         lwe_size,
    ///     )?;
    ///
    /// cuda_engine.discard_convert_lwe_ciphertext_vector(
    ///     h_view_output_ciphertext_vector.borrow_mut(),
    ///     &d_ciphertext_vector,
    /// )?;
    ///
    /// assert_eq!(
    ///     h_view_output_ciphertext_vector.lwe_dimension(),
    ///     lwe_dimension
    /// );
    /// assert_eq!(
    ///     h_view_output_ciphertext_vector.lwe_ciphertext_count(),
    ///     lwe_ciphertext_count
    /// );
    ///
    /// // Extracts the internal container
    /// let h_raw_input_ciphertext_vector: Vec<u32> =
    ///     default_engine.consume_retrieve_lwe_ciphertext_vector(h_ciphertext_vector)?;
    /// let h_raw_output_ciphertext_vector: &[u32] =
    ///     default_engine.consume_retrieve_lwe_ciphertext_vector(h_view_output_ciphertext_vector)?;
    /// assert_eq!(
    ///     h_raw_input_ciphertext_vector,
    ///     h_raw_output_ciphertext_vector.to_vec()
    /// );
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_convert_lwe_ciphertext_vector(
        &mut self,
        output: &mut LweCiphertextVectorMutView32,
        input: &CudaLweCiphertextVector32,
    ) -> Result<(), LweCiphertextVectorDiscardingConversionError<CudaError>> {
        unsafe { self.discard_convert_lwe_ciphertext_vector_unchecked(output, input) };
        Ok(())
    }

    unsafe fn discard_convert_lwe_ciphertext_vector_unchecked(
        &mut self,
        output: &mut LweCiphertextVectorMutView32,
        input: &CudaLweCiphertextVector32,
    ) {
        discard_copy_lwe_ciphertext_vector_from_gpu_to_cpu::<u32>(
            &mut output.0,
            self.get_cuda_streams(),
            &input.0,
            self.get_number_of_gpus(),
        );
    }
}

/// # Description
/// Convert an LWE ciphertext vector with 64 bits of precision from GPU to a view on CPU.
/// The data from each GPU is copied into a part of an LweCiphertextVectorMutView64 on the CPU.
impl
    LweCiphertextVectorDiscardingConversionEngine<
        CudaLweCiphertextVector64,
        LweCiphertextVectorMutView64<'_>,
    > for CudaEngine
{
    /// # Example
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// use std::borrow::BorrowMut;
    /// let lwe_dimension = LweDimension(6);
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = vec![3_u64 << 50; 3];
    /// let noise = Variance(2_f64.powf(-50.));
    ///
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let h_key: LweSecretKey64 = default_engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let h_plaintext_vector: PlaintextVector64 =
    ///     default_engine.create_plaintext_vector_from(&input)?;
    /// let mut h_ciphertext_vector: LweCiphertextVector64 =
    ///     default_engine.encrypt_lwe_ciphertext_vector(&h_key, &h_plaintext_vector, noise)?;
    ///
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_ciphertext_vector: CudaLweCiphertextVector64 =
    ///     cuda_engine.convert_lwe_ciphertext_vector(&h_ciphertext_vector)?;
    /// let lwe_ciphertext_count = d_ciphertext_vector.lwe_ciphertext_count();
    /// let lwe_size = d_ciphertext_vector.lwe_dimension().to_lwe_size();
    ///
    /// // Prepares the output container
    /// let mut h_raw_output_ciphertext_vector = vec![0_u64; lwe_size.0 * lwe_ciphertext_count.0];
    /// let mut h_view_output_ciphertext_vector: LweCiphertextVectorMutView64 = default_engine
    ///     .create_lwe_ciphertext_vector_from(
    ///         h_raw_output_ciphertext_vector.as_mut_slice(),
    ///         lwe_size,
    ///     )?;
    ///
    /// cuda_engine.discard_convert_lwe_ciphertext_vector(
    ///     h_view_output_ciphertext_vector.borrow_mut(),
    ///     &d_ciphertext_vector,
    /// )?;
    ///
    /// assert_eq!(
    ///     h_view_output_ciphertext_vector.lwe_dimension(),
    ///     lwe_dimension
    /// );
    /// assert_eq!(
    ///     h_view_output_ciphertext_vector.lwe_ciphertext_count(),
    ///     lwe_ciphertext_count
    /// );
    ///
    /// // Extracts the internal container
    /// let h_raw_input_ciphertext_vector: Vec<u64> =
    ///     default_engine.consume_retrieve_lwe_ciphertext_vector(h_ciphertext_vector)?;
    /// let h_raw_output_ciphertext_vector: &[u64] =
    ///     default_engine.consume_retrieve_lwe_ciphertext_vector(h_view_output_ciphertext_vector)?;
    /// assert_eq!(
    ///     h_raw_input_ciphertext_vector,
    ///     h_raw_output_ciphertext_vector.to_vec()
    /// );
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_convert_lwe_ciphertext_vector(
        &mut self,
        output: &mut LweCiphertextVectorMutView64,
        input: &CudaLweCiphertextVector64,
    ) -> Result<(), LweCiphertextVectorDiscardingConversionError<CudaError>> {
        unsafe { self.discard_convert_lwe_ciphertext_vector_unchecked(output, input) };
        Ok(())
    }

    unsafe fn discard_convert_lwe_ciphertext_vector_unchecked(
        &mut self,
        output: &mut LweCiphertextVectorMutView64,
        input: &CudaLweCiphertextVector64,
    ) {
        discard_copy_lwe_ciphertext_vector_from_gpu_to_cpu::<u64>(
            &mut output.0,
            self.get_cuda_streams(),
            &input.0,
            self.get_number_of_gpus(),
        );
    }
}
