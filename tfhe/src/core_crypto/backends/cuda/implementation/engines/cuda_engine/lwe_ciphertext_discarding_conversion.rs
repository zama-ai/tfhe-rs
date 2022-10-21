use crate::core_crypto::backends::cuda::implementation::engines::{CudaEngine, CudaError};
use crate::core_crypto::backends::cuda::implementation::entities::{
    CudaLweCiphertext32, CudaLweCiphertext64,
};
use crate::core_crypto::commons::math::tensor::{AsMutSlice, AsRefSlice};
use crate::core_crypto::prelude::{
    LweCiphertext32, LweCiphertextMutView32, LweCiphertextMutView64,
};
use crate::core_crypto::specification::engines::{
    LweCiphertextDiscardingConversionEngine, LweCiphertextDiscardingConversionError,
};

/// # Description
///
/// Convert an LWE ciphertext with 32 bits of precision from GPU 0 to a view on the CPU.
impl LweCiphertextDiscardingConversionEngine<CudaLweCiphertext32, LweCiphertextMutView32<'_>>
    for CudaEngine
{
    /// # Example
    /// ```
    /// use tfhe::core_crypto::prelude::{
    ///     LweCiphertextCount, LweDimension, Variance, *,
    /// };
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// use std::borrow::BorrowMut;
    /// let lwe_dimension = LweDimension(6);
    /// // Here a hard-set encoding is applied (shift by 25 bits)
    /// let input = 3_u32 << 25;
    /// let noise = Variance(2_f64.powf(-50.));
    ///
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let h_key: LweSecretKey32 = default_engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let h_plaintext: Plaintext32 = default_engine.create_plaintext_from(&input)?;
    /// let mut h_ciphertext: LweCiphertext32 =
    ///     default_engine.encrypt_lwe_ciphertext(&h_key, &h_plaintext, noise)?;
    ///
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_ciphertext: CudaLweCiphertext32 = cuda_engine.convert_lwe_ciphertext(&h_ciphertext)?;
    ///
    /// // Prepares the output container
    /// let mut h_raw_output_ciphertext = vec![0_u32; lwe_dimension.0 + 1];
    /// let mut h_output_view_ciphertext: LweCiphertextMutView32 =
    ///     default_engine.create_lwe_ciphertext_from(h_raw_output_ciphertext.as_mut_slice())?;
    ///
    /// cuda_engine.discard_convert_lwe_ciphertext(&mut h_output_view_ciphertext, &d_ciphertext)?;
    ///
    /// assert_eq!(h_output_view_ciphertext.lwe_dimension(), lwe_dimension);
    /// // Extracts the internal container
    /// let h_raw_input_ciphertext: Vec<u32> =
    ///     default_engine.consume_retrieve_lwe_ciphertext(h_ciphertext)?;
    /// let h_raw_output_ciphertext: &[u32] =
    ///     default_engine.consume_retrieve_lwe_ciphertext(h_output_view_ciphertext)?;
    /// assert_eq!(h_raw_input_ciphertext.as_slice(), h_raw_output_ciphertext);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_convert_lwe_ciphertext(
        &mut self,
        output: &mut LweCiphertextMutView32,
        input: &CudaLweCiphertext32,
    ) -> Result<(), LweCiphertextDiscardingConversionError<CudaError>> {
        unsafe { self.discard_convert_lwe_ciphertext_unchecked(output, input) };
        Ok(())
    }

    unsafe fn discard_convert_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut LweCiphertextMutView32,
        input: &CudaLweCiphertext32,
    ) {
        let stream = &self.streams[0];
        stream.copy_to_cpu::<u32>(output.0.tensor.as_mut_slice(), &input.0.d_vec);
    }
}

/// # Description
///
/// Convert an LWE ciphertext with 32 bits of precision from GPU 0 to a ciphertext on the CPU.
impl LweCiphertextDiscardingConversionEngine<CudaLweCiphertext32, LweCiphertext32> for CudaEngine {
    /// # Example
    /// ```
    /// use tfhe::core_crypto::prelude::{
    ///     LweCiphertextCount, LweDimension, Variance, *,
    /// };
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// use std::borrow::BorrowMut;
    /// let lwe_dimension = LweDimension(6);
    /// // Here a hard-set encoding is applied (shift by 25 bits)
    /// let input = 3_u32 << 25;
    /// let noise = Variance(2_f64.powf(-50.));
    ///
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let h_key: LweSecretKey32 = default_engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let h_plaintext: Plaintext32 = default_engine.create_plaintext_from(&input)?;
    /// let mut h_ciphertext: LweCiphertext32 =
    ///     default_engine.encrypt_lwe_ciphertext(&h_key, &h_plaintext, noise)?;
    ///
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_ciphertext: CudaLweCiphertext32 = cuda_engine.convert_lwe_ciphertext(&h_ciphertext)?;
    ///
    /// // Prepares the output container
    /// let h_raw_output_ciphertext = vec![0_u32; lwe_dimension.0 + 1];
    /// let mut h_output_ciphertext: LweCiphertext32 =
    ///     default_engine.create_lwe_ciphertext_from(h_raw_output_ciphertext)?;
    ///
    /// cuda_engine.discard_convert_lwe_ciphertext(&mut h_output_ciphertext, &d_ciphertext)?;
    ///
    /// assert_eq!(h_output_ciphertext.lwe_dimension(), lwe_dimension);
    /// // Extracts the internal container
    /// let h_raw_input_ciphertext: Vec<u32> =
    ///     default_engine.consume_retrieve_lwe_ciphertext(h_ciphertext)?;
    /// let h_raw_output_ciphertext: Vec<u32> =
    ///     default_engine.consume_retrieve_lwe_ciphertext(h_output_ciphertext)?;
    /// assert_eq!(h_raw_input_ciphertext, h_raw_output_ciphertext);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_convert_lwe_ciphertext(
        &mut self,
        output: &mut LweCiphertext32,
        input: &CudaLweCiphertext32,
    ) -> Result<(), LweCiphertextDiscardingConversionError<CudaError>> {
        unsafe { self.discard_convert_lwe_ciphertext_unchecked(output, input) };
        Ok(())
    }

    unsafe fn discard_convert_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut LweCiphertext32,
        input: &CudaLweCiphertext32,
    ) {
        let stream = &self.streams[0];
        stream.copy_to_cpu::<u32>(output.0.tensor.as_mut_slice(), &input.0.d_vec);
    }
}

/// # Description
///
/// Convert an LWE ciphertext with 32 bits of precision from CPU to a ciphertext on the GPU 0.
impl LweCiphertextDiscardingConversionEngine<LweCiphertext32, CudaLweCiphertext32> for CudaEngine {
    /// # Example
    /// ```
    /// use tfhe::core_crypto::prelude::{
    ///     LweCiphertextCount, LweDimension, Variance, *,
    /// };
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// use std::borrow::BorrowMut;
    /// let lwe_dimension = LweDimension(6);
    /// // Here a hard-set encoding is applied (shift by 25 bits)
    /// let input = 3_u32 << 25;
    /// let noise = Variance(2_f64.powf(-50.));
    ///
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let h_key: LweSecretKey32 = default_engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let h_plaintext: Plaintext32 = default_engine.create_plaintext_from(&input)?;
    /// let mut h_ciphertext: LweCiphertext32 =
    ///     default_engine.encrypt_lwe_ciphertext(&h_key, &h_plaintext, noise)?;
    ///
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let mut d_ciphertext: CudaLweCiphertext32 =
    ///     cuda_engine.convert_lwe_ciphertext(&h_ciphertext)?;
    ///
    /// let h_ciphertext_out: LweCiphertext32 = cuda_engine.convert_lwe_ciphertext(&d_ciphertext)?;
    ///
    /// assert_eq!(h_ciphertext, h_ciphertext_out);
    ///
    /// // Prepare input for discarding convert
    /// let input_2 = 5_u32 << 25;
    /// let h_plaintext_2: Plaintext32 = default_engine.create_plaintext_from(&input_2)?;
    /// let mut h_ciphertext_2: LweCiphertext32 = default_engine
    ///     .trivially_encrypt_lwe_ciphertext(lwe_dimension.to_lwe_size(), &h_plaintext_2)?;
    ///
    /// cuda_engine.discard_convert_lwe_ciphertext(&mut d_ciphertext, &h_ciphertext_2)?;
    ///
    /// let h_ciphertext_out_2: LweCiphertext32 = cuda_engine.convert_lwe_ciphertext(&d_ciphertext)?;
    ///
    /// assert_eq!(h_ciphertext_2, h_ciphertext_out_2);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_convert_lwe_ciphertext(
        &mut self,
        output: &mut CudaLweCiphertext32,
        input: &LweCiphertext32,
    ) -> Result<(), LweCiphertextDiscardingConversionError<CudaError>> {
        unsafe { self.discard_convert_lwe_ciphertext_unchecked(output, input) };
        Ok(())
    }

    unsafe fn discard_convert_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut CudaLweCiphertext32,
        input: &LweCiphertext32,
    ) {
        let stream = &self.streams[0];
        stream.copy_to_gpu::<u32>(&mut output.0.d_vec, input.0.tensor.as_slice());
    }
}

/// # Description
///
/// Convert an LWE ciphertext with 64 bits of precision from GPU 0 to a view on the CPU.
impl LweCiphertextDiscardingConversionEngine<CudaLweCiphertext64, LweCiphertextMutView64<'_>>
    for CudaEngine
{
    /// # Example
    /// ```
    /// use tfhe::core_crypto::prelude::{
    ///     LweCiphertextCount, LweDimension, Variance, *,
    /// };
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// use std::borrow::BorrowMut;
    /// let lwe_dimension = LweDimension(6);
    /// // Here a hard-set encoding is applied (shift by 25 bits)
    /// let input = 3_u64 << 50;
    /// let noise = Variance(2_f64.powf(-50.));
    ///
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let h_key: LweSecretKey64 = default_engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let h_plaintext: Plaintext64 = default_engine.create_plaintext_from(&input)?;
    /// let mut h_ciphertext: LweCiphertext64 =
    ///     default_engine.encrypt_lwe_ciphertext(&h_key, &h_plaintext, noise)?;
    ///
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_ciphertext: CudaLweCiphertext64 = cuda_engine.convert_lwe_ciphertext(&h_ciphertext)?;
    ///
    /// // Prepares the output container
    /// let mut h_raw_output_ciphertext = vec![0_u64; lwe_dimension.0 + 1];
    /// let mut h_view_output_ciphertext: LweCiphertextMutView64 =
    ///     default_engine.create_lwe_ciphertext_from(h_raw_output_ciphertext.as_mut_slice())?;
    ///
    /// cuda_engine
    ///     .discard_convert_lwe_ciphertext(h_view_output_ciphertext.borrow_mut(), &d_ciphertext)?;
    ///
    /// assert_eq!(h_view_output_ciphertext.lwe_dimension(), lwe_dimension);
    /// // Extracts the internal container
    /// let h_raw_input_ciphertext: Vec<u64> =
    ///     default_engine.consume_retrieve_lwe_ciphertext(h_ciphertext)?;
    /// let h_raw_output_ciphertext: &[u64] =
    ///     default_engine.consume_retrieve_lwe_ciphertext(h_view_output_ciphertext)?;
    /// assert_eq!(h_raw_input_ciphertext, h_raw_output_ciphertext.to_vec());
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_convert_lwe_ciphertext(
        &mut self,
        output: &mut LweCiphertextMutView64,
        input: &CudaLweCiphertext64,
    ) -> Result<(), LweCiphertextDiscardingConversionError<CudaError>> {
        unsafe { self.discard_convert_lwe_ciphertext_unchecked(output, input) };
        Ok(())
    }

    unsafe fn discard_convert_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut LweCiphertextMutView64,
        input: &CudaLweCiphertext64,
    ) {
        let stream = &self.streams[0];
        stream.copy_to_cpu::<u64>(output.0.tensor.as_mut_slice(), &input.0.d_vec);
    }
}
