use crate::core_crypto::backends::cuda::engines::CudaError;
use crate::core_crypto::backends::cuda::implementation::engines::{
    check_base_log, check_glwe_dim, CudaEngine,
};
use crate::core_crypto::backends::cuda::implementation::entities::{
    CudaFourierLweBootstrapKey32, CudaFourierLweBootstrapKey64, CudaGlweCiphertextVector32,
    CudaGlweCiphertextVector64, CudaLweCiphertextVector32, CudaLweCiphertextVector64,
};
use crate::core_crypto::backends::cuda::private::crypto::bootstrap::execute_lwe_ciphertext_vector_low_latency_bootstrap_on_gpu;
use crate::core_crypto::specification::engines::{
    LweCiphertextVectorDiscardingBootstrapEngine, LweCiphertextVectorDiscardingBootstrapError,
};
use crate::core_crypto::specification::entities::LweBootstrapKeyEntity;

/// # Description
/// A discard bootstrap on a vector of input ciphertext vectors with 32 bits of precision.
/// The bootstraps are all using one cuda bootstrap key in the Fourier domain, and as
/// many lookup tables as there are input LWE ciphertexts.
impl
    LweCiphertextVectorDiscardingBootstrapEngine<
        CudaFourierLweBootstrapKey32,
        CudaGlweCiphertextVector32,
        CudaLweCiphertextVector32,
        CudaLweCiphertextVector32,
    > for CudaEngine
{
    /// # Example
    /// ```
    /// use tfhe::core_crypto::prelude::{LweCiphertextCount, LweDimension, Variance, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, PolynomialSize,
    /// };
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let (lwe_dim, lwe_dim_output, glwe_dim, poly_size) = (
    ///     LweDimension(130),
    ///     LweDimension(512),
    ///     GlweDimension(1),
    ///     PolynomialSize(512),
    /// );
    /// let log_degree = f64::log2(poly_size.0 as f64) as i32;
    /// let val: u32 = ((poly_size.0 as f64 - (10. * f64::sqrt((lwe_dim.0 as f64) / 16.0)))
    ///     * 2_f64.powi(32 - log_degree - 1)) as u32;
    /// let input = vec![val; 3];
    /// let noise = Variance(2_f64.powf(-29.));
    /// let (dec_lc, dec_bl) = (DecompositionLevelCount(3), DecompositionBaseLog(7));
    /// // An identity function is applied during the bootstrap
    /// let mut lut = vec![0u32; poly_size.0 * 3];
    /// for i in 0..poly_size.0 {
    ///     let l = (i as f64 * 2_f64.powi(32 - log_degree - 1)) as u32;
    ///     lut[i] = l;
    ///     lut[i + poly_size.0] = l;
    ///     lut[i + 2 * poly_size.0] = l;
    /// }
    ///
    /// // 1. default engine
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// // create a vector of LWE ciphertexts
    /// let h_input_key: LweSecretKey32 = default_engine.generate_new_lwe_secret_key(lwe_dim)?;
    /// let h_input_plaintext_vector: PlaintextVector32 =
    ///     default_engine.create_plaintext_vector_from(&input)?;
    /// let mut h_input_ciphertext_vector: LweCiphertextVector32 = default_engine
    ///     .encrypt_lwe_ciphertext_vector(&h_input_key, &h_input_plaintext_vector, noise)?;
    /// // create a vector of GLWE ciphertexts containing the encryptions of the LUTs
    /// let h_lut_plaintext_vector = default_engine.create_plaintext_vector_from(&lut)?;
    /// let h_lut_key: GlweSecretKey32 =
    ///     default_engine.generate_new_glwe_secret_key(glwe_dim, poly_size)?;
    /// let h_lut_vector = default_engine.encrypt_glwe_ciphertext_vector(
    ///     &h_lut_key,
    ///     &h_lut_plaintext_vector,
    ///     noise,
    /// )?;
    /// // create a BSK
    /// let h_bootstrap_key: LweBootstrapKey32 = default_engine.generate_new_lwe_bootstrap_key(
    ///     &h_input_key,
    ///     &h_lut_key,
    ///     dec_bl,
    ///     dec_lc,
    ///     noise,
    /// )?;
    /// // initialize an output LWE ciphertext vector
    /// let h_dummy_key: LweSecretKey32 = default_engine.generate_new_lwe_secret_key(lwe_dim_output)?;
    ///
    /// // 2. cuda engine
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// // convert input to GPU (split over the GPUs)
    /// let d_input_ciphertext_vector: CudaLweCiphertextVector32 =
    ///     cuda_engine.convert_lwe_ciphertext_vector(&h_input_ciphertext_vector)?;
    /// // convert accumulators to GPU
    /// let d_input_lut_vector: CudaGlweCiphertextVector32 =
    ///     cuda_engine.convert_glwe_ciphertext_vector(&h_lut_vector)?;
    /// // convert BSK to GPU (and from Standard to Fourier representations)
    /// let d_fourier_bsk: CudaFourierLweBootstrapKey32 =
    ///     cuda_engine.convert_lwe_bootstrap_key(&h_bootstrap_key)?;
    /// // launch bootstrap on GPU
    /// let h_zero_output_ciphertext_vector: LweCiphertextVector32 = default_engine
    ///     .zero_encrypt_lwe_ciphertext_vector(&h_dummy_key, noise, LweCiphertextCount(3))?;
    /// let mut d_output_ciphertext_vector: CudaLweCiphertextVector32 =
    ///     cuda_engine.convert_lwe_ciphertext_vector(&h_zero_output_ciphertext_vector)?;
    /// cuda_engine.discard_bootstrap_lwe_ciphertext_vector(
    ///     &mut d_output_ciphertext_vector,
    ///     &d_input_ciphertext_vector,
    ///     &d_input_lut_vector,
    ///     &d_fourier_bsk,
    /// )?;
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_bootstrap_lwe_ciphertext_vector(
        &mut self,
        output: &mut CudaLweCiphertextVector32,
        input: &CudaLweCiphertextVector32,
        acc: &CudaGlweCiphertextVector32,
        bsk: &CudaFourierLweBootstrapKey32,
    ) -> Result<(), LweCiphertextVectorDiscardingBootstrapError<CudaError>> {
        LweCiphertextVectorDiscardingBootstrapError::perform_generic_checks(
            output, input, acc, bsk,
        )?;
        let poly_size = bsk.polynomial_size();
        check_poly_size!(poly_size);
        let glwe_dim = bsk.glwe_dimension();
        check_glwe_dim!(glwe_dim);
        let base_log = bsk.decomposition_base_log();
        check_base_log!(base_log);
        unsafe { self.discard_bootstrap_lwe_ciphertext_vector_unchecked(output, input, acc, bsk) };
        Ok(())
    }

    unsafe fn discard_bootstrap_lwe_ciphertext_vector_unchecked(
        &mut self,
        output: &mut CudaLweCiphertextVector32,
        input: &CudaLweCiphertextVector32,
        acc: &CudaGlweCiphertextVector32,
        bsk: &CudaFourierLweBootstrapKey32,
    ) {
        execute_lwe_ciphertext_vector_low_latency_bootstrap_on_gpu::<u32>(
            self.get_cuda_streams(),
            &mut output.0,
            &input.0,
            &acc.0,
            &bsk.0,
            self.get_number_of_gpus(),
            self.get_cuda_shared_memory(),
        );
    }
}

/// # Description
/// A discard bootstrap on a vector of input ciphertext vectors with 64 bits of precision.
/// The bootstraps are all using one cuda bootstrap key in the Fourier domain, and as
/// many lookup tables as there are input LWE ciphertexts.
impl
    LweCiphertextVectorDiscardingBootstrapEngine<
        CudaFourierLweBootstrapKey64,
        CudaGlweCiphertextVector64,
        CudaLweCiphertextVector64,
        CudaLweCiphertextVector64,
    > for CudaEngine
{
    /// # Example
    /// ```
    /// use tfhe::core_crypto::prelude::{LweCiphertextCount, LweDimension, Variance, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, PolynomialSize,
    /// };
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let (lwe_dim, lwe_dim_output, glwe_dim, poly_size) = (
    ///     LweDimension(130),
    ///     LweDimension(512),
    ///     GlweDimension(1),
    ///     PolynomialSize(512),
    /// );
    /// let log_degree = f64::log2(poly_size.0 as f64) as i32;
    /// let val: u64 = ((poly_size.0 as f64 - (10. * f64::sqrt((lwe_dim.0 as f64) / 16.0)))
    ///     * 2_f64.powi(64 - log_degree - 1)) as u64;
    /// let input = vec![val; 3];
    /// let noise = Variance(2_f64.powf(-29.));
    /// let (dec_lc, dec_bl) = (DecompositionLevelCount(3), DecompositionBaseLog(7));
    /// // An identity function is applied during the bootstrap
    /// let mut lut = vec![0u64; poly_size.0 * 3];
    /// for i in 0..poly_size.0 {
    ///     let l = (i as f64 * 2_f64.powi(64 - log_degree - 1)) as u64;
    ///     lut[i] = l;
    ///     lut[i + poly_size.0] = l;
    ///     lut[i + 2 * poly_size.0] = l;
    /// }
    ///
    /// // 1. default engine
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// // create a vector of LWE ciphertexts
    /// let h_input_key: LweSecretKey64 = default_engine.generate_new_lwe_secret_key(lwe_dim)?;
    /// let h_input_plaintext_vector: PlaintextVector64 =
    ///     default_engine.create_plaintext_vector_from(&input)?;
    /// let mut h_input_ciphertext_vector: LweCiphertextVector64 = default_engine
    ///     .encrypt_lwe_ciphertext_vector(&h_input_key, &h_input_plaintext_vector, noise)?;
    /// // create a vector of GLWE ciphertexts containing the encryptions of the LUTs
    /// let h_lut_plaintext_vector = default_engine.create_plaintext_vector_from(&lut)?;
    /// let h_lut_key: GlweSecretKey64 =
    ///     default_engine.generate_new_glwe_secret_key(glwe_dim, poly_size)?;
    /// let h_lut_vector = default_engine.encrypt_glwe_ciphertext_vector(
    ///     &h_lut_key,
    ///     &h_lut_plaintext_vector,
    ///     noise,
    /// )?;
    /// // create a BSK
    /// let h_bootstrap_key: LweBootstrapKey64 = default_engine.generate_new_lwe_bootstrap_key(
    ///     &h_input_key,
    ///     &h_lut_key,
    ///     dec_bl,
    ///     dec_lc,
    ///     noise,
    /// )?;
    /// // initialize an output LWE ciphertext vector
    /// let h_dummy_key: LweSecretKey64 = default_engine.generate_new_lwe_secret_key(lwe_dim_output)?;
    ///
    /// // 2. cuda engine
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// // convert input to GPU (split over the GPUs)
    /// let d_input_ciphertext_vector: CudaLweCiphertextVector64 =
    ///     cuda_engine.convert_lwe_ciphertext_vector(&h_input_ciphertext_vector)?;
    /// // convert accumulators to GPU
    /// let d_input_lut_vector: CudaGlweCiphertextVector64 =
    ///     cuda_engine.convert_glwe_ciphertext_vector(&h_lut_vector)?;
    /// // convert BSK to GPU (and from Standard to Fourier representations)
    /// let d_fourier_bsk: CudaFourierLweBootstrapKey64 =
    ///     cuda_engine.convert_lwe_bootstrap_key(&h_bootstrap_key)?;
    /// // launch bootstrap on GPU
    /// let h_zero_output_ciphertext_vector: LweCiphertextVector64 = default_engine
    ///     .zero_encrypt_lwe_ciphertext_vector(&h_dummy_key, noise, LweCiphertextCount(3))?;
    /// let mut d_output_ciphertext_vector: CudaLweCiphertextVector64 =
    ///     cuda_engine.convert_lwe_ciphertext_vector(&h_zero_output_ciphertext_vector)?;
    /// cuda_engine.discard_bootstrap_lwe_ciphertext_vector(
    ///     &mut d_output_ciphertext_vector,
    ///     &d_input_ciphertext_vector,
    ///     &d_input_lut_vector,
    ///     &d_fourier_bsk,
    /// )?;
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_bootstrap_lwe_ciphertext_vector(
        &mut self,
        output: &mut CudaLweCiphertextVector64,
        input: &CudaLweCiphertextVector64,
        acc: &CudaGlweCiphertextVector64,
        bsk: &CudaFourierLweBootstrapKey64,
    ) -> Result<(), LweCiphertextVectorDiscardingBootstrapError<CudaError>> {
        LweCiphertextVectorDiscardingBootstrapError::perform_generic_checks(
            output, input, acc, bsk,
        )?;
        let poly_size = bsk.polynomial_size();
        check_poly_size!(poly_size);
        let glwe_dim = bsk.glwe_dimension();
        check_glwe_dim!(glwe_dim);
        let base_log = bsk.decomposition_base_log();
        check_base_log!(base_log);
        unsafe { self.discard_bootstrap_lwe_ciphertext_vector_unchecked(output, input, acc, bsk) };
        Ok(())
    }

    unsafe fn discard_bootstrap_lwe_ciphertext_vector_unchecked(
        &mut self,
        output: &mut CudaLweCiphertextVector64,
        input: &CudaLweCiphertextVector64,
        acc: &CudaGlweCiphertextVector64,
        bsk: &CudaFourierLweBootstrapKey64,
    ) {
        execute_lwe_ciphertext_vector_low_latency_bootstrap_on_gpu::<u64>(
            self.get_cuda_streams(),
            &mut output.0,
            &input.0,
            &acc.0,
            &bsk.0,
            self.get_number_of_gpus(),
            self.get_cuda_shared_memory(),
        );
    }
}
