use crate::core_crypto::backends::cuda::engines::CudaError;
use crate::core_crypto::backends::cuda::implementation::engines::{
    check_base_log, check_glwe_dim, CudaEngine,
};
use crate::core_crypto::backends::cuda::implementation::entities::{
    CudaFourierLweBootstrapKey32, CudaFourierLweBootstrapKey64, CudaGlweCiphertext32,
    CudaGlweCiphertext64, CudaLweCiphertext32, CudaLweCiphertext64,
};
use crate::core_crypto::backends::cuda::private::device::NumberOfSamples;
use crate::core_crypto::prelude::LweCiphertextIndex;
use crate::core_crypto::specification::engines::{
    LweCiphertextDiscardingBootstrapEngine, LweCiphertextDiscardingBootstrapError,
};
use crate::core_crypto::specification::entities::LweBootstrapKeyEntity;

impl From<CudaError> for LweCiphertextDiscardingBootstrapError<CudaError> {
    fn from(err: CudaError) -> Self {
        Self::Engine(err)
    }
}

/// # Description
/// A discard bootstrap on an input ciphertext with 32 bits of precision.
/// The input bootstrap key is in the Fourier domain.
impl
    LweCiphertextDiscardingBootstrapEngine<
        CudaFourierLweBootstrapKey32,
        CudaGlweCiphertext32,
        CudaLweCiphertext32,
        CudaLweCiphertext32,
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
    /// let input = val;
    /// let noise = Variance(2_f64.powf(-29.));
    /// let (dec_lc, dec_bl) = (DecompositionLevelCount(3), DecompositionBaseLog(7));
    /// // An identity function is applied during the bootstrap
    /// let mut lut = vec![0u32; poly_size.0];
    /// for i in 0..poly_size.0 {
    ///     let l = (i as f64 * 2_f64.powi(32 - log_degree - 1)) as u32;
    ///     lut[i] = l;
    /// }
    ///
    /// // 1. default engine
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// // create a vector of LWE ciphertexts
    /// let h_input_key: LweSecretKey32 = default_engine.generate_new_lwe_secret_key(lwe_dim)?;
    /// let h_input_plaintext: Plaintext32 = default_engine.create_plaintext_from(&input)?;
    /// let mut h_input_ciphertext: LweCiphertext32 =
    ///     default_engine.encrypt_lwe_ciphertext(&h_input_key, &h_input_plaintext, noise)?;
    /// // create a GLWE ciphertext containing an encryption of the LUT
    /// let h_lut_plaintext_vector = default_engine.create_plaintext_vector_from(&lut)?;
    /// let h_lut_key: GlweSecretKey32 =
    ///     default_engine.generate_new_glwe_secret_key(glwe_dim, poly_size)?;
    /// let h_lut =
    ///     default_engine.encrypt_glwe_ciphertext(&h_lut_key, &h_lut_plaintext_vector, noise)?;
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
    /// // convert input to GPU 0
    /// let d_input_ciphertext: CudaLweCiphertext32 =
    ///     cuda_engine.convert_lwe_ciphertext(&h_input_ciphertext)?;
    /// // convert accumulator to GPU
    /// let d_input_lut: CudaGlweCiphertext32 = cuda_engine.convert_glwe_ciphertext(&h_lut)?;
    /// // convert BSK to GPU (and from Standard to Fourier representations)
    /// let d_fourier_bsk: CudaFourierLweBootstrapKey32 =
    ///     cuda_engine.convert_lwe_bootstrap_key(&h_bootstrap_key)?;
    /// // launch bootstrap on GPU
    /// let h_zero_output_ciphertext: LweCiphertext32 =
    ///     default_engine.zero_encrypt_lwe_ciphertext(&h_dummy_key, noise)?;
    /// let mut d_output_ciphertext: CudaLweCiphertext32 =
    ///     cuda_engine.convert_lwe_ciphertext(&h_zero_output_ciphertext)?;
    /// cuda_engine.discard_bootstrap_lwe_ciphertext(
    ///     &mut d_output_ciphertext,
    ///     &d_input_ciphertext,
    ///     &d_input_lut,
    ///     &d_fourier_bsk,
    /// )?;
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_bootstrap_lwe_ciphertext(
        &mut self,
        output: &mut CudaLweCiphertext32,
        input: &CudaLweCiphertext32,
        acc: &CudaGlweCiphertext32,
        bsk: &CudaFourierLweBootstrapKey32,
    ) -> Result<(), LweCiphertextDiscardingBootstrapError<CudaError>> {
        LweCiphertextDiscardingBootstrapError::perform_generic_checks(output, input, acc, bsk)?;
        let poly_size = bsk.polynomial_size();
        check_poly_size!(poly_size);
        let glwe_dim = bsk.glwe_dimension();
        check_glwe_dim!(glwe_dim);
        let base_log = bsk.decomposition_base_log();
        check_base_log!(base_log);
        unsafe { self.discard_bootstrap_lwe_ciphertext_unchecked(output, input, acc, bsk) };
        Ok(())
    }

    unsafe fn discard_bootstrap_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut CudaLweCiphertext32,
        input: &CudaLweCiphertext32,
        acc: &CudaGlweCiphertext32,
        bsk: &CudaFourierLweBootstrapKey32,
    ) {
        let stream = self.streams.first().unwrap();
        let mut test_vector_indexes = stream.malloc::<u32>(1);
        stream.copy_to_gpu(&mut test_vector_indexes, &[0]);

        stream.discard_bootstrap_low_latency_lwe_ciphertext_vector::<u32>(
            &mut output.0.d_vec,
            &acc.0.d_vec,
            &test_vector_indexes,
            &input.0.d_vec,
            bsk.0.d_vecs.first().unwrap(),
            input.0.lwe_dimension,
            bsk.glwe_dimension(),
            bsk.polynomial_size(),
            bsk.decomposition_base_log(),
            bsk.decomposition_level_count(),
            NumberOfSamples(1),
            LweCiphertextIndex(0),
            self.get_cuda_shared_memory(),
        );
    }
}

/// # Description
/// A discard bootstrap on an input ciphertext with 64 bits of precision.
/// The input bootstrap key is in the Fourier domain.
impl
    LweCiphertextDiscardingBootstrapEngine<
        CudaFourierLweBootstrapKey64,
        CudaGlweCiphertext64,
        CudaLweCiphertext64,
        CudaLweCiphertext64,
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
    /// let log_degree = f64::log2(poly_size.0 as f64) as i64;
    /// let val: u64 = ((poly_size.0 as f64 - (10. * f64::sqrt((lwe_dim.0 as f64) / 16.0)))
    ///     * 2_f64.powi((64 - log_degree - 1) as i32)) as u64;
    /// let input = val;
    /// let noise = Variance(2_f64.powf(-29.));
    /// let (dec_lc, dec_bl) = (DecompositionLevelCount(3), DecompositionBaseLog(7));
    /// // An identity function is applied during the bootstrap
    /// let mut lut = vec![0u64; poly_size.0];
    /// for i in 0..poly_size.0 {
    ///     let l = (i as f64 * 2_f64.powi((64 - log_degree - 1) as i32)) as u64;
    ///     lut[i] = l;
    /// }
    ///
    /// // 1. default engine
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// // create a vector of LWE ciphertexts
    /// let h_input_key: LweSecretKey64 = default_engine.generate_new_lwe_secret_key(lwe_dim)?;
    /// let h_input_plaintext: Plaintext64 = default_engine.create_plaintext_from(&input)?;
    /// let mut h_input_ciphertext: LweCiphertext64 =
    ///     default_engine.encrypt_lwe_ciphertext(&h_input_key, &h_input_plaintext, noise)?;
    /// // create a GLWE ciphertext containing an encryption of the LUT
    /// let h_lut_plaintext_vector = default_engine.create_plaintext_vector_from(&lut)?;
    /// let h_lut_key: GlweSecretKey64 =
    ///     default_engine.generate_new_glwe_secret_key(glwe_dim, poly_size)?;
    /// let h_lut =
    ///     default_engine.encrypt_glwe_ciphertext(&h_lut_key, &h_lut_plaintext_vector, noise)?;
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
    /// // convert input to GPU 0
    /// let d_input_ciphertext: CudaLweCiphertext64 =
    ///     cuda_engine.convert_lwe_ciphertext(&h_input_ciphertext)?;
    /// // convert accumulator to GPU
    /// let d_input_lut: CudaGlweCiphertext64 = cuda_engine.convert_glwe_ciphertext(&h_lut)?;
    /// // convert BSK to GPU (and from Standard to Fourier representations)
    /// let d_fourier_bsk: CudaFourierLweBootstrapKey64 =
    ///     cuda_engine.convert_lwe_bootstrap_key(&h_bootstrap_key)?;
    /// // launch bootstrap on GPU
    /// let h_zero_output_ciphertext: LweCiphertext64 =
    ///     default_engine.zero_encrypt_lwe_ciphertext(&h_dummy_key, noise)?;
    /// let mut d_output_ciphertext: CudaLweCiphertext64 =
    ///     cuda_engine.convert_lwe_ciphertext(&h_zero_output_ciphertext)?;
    /// cuda_engine.discard_bootstrap_lwe_ciphertext(
    ///     &mut d_output_ciphertext,
    ///     &d_input_ciphertext,
    ///     &d_input_lut,
    ///     &d_fourier_bsk,
    /// )?;
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_bootstrap_lwe_ciphertext(
        &mut self,
        output: &mut CudaLweCiphertext64,
        input: &CudaLweCiphertext64,
        acc: &CudaGlweCiphertext64,
        bsk: &CudaFourierLweBootstrapKey64,
    ) -> Result<(), LweCiphertextDiscardingBootstrapError<CudaError>> {
        LweCiphertextDiscardingBootstrapError::perform_generic_checks(output, input, acc, bsk)?;
        let poly_size = bsk.polynomial_size();
        check_poly_size!(poly_size);
        let glwe_dim = bsk.glwe_dimension();
        check_glwe_dim!(glwe_dim);
        let base_log = bsk.decomposition_base_log();
        check_base_log!(base_log);
        unsafe { self.discard_bootstrap_lwe_ciphertext_unchecked(output, input, acc, bsk) };
        Ok(())
    }

    unsafe fn discard_bootstrap_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut CudaLweCiphertext64,
        input: &CudaLweCiphertext64,
        acc: &CudaGlweCiphertext64,
        bsk: &CudaFourierLweBootstrapKey64,
    ) {
        let stream = self.streams.first().unwrap();
        let mut test_vector_indexes = stream.malloc::<u32>(1);
        stream.copy_to_gpu(&mut test_vector_indexes, &[0]);

        stream.discard_bootstrap_low_latency_lwe_ciphertext_vector::<u64>(
            &mut output.0.d_vec,
            &acc.0.d_vec,
            &test_vector_indexes,
            &input.0.d_vec,
            bsk.0.d_vecs.first().unwrap(),
            input.0.lwe_dimension,
            bsk.glwe_dimension(),
            bsk.polynomial_size(),
            bsk.decomposition_base_log(),
            bsk.decomposition_level_count(),
            NumberOfSamples(1),
            LweCiphertextIndex(0),
            self.get_cuda_shared_memory(),
        );
    }
}
