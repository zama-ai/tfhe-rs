use crate::core_crypto::backends::cuda::engines::CudaError;
use crate::core_crypto::backends::cuda::implementation::engines::CudaEngine;
use crate::core_crypto::backends::cuda::implementation::entities::{
    CudaLweCiphertext32, CudaLweCiphertext64, CudaLweKeyswitchKey32, CudaLweKeyswitchKey64,
};
use crate::core_crypto::backends::cuda::private::device::NumberOfSamples;
use crate::core_crypto::specification::engines::{
    LweCiphertextDiscardingKeyswitchEngine, LweCiphertextDiscardingKeyswitchError,
};
use crate::core_crypto::specification::entities::LweKeyswitchKeyEntity;

impl From<CudaError> for LweCiphertextDiscardingKeyswitchError<CudaError> {
    fn from(err: CudaError) -> Self {
        Self::Engine(err)
    }
}

/// # Description
/// A discard keyswitch on a vector of input ciphertext vectors with 32 bits of precision.
impl
    LweCiphertextDiscardingKeyswitchEngine<
        CudaLweKeyswitchKey32,
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
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let input_lwe_dimension = LweDimension(6);
    /// let output_lwe_dimension = LweDimension(3);
    /// let decomposition_level_count = DecompositionLevelCount(2);
    /// let decomposition_base_log = DecompositionBaseLog(8);
    ///
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = 3_u32 << 20;
    /// let noise = Variance(2_f64.powf(-50.));
    ///
    /// // Generate two secret keys
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let input_key: LweSecretKey32 =
    ///     default_engine.generate_new_lwe_secret_key(input_lwe_dimension)?;
    /// let output_key: LweSecretKey32 =
    ///     default_engine.generate_new_lwe_secret_key(output_lwe_dimension)?;
    ///
    /// // Generate keyswitch keys to switch between first_key and second_key
    /// let h_ksk = default_engine.generate_new_lwe_keyswitch_key(
    ///     &input_key,
    ///     &output_key,
    ///     decomposition_level_count,
    ///     decomposition_base_log,
    ///     noise,
    /// )?;
    ///
    /// // Encrypt something
    /// let h_plaintext: Plaintext32 = default_engine.create_plaintext_from(&input)?;
    /// let mut h_ciphertext: LweCiphertext32 =
    ///     default_engine.encrypt_lwe_ciphertext(&input_key, &h_plaintext, noise)?;
    ///
    /// // Copy to the GPU
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_ciphertext: CudaLweCiphertext32 = cuda_engine.convert_lwe_ciphertext(&h_ciphertext)?;
    /// let d_ksk: CudaLweKeyswitchKey32 = cuda_engine.convert_lwe_keyswitch_key(&h_ksk)?;
    ///
    /// // launch keyswitch on GPU
    /// let h_dummy_key: LweSecretKey32 =
    ///     default_engine.generate_new_lwe_secret_key(output_lwe_dimension)?;
    /// let h_zero_ciphertext: LweCiphertext32 =
    ///     default_engine.zero_encrypt_lwe_ciphertext(&h_dummy_key, noise)?;
    ///
    /// let mut d_keyswitched_ciphertext: CudaLweCiphertext32 =
    ///     cuda_engine.convert_lwe_ciphertext(&h_zero_ciphertext)?;
    /// cuda_engine.discard_keyswitch_lwe_ciphertext(
    ///     &mut d_keyswitched_ciphertext,
    ///     &d_ciphertext,
    ///     &d_ksk,
    /// )?;
    ///
    /// assert_eq!(
    ///     d_keyswitched_ciphertext.lwe_dimension(),
    ///     output_lwe_dimension
    /// );
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_keyswitch_lwe_ciphertext(
        &mut self,
        output: &mut CudaLweCiphertext32,
        input: &CudaLweCiphertext32,
        ksk: &CudaLweKeyswitchKey32,
    ) -> Result<(), LweCiphertextDiscardingKeyswitchError<CudaError>> {
        LweCiphertextDiscardingKeyswitchError::perform_generic_checks(output, input, ksk)?;
        unsafe { self.discard_keyswitch_lwe_ciphertext_unchecked(output, input, ksk) };
        Ok(())
    }

    unsafe fn discard_keyswitch_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut CudaLweCiphertext32,
        input: &CudaLweCiphertext32,
        ksk: &CudaLweKeyswitchKey32,
    ) {
        let stream = &self.streams[0];

        stream.discard_keyswitch_lwe_ciphertext_vector::<u32>(
            &mut output.0.d_vec,
            &input.0.d_vec,
            input.0.lwe_dimension,
            output.0.lwe_dimension,
            ksk.0.d_vecs.first().unwrap(),
            ksk.decomposition_base_log(),
            ksk.decomposition_level_count(),
            NumberOfSamples(1),
        );
    }
}

/// # Description
/// A discard keyswitch on a vector of input ciphertext vectors with 64 bits of precision.
impl
    LweCiphertextDiscardingKeyswitchEngine<
        CudaLweKeyswitchKey64,
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
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let input_lwe_dimension = LweDimension(6);
    /// let output_lwe_dimension = LweDimension(3);
    /// let decomposition_level_count = DecompositionLevelCount(2);
    /// let decomposition_base_log = DecompositionBaseLog(8);
    ///
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = 3_u64 << 50;
    /// let noise = Variance(2_f64.powf(-50.));
    ///
    /// // Generate two secret keys
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let input_key: LweSecretKey64 =
    ///     default_engine.generate_new_lwe_secret_key(input_lwe_dimension)?;
    /// let output_key: LweSecretKey64 =
    ///     default_engine.generate_new_lwe_secret_key(output_lwe_dimension)?;
    ///
    /// // Generate keyswitch keys to switch between first_key and second_key
    /// let h_ksk = default_engine.generate_new_lwe_keyswitch_key(
    ///     &input_key,
    ///     &output_key,
    ///     decomposition_level_count,
    ///     decomposition_base_log,
    ///     noise,
    /// )?;
    ///
    /// // Encrypt something
    /// let h_plaintext: Plaintext64 = default_engine.create_plaintext_from(&input)?;
    /// let mut h_ciphertext: LweCiphertext64 =
    ///     default_engine.encrypt_lwe_ciphertext(&input_key, &h_plaintext, noise)?;
    ///
    /// // Copy to the GPU
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_ciphertext: CudaLweCiphertext64 = cuda_engine.convert_lwe_ciphertext(&h_ciphertext)?;
    /// let d_ksk: CudaLweKeyswitchKey64 = cuda_engine.convert_lwe_keyswitch_key(&h_ksk)?;
    ///
    /// // launch keyswitch on GPU
    /// let h_dummy_key: LweSecretKey64 =
    ///     default_engine.generate_new_lwe_secret_key(output_lwe_dimension)?;
    /// let h_zero_ciphertext: LweCiphertext64 =
    ///     default_engine.zero_encrypt_lwe_ciphertext(&h_dummy_key, noise)?;
    ///
    /// let mut d_keyswitched_ciphertext: CudaLweCiphertext64 =
    ///     cuda_engine.convert_lwe_ciphertext(&h_zero_ciphertext)?;
    /// cuda_engine.discard_keyswitch_lwe_ciphertext(
    ///     &mut d_keyswitched_ciphertext,
    ///     &d_ciphertext,
    ///     &d_ksk,
    /// )?;
    ///
    /// assert_eq!(
    ///     d_keyswitched_ciphertext.lwe_dimension(),
    ///     output_lwe_dimension
    /// );
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_keyswitch_lwe_ciphertext(
        &mut self,
        output: &mut CudaLweCiphertext64,
        input: &CudaLweCiphertext64,
        ksk: &CudaLweKeyswitchKey64,
    ) -> Result<(), LweCiphertextDiscardingKeyswitchError<CudaError>> {
        LweCiphertextDiscardingKeyswitchError::perform_generic_checks(output, input, ksk)?;
        unsafe { self.discard_keyswitch_lwe_ciphertext_unchecked(output, input, ksk) };
        Ok(())
    }

    unsafe fn discard_keyswitch_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut CudaLweCiphertext64,
        input: &CudaLweCiphertext64,
        ksk: &CudaLweKeyswitchKey64,
    ) {
        let stream = &self.streams[0];

        stream.discard_keyswitch_lwe_ciphertext_vector::<u64>(
            &mut output.0.d_vec,
            &input.0.d_vec,
            input.0.lwe_dimension,
            output.0.lwe_dimension,
            ksk.0.d_vecs.first().unwrap(),
            ksk.decomposition_base_log(),
            ksk.decomposition_level_count(),
            NumberOfSamples(1),
        );
    }
}
