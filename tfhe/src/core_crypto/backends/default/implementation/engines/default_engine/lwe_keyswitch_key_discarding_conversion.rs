use crate::core_crypto::backends::default::engines::DefaultEngine;
use crate::core_crypto::backends::default::entities::{
    LweKeyswitchKey32, LweKeyswitchKey64, LweKeyswitchKeyMutView32, LweKeyswitchKeyMutView64,
};
use crate::core_crypto::commons::math::tensor::{AsMutTensor, AsRefTensor};
use crate::core_crypto::specification::engines::{
    LweKeyswitchKeyDiscardingConversionEngine, LweKeyswitchKeyDiscardingConversionError,
};

impl LweKeyswitchKeyDiscardingConversionEngine<LweKeyswitchKey32, LweKeyswitchKeyMutView32<'_>>
    for DefaultEngine
{
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::Variance;
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, LweDimension,
    /// };
    /// use tfhe::core_crypto::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let input_lwe_dimension = LweDimension(6);
    /// let output_lwe_dimension = LweDimension(3);
    /// let decomposition_level_count = DecompositionLevelCount(2);
    /// let decomposition_base_log = DecompositionBaseLog(8);
    /// let noise = Variance(2_f64.powf(-50.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let input_key: LweSecretKey32 = engine.generate_new_lwe_secret_key(input_lwe_dimension)?;
    /// let output_key: LweSecretKey32 = engine.generate_new_lwe_secret_key(output_lwe_dimension)?;
    ///
    /// let keyswitch_key = engine.generate_new_lwe_keyswitch_key(
    ///     &input_key,
    ///     &output_key,
    ///     decomposition_level_count,
    ///     decomposition_base_log,
    ///     noise,
    /// )?;
    ///
    /// let mut owned_container = vec![
    ///     0_u32;
    ///     decomposition_level_count.0 * output_lwe_dimension.to_lwe_size().0 * input_lwe_dimension.0
    /// ];
    ///
    /// let mut out_ksk_mut_view: LweKeyswitchKeyMutView32 = engine.create_lwe_keyswitch_key_from(
    ///     owned_container.as_mut_slice(),
    ///     output_lwe_dimension,
    ///     decomposition_base_log,
    ///     decomposition_level_count,
    /// )?;
    ///
    /// #
    /// assert_eq!(
    /// #     out_ksk_mut_view.decomposition_level_count(),
    /// #     decomposition_level_count
    /// # );
    /// assert_eq!(
    /// #     out_ksk_mut_view.decomposition_base_log(),
    /// #     decomposition_base_log
    /// # );
    /// assert_eq!(out_ksk_mut_view.input_lwe_dimension(), input_lwe_dimension);
    /// assert_eq!(out_ksk_mut_view.output_lwe_dimension(), output_lwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_convert_lwe_keyswitch_key(
        &mut self,
        output: &mut LweKeyswitchKeyMutView32<'_>,
        input: &LweKeyswitchKey32,
    ) -> Result<(), LweKeyswitchKeyDiscardingConversionError<Self::EngineError>> {
        LweKeyswitchKeyDiscardingConversionError::perform_generic_checks(output, input)?;
        unsafe { self.discard_convert_lwe_keyswitch_key_unchecked(output, input) };
        Ok(())
    }

    unsafe fn discard_convert_lwe_keyswitch_key_unchecked(
        &mut self,
        output: &mut LweKeyswitchKeyMutView32<'_>,
        input: &LweKeyswitchKey32,
    ) {
        output.0.as_mut_tensor().fill_with_copy(input.0.as_tensor());
    }
}

impl LweKeyswitchKeyDiscardingConversionEngine<LweKeyswitchKey64, LweKeyswitchKeyMutView64<'_>>
    for DefaultEngine
{
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::Variance;
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, LweDimension,
    /// };
    /// use tfhe::core_crypto::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let input_lwe_dimension = LweDimension(6);
    /// let output_lwe_dimension = LweDimension(3);
    /// let decomposition_level_count = DecompositionLevelCount(2);
    /// let decomposition_base_log = DecompositionBaseLog(8);
    /// let noise = Variance(2_f64.powf(-50.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let input_key: LweSecretKey64 = engine.generate_new_lwe_secret_key(input_lwe_dimension)?;
    /// let output_key: LweSecretKey64 = engine.generate_new_lwe_secret_key(output_lwe_dimension)?;
    ///
    /// let keyswitch_key = engine.generate_new_lwe_keyswitch_key(
    ///     &input_key,
    ///     &output_key,
    ///     decomposition_level_count,
    ///     decomposition_base_log,
    ///     noise,
    /// )?;
    ///
    /// let mut owned_container = vec![
    ///     0_u64;
    ///     decomposition_level_count.0 * output_lwe_dimension.to_lwe_size().0 * input_lwe_dimension.0
    /// ];
    ///
    /// let mut out_ksk_mut_view: LweKeyswitchKeyMutView64 = engine.create_lwe_keyswitch_key_from(
    ///     owned_container.as_mut_slice(),
    ///     output_lwe_dimension,
    ///     decomposition_base_log,
    ///     decomposition_level_count,
    /// )?;
    ///
    /// #
    /// assert_eq!(
    /// #     out_ksk_mut_view.decomposition_level_count(),
    /// #     decomposition_level_count
    /// # );
    /// assert_eq!(
    /// #     out_ksk_mut_view.decomposition_base_log(),
    /// #     decomposition_base_log
    /// # );
    /// assert_eq!(out_ksk_mut_view.input_lwe_dimension(), input_lwe_dimension);
    /// assert_eq!(out_ksk_mut_view.output_lwe_dimension(), output_lwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_convert_lwe_keyswitch_key(
        &mut self,
        output: &mut LweKeyswitchKeyMutView64<'_>,
        input: &LweKeyswitchKey64,
    ) -> Result<(), LweKeyswitchKeyDiscardingConversionError<Self::EngineError>> {
        LweKeyswitchKeyDiscardingConversionError::perform_generic_checks(output, input)?;
        unsafe { self.discard_convert_lwe_keyswitch_key_unchecked(output, input) };
        Ok(())
    }

    unsafe fn discard_convert_lwe_keyswitch_key_unchecked(
        &mut self,
        output: &mut LweKeyswitchKeyMutView64<'_>,
        input: &LweKeyswitchKey64,
    ) {
        output.0.as_mut_tensor().fill_with_copy(input.0.as_tensor());
    }
}
