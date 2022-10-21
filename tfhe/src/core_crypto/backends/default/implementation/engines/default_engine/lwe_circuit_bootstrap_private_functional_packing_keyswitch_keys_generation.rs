use crate::core_crypto::backends::default::implementation::engines::DefaultEngine;
use crate::core_crypto::backends::default::implementation::entities::{
    GlweSecretKey32, GlweSecretKey64, LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32,
    LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64, LweSecretKey32, LweSecretKey64,
};
use crate::core_crypto::commons::crypto::glwe::LwePrivateFunctionalPackingKeyswitchKeyList as ImplLwePrivateFunctionalPackingKeyswitchKeyList;
use crate::core_crypto::prelude::{
    DecompositionBaseLog, DecompositionLevelCount, FunctionalPackingKeyswitchKeyCount, Variance,
};
use crate::core_crypto::specification::engines::{
    LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysGenerationEngine,
    LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysGenerationError,
};
use crate::core_crypto::specification::entities::{GlweSecretKeyEntity, LweSecretKeyEntity};

/// # Description:
/// Implementation of [`LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysGenerationEngine`]
/// for [`DefaultEngine`] that operates on 32 bits integers.
impl
    LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysGenerationEngine<
        LweSecretKey32,
        GlweSecretKey32,
        LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32,
    > for DefaultEngine
{
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::Variance;
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, LweDimension, GlweDimension,FunctionalPackingKeyswitchKeyCount
    /// };
    /// use tfhe::core_crypto::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let input_lwe_dimension = LweDimension(10);
    /// let output_glwe_dimension = GlweDimension(3);
    /// let polynomial_size = PolynomialSize(256);
    /// let decomposition_base_log = DecompositionBaseLog(3);
    /// let decomposition_level_count = DecompositionLevelCount(5);
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let input_key: LweSecretKey32 = engine.generate_new_lwe_secret_key(input_lwe_dimension)?;
    /// let output_key: GlweSecretKey32 = engine.generate_new_glwe_secret_key(output_glwe_dimension,
    /// polynomial_size)?;
    ///
    /// let cbs_private_functional_packing_keyswitch_key:
    ///     LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32 =
    ///     engine
    ///     .generate_new_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys(
    ///         &input_key,
    ///         &output_key,
    ///         decomposition_base_log,
    ///         decomposition_level_count,
    ///         noise,
    /// )?;
    /// #
    /// assert_eq!(
    /// #     cbs_private_functional_packing_keyswitch_key.decomposition_level_count(),
    /// #     decomposition_level_count
    /// # );
    /// assert_eq!(
    /// #     cbs_private_functional_packing_keyswitch_key.decomposition_base_log(),
    /// #     decomposition_base_log
    /// # );
    /// assert_eq!(cbs_private_functional_packing_keyswitch_key.input_lwe_dimension(),
    /// input_lwe_dimension);
    /// assert_eq!(cbs_private_functional_packing_keyswitch_key.output_glwe_dimension(),
    /// output_glwe_dimension);
    /// assert_eq!(cbs_private_functional_packing_keyswitch_key.key_count().0,
    /// output_glwe_dimension.to_glwe_size().0);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn generate_new_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys(
        &mut self,
        input_lwe_key: &LweSecretKey32,
        output_glwe_key: &GlweSecretKey32,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        noise: Variance,
    ) -> Result<
        LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32,
        LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysGenerationError<Self::EngineError>,
    > {
        LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysGenerationError::perform_generic_checks(
            decomposition_level_count, decomposition_base_log, 32)?;
        Ok(unsafe {
            self.generate_new_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_unchecked(input_lwe_key, output_glwe_key, decomposition_base_log, decomposition_level_count, noise)
        })
    }

    unsafe fn generate_new_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_unchecked(
        &mut self,
        input_lwe_key: &LweSecretKey32,
        output_glwe_key: &GlweSecretKey32,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        noise: Variance,
    ) -> LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32 {
        let mut fpksk_list = ImplLwePrivateFunctionalPackingKeyswitchKeyList::allocate(
            0u32,
            decomposition_level_count,
            decomposition_base_log,
            input_lwe_key.lwe_dimension(),
            output_glwe_key.glwe_dimension(),
            output_glwe_key.polynomial_size(),
            FunctionalPackingKeyswitchKeyCount(output_glwe_key.glwe_dimension().to_glwe_size().0),
        );

        fpksk_list.fill_with_fpksk_for_circuit_bootstrap(
            &input_lwe_key.0,
            &output_glwe_key.0,
            noise,
            &mut self.encryption_generator,
        );

        LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32(fpksk_list)
    }
}

/// # Description:
/// Implementation of [`LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysGenerationEngine`]
/// for [`DefaultEngine`] that operates on 64 bits integers.
impl
    LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysGenerationEngine<
        LweSecretKey64,
        GlweSecretKey64,
        LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64,
    > for DefaultEngine
{
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::Variance;
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, LweDimension, GlweDimension,FunctionalPackingKeyswitchKeyCount
    /// };
    /// use tfhe::core_crypto::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let input_lwe_dimension = LweDimension(10);
    /// let output_glwe_dimension = GlweDimension(3);
    /// let polynomial_size = PolynomialSize(256);
    /// let decomposition_base_log = DecompositionBaseLog(3);
    /// let decomposition_level_count = DecompositionLevelCount(5);
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let input_key: LweSecretKey64 = engine.generate_new_lwe_secret_key(input_lwe_dimension)?;
    /// let output_key: GlweSecretKey64 = engine.generate_new_glwe_secret_key(output_glwe_dimension,
    /// polynomial_size)?;
    ///
    /// let cbs_private_functional_packing_keyswitch_key:
    ///     LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64 =
    ///     engine
    ///     .generate_new_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys(
    ///         &input_key,
    ///         &output_key,
    ///         decomposition_base_log,
    ///         decomposition_level_count,
    ///         noise,
    /// )?;
    /// #
    /// assert_eq!(
    /// #     cbs_private_functional_packing_keyswitch_key.decomposition_level_count(),
    /// #     decomposition_level_count
    /// # );
    /// assert_eq!(
    /// #     cbs_private_functional_packing_keyswitch_key.decomposition_base_log(),
    /// #     decomposition_base_log
    /// # );
    /// assert_eq!(cbs_private_functional_packing_keyswitch_key.input_lwe_dimension(),
    /// input_lwe_dimension);
    /// assert_eq!(cbs_private_functional_packing_keyswitch_key.output_glwe_dimension(),
    /// output_glwe_dimension);
    /// assert_eq!(cbs_private_functional_packing_keyswitch_key.key_count().0,
    /// output_glwe_dimension.to_glwe_size().0);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn generate_new_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys(
        &mut self,
        input_lwe_key: &LweSecretKey64,
        output_glwe_key: &GlweSecretKey64,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        noise: Variance,
    ) -> Result<
        LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64,
        LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysGenerationError<Self::EngineError>,
    > {
        LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysGenerationError::perform_generic_checks(
            decomposition_level_count, decomposition_base_log, 64)?;
        Ok(unsafe {
            self.generate_new_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_unchecked(input_lwe_key, output_glwe_key, decomposition_base_log, decomposition_level_count, noise)
        })
    }

    unsafe fn generate_new_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_unchecked(
        &mut self,
        input_lwe_key: &LweSecretKey64,
        output_glwe_key: &GlweSecretKey64,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        noise: Variance,
    ) -> LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64 {
        let mut fpksk_list = ImplLwePrivateFunctionalPackingKeyswitchKeyList::allocate(
            0u64,
            decomposition_level_count,
            decomposition_base_log,
            input_lwe_key.lwe_dimension(),
            output_glwe_key.glwe_dimension(),
            output_glwe_key.polynomial_size(),
            FunctionalPackingKeyswitchKeyCount(output_glwe_key.glwe_dimension().to_glwe_size().0),
        );

        fpksk_list.fill_with_fpksk_for_circuit_bootstrap(
            &input_lwe_key.0,
            &output_glwe_key.0,
            noise,
            &mut self.encryption_generator,
        );

        LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64(fpksk_list)
    }
}
