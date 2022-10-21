use crate::core_crypto::prelude::{
    DecompositionBaseLog, DecompositionLevelCount, PolynomialSize, StandardDev,
};

use crate::core_crypto::backends::default::entities::{
    CleartextVector64, LwePrivateFunctionalPackingKeyswitchKey32,
    LwePrivateFunctionalPackingKeyswitchKey64,
};
use crate::core_crypto::backends::default::implementation::engines::DefaultEngine;
use crate::core_crypto::backends::default::implementation::entities::{
    LweSecretKey32, LweSecretKey64,
};
use crate::core_crypto::commons::crypto::glwe::LwePrivateFunctionalPackingKeyswitchKey as ImplLwePrivateFunctionalPackingKeyswitchKey;
use crate::core_crypto::commons::math::polynomial::Polynomial;
use crate::core_crypto::commons::math::tensor::{AsRefSlice, AsRefTensor};
use crate::core_crypto::prelude::{
    CleartextVector32, GlweSecretKey32, GlweSecretKey64, GlweSecretKeyEntity,
};
use crate::core_crypto::specification::engines::{
    LwePrivateFunctionalLwePackingKeyswitchKeyGenerationEngine,
    LwePrivateFunctionalLwePackingKeyswitchKeyGenerationError,
};
use crate::core_crypto::specification::entities::LweSecretKeyEntity;

/// # Description:
/// Implementation of [`LwePrivateFunctionalLwePackingKeyswitchKeyGenerationEngine`] for
/// [`DefaultEngine`] that operates on 32 bits integers.
/// Note that the function applied during keyswitching is of the form m -> m * pol for a polynomial
/// `pol`. The input `polynomial` should be a cleartext vector containing the coefficients of pol
/// starting with the constant term.
impl
    LwePrivateFunctionalLwePackingKeyswitchKeyGenerationEngine<
        LweSecretKey32,
        GlweSecretKey32,
        LwePrivateFunctionalPackingKeyswitchKey32,
        CleartextVector32,
        u32,
    > for DefaultEngine
{
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::Variance;
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, LweDimension, GlweDimension
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
    /// let val = vec![1_u32; output_key.polynomial_size().0];
    /// let polynomial: CleartextVector32 = engine.create_cleartext_vector_from(&val)?;
    /// let private_functional_packing_keyswitch_key = engine
    /// .generate_new_lwe_private_functional_packing_keyswitch_key(
    ///     &input_key,
    ///     &output_key,
    ///     decomposition_level_count,
    ///     decomposition_base_log,
    ///     StandardDev(noise.get_standard_dev()),
    ///     &|x|x,
    ///     &polynomial,
    /// )?;
    /// #
    /// assert_eq!(
    /// #     private_functional_packing_keyswitch_key.decomposition_level_count(),
    /// #     decomposition_level_count
    /// # );
    /// assert_eq!(
    /// #     private_functional_packing_keyswitch_key.decomposition_base_log(),
    /// #     decomposition_base_log
    /// # );
    /// assert_eq!(private_functional_packing_keyswitch_key.input_lwe_dimension(),
    /// input_lwe_dimension);
    /// assert_eq!(private_functional_packing_keyswitch_key.output_glwe_dimension(),
    /// output_glwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn generate_new_lwe_private_functional_packing_keyswitch_key(
        &mut self,
        input_key: &LweSecretKey32,
        output_key: &GlweSecretKey32,
        decomposition_level_count: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        noise: StandardDev,
        f: &dyn Fn(u32) -> u32,
        polynomial: &CleartextVector32,
    ) -> Result<
        LwePrivateFunctionalPackingKeyswitchKey32,
        LwePrivateFunctionalLwePackingKeyswitchKeyGenerationError<Self::EngineError>,
    > {
        LwePrivateFunctionalLwePackingKeyswitchKeyGenerationError::perform_generic_checks(
            decomposition_level_count,
            decomposition_base_log,
            32,
            output_key.polynomial_size(),
            PolynomialSize(polynomial.0.as_tensor().len()),
        )?;
        Ok(unsafe {
            self.generate_new_lwe_private_functional_packing_keyswitch_key_unchecked(
                input_key,
                output_key,
                decomposition_level_count,
                decomposition_base_log,
                noise,
                f,
                polynomial,
            )
        })
    }

    unsafe fn generate_new_lwe_private_functional_packing_keyswitch_key_unchecked(
        &mut self,
        input_key: &LweSecretKey32,
        output_key: &GlweSecretKey32,
        decomposition_level_count: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        noise: StandardDev,
        f: &dyn Fn(u32) -> u32,
        polynomial: &CleartextVector32,
    ) -> LwePrivateFunctionalPackingKeyswitchKey32 {
        let mut pfpksk = ImplLwePrivateFunctionalPackingKeyswitchKey::allocate(
            0,
            decomposition_level_count,
            decomposition_base_log,
            input_key.lwe_dimension(),
            output_key.glwe_dimension(),
            output_key.polynomial_size(),
        );
        let poly = Polynomial::from_container(polynomial.0.as_tensor().as_slice().to_vec());

        pfpksk.fill_with_private_functional_packing_keyswitch_key(
            &input_key.0,
            &output_key.0,
            noise,
            &mut self.encryption_generator,
            f,
            &poly,
        );
        LwePrivateFunctionalPackingKeyswitchKey32(pfpksk)
    }
}

/// # Description:
/// Implementation of [`LwePrivateFunctionalLwePackingKeyswitchKeyGenerationEngine`] for
/// [`DefaultEngine`] that operates on 64 bits integers.
/// Note that the function applied during keyswitching is of the form m -> m * pol for a polynomial
/// `pol`. The input `polynomial` should be a cleartext vector containing the coefficients of pol
/// starting with the constant term.
impl
    LwePrivateFunctionalLwePackingKeyswitchKeyGenerationEngine<
        LweSecretKey64,
        GlweSecretKey64,
        LwePrivateFunctionalPackingKeyswitchKey64,
        CleartextVector64,
        u64,
    > for DefaultEngine
{
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::Variance;
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, LweDimension, GlweDimension
    /// };
    /// use tfhe::core_crypto::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let input_lwe_dimension = LweDimension(6);
    /// let output_glwe_dimension = GlweDimension(3);
    /// let polynomial_size = PolynomialSize(256);
    /// let decomposition_level_count = DecompositionLevelCount(2);
    /// let decomposition_base_log = DecompositionBaseLog(8);
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
    /// let val = vec![1_u64; output_key.polynomial_size().0];
    /// let polynomial: CleartextVector64 = engine.create_cleartext_vector_from(&val)?;
    /// let private_functional_packing_keyswitch_key = engine
    /// .generate_new_lwe_private_functional_packing_keyswitch_key(
    ///     &input_key,
    ///     &output_key,
    ///     decomposition_level_count,
    ///     decomposition_base_log,
    ///     StandardDev(noise.get_standard_dev()),
    ///     &|x|x,
    ///     &polynomial,
    /// )?;
    /// #
    /// assert_eq!(
    /// #     private_functional_packing_keyswitch_key.decomposition_level_count(),
    /// #     decomposition_level_count
    /// # );
    /// assert_eq!(
    /// #     private_functional_packing_keyswitch_key.decomposition_base_log(),
    /// #     decomposition_base_log
    /// # );
    /// assert_eq!(private_functional_packing_keyswitch_key.input_lwe_dimension(),
    /// input_lwe_dimension);
    /// assert_eq!(private_functional_packing_keyswitch_key.output_glwe_dimension(),
    /// output_glwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn generate_new_lwe_private_functional_packing_keyswitch_key(
        &mut self,
        input_key: &LweSecretKey64,
        output_key: &GlweSecretKey64,
        decomposition_level_count: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        noise: StandardDev,
        f: &dyn Fn(u64) -> u64,
        polynomial: &CleartextVector64,
    ) -> Result<
        LwePrivateFunctionalPackingKeyswitchKey64,
        LwePrivateFunctionalLwePackingKeyswitchKeyGenerationError<Self::EngineError>,
    > {
        LwePrivateFunctionalLwePackingKeyswitchKeyGenerationError::perform_generic_checks(
            decomposition_level_count,
            decomposition_base_log,
            64,
            output_key.polynomial_size(),
            PolynomialSize(polynomial.0.as_tensor().len()),
        )?;
        Ok(unsafe {
            self.generate_new_lwe_private_functional_packing_keyswitch_key_unchecked(
                input_key,
                output_key,
                decomposition_level_count,
                decomposition_base_log,
                noise,
                f,
                polynomial,
            )
        })
    }

    unsafe fn generate_new_lwe_private_functional_packing_keyswitch_key_unchecked(
        &mut self,
        input_key: &LweSecretKey64,
        output_key: &GlweSecretKey64,
        decomposition_level_count: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        noise: StandardDev,
        f: &dyn Fn(u64) -> u64,
        polynomial: &CleartextVector64,
    ) -> LwePrivateFunctionalPackingKeyswitchKey64 {
        let mut pfpksk = ImplLwePrivateFunctionalPackingKeyswitchKey::allocate(
            0,
            decomposition_level_count,
            decomposition_base_log,
            input_key.lwe_dimension(),
            output_key.glwe_dimension(),
            output_key.polynomial_size(),
        );
        let poly = Polynomial::from_container(polynomial.0.as_tensor().as_slice().to_vec());

        pfpksk.fill_with_private_functional_packing_keyswitch_key(
            &input_key.0,
            &output_key.0,
            noise,
            &mut self.encryption_generator,
            f,
            &poly,
        );
        LwePrivateFunctionalPackingKeyswitchKey64(pfpksk)
    }
}
