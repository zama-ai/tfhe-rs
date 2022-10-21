use crate::core_crypto::prelude::LweDimension;

use crate::core_crypto::backends::default::implementation::engines::DefaultEngine;
use crate::core_crypto::backends::default::implementation::entities::{
    LweSecretKey32, LweSecretKey64,
};
use crate::core_crypto::commons::crypto::secret::LweSecretKey as ImplLweSecretKey;
use crate::core_crypto::specification::engines::{
    LweSecretKeyGenerationEngine, LweSecretKeyGenerationError,
};

/// # Description:
/// Implementation of [`LweSecretKeyGenerationEngine`] for [`DefaultEngine`] that operates on
/// 32 bits integers.
impl LweSecretKeyGenerationEngine<LweSecretKey32> for DefaultEngine {
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{LweDimension, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(6);
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let lwe_secret_key: LweSecretKey32 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// #
    /// assert_eq!(lwe_secret_key.lwe_dimension(), lwe_dimension);
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn generate_new_lwe_secret_key(
        &mut self,
        lwe_dimension: LweDimension,
    ) -> Result<LweSecretKey32, LweSecretKeyGenerationError<Self::EngineError>> {
        LweSecretKeyGenerationError::perform_generic_checks(lwe_dimension)?;
        Ok(unsafe { self.generate_new_lwe_secret_key_unchecked(lwe_dimension) })
    }

    unsafe fn generate_new_lwe_secret_key_unchecked(
        &mut self,
        lwe_dimension: LweDimension,
    ) -> LweSecretKey32 {
        LweSecretKey32(ImplLweSecretKey::generate_binary(
            lwe_dimension,
            &mut self.secret_generator,
        ))
    }
}

/// # Description:
/// Implementation of [`LweSecretKeyGenerationEngine`] for [`DefaultEngine`] that operates on
/// 64 bits integers.
impl LweSecretKeyGenerationEngine<LweSecretKey64> for DefaultEngine {
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{LweDimension, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(6);
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let lwe_secret_key: LweSecretKey64 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// #
    /// assert_eq!(lwe_secret_key.lwe_dimension(), lwe_dimension);
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn generate_new_lwe_secret_key(
        &mut self,
        lwe_dimension: LweDimension,
    ) -> Result<LweSecretKey64, LweSecretKeyGenerationError<Self::EngineError>> {
        LweSecretKeyGenerationError::perform_generic_checks(lwe_dimension)?;
        Ok(unsafe { self.generate_new_lwe_secret_key_unchecked(lwe_dimension) })
    }

    unsafe fn generate_new_lwe_secret_key_unchecked(
        &mut self,
        lwe_dimension: LweDimension,
    ) -> LweSecretKey64 {
        LweSecretKey64(ImplLweSecretKey::generate_binary(
            lwe_dimension,
            &mut self.secret_generator,
        ))
    }
}
