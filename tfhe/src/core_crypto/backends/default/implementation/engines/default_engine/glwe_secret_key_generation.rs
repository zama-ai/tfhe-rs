use crate::core_crypto::prelude::{GlweDimension, PolynomialSize};

use crate::core_crypto::backends::default::implementation::engines::DefaultEngine;
use crate::core_crypto::backends::default::implementation::entities::{
    GlweSecretKey32, GlweSecretKey64,
};
use crate::core_crypto::commons::crypto::secret::GlweSecretKey as ImplGlweSecretKey;
use crate::core_crypto::specification::engines::{
    GlweSecretKeyGenerationEngine, GlweSecretKeyGenerationError,
};

/// # Description:
/// Implementation of [`GlweSecretKeyGenerationEngine`] for [`DefaultEngine`] that operates on
/// 32 bits integers.
impl GlweSecretKeyGenerationEngine<GlweSecretKey32> for DefaultEngine {
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{GlweDimension, PolynomialSize, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(4);
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let glwe_secret_key: GlweSecretKey32 =
    ///     engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// #
    /// assert_eq!(glwe_secret_key.glwe_dimension(), glwe_dimension);
    /// assert_eq!(glwe_secret_key.polynomial_size(), polynomial_size);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn generate_new_glwe_secret_key(
        &mut self,
        glwe_dimension: GlweDimension,
        polynomial_size: PolynomialSize,
    ) -> Result<GlweSecretKey32, GlweSecretKeyGenerationError<Self::EngineError>> {
        GlweSecretKeyGenerationError::perform_generic_checks(glwe_dimension, polynomial_size)?;
        Ok(unsafe { self.generate_new_glwe_secret_key_unchecked(glwe_dimension, polynomial_size) })
    }

    unsafe fn generate_new_glwe_secret_key_unchecked(
        &mut self,
        glwe_dimension: GlweDimension,
        polynomial_size: PolynomialSize,
    ) -> GlweSecretKey32 {
        GlweSecretKey32(ImplGlweSecretKey::generate_binary(
            glwe_dimension,
            polynomial_size,
            &mut self.secret_generator,
        ))
    }
}

/// # Description:
/// Implementation of [`GlweSecretKeyGenerationEngine`] for [`DefaultEngine`] that operates on
/// 64 bits integers.
impl GlweSecretKeyGenerationEngine<GlweSecretKey64> for DefaultEngine {
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{GlweDimension, PolynomialSize, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(4);
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let glwe_secret_key: GlweSecretKey64 =
    ///     engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// #
    /// assert_eq!(glwe_secret_key.glwe_dimension(), glwe_dimension);
    /// assert_eq!(glwe_secret_key.polynomial_size(), polynomial_size);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn generate_new_glwe_secret_key(
        &mut self,
        glwe_dimension: GlweDimension,
        polynomial_size: PolynomialSize,
    ) -> Result<GlweSecretKey64, GlweSecretKeyGenerationError<Self::EngineError>> {
        GlweSecretKeyGenerationError::perform_generic_checks(glwe_dimension, polynomial_size)?;
        Ok(unsafe { self.generate_new_glwe_secret_key_unchecked(glwe_dimension, polynomial_size) })
    }

    unsafe fn generate_new_glwe_secret_key_unchecked(
        &mut self,
        glwe_dimension: GlweDimension,
        polynomial_size: PolynomialSize,
    ) -> GlweSecretKey64 {
        GlweSecretKey64(ImplGlweSecretKey::generate_binary(
            glwe_dimension,
            polynomial_size,
            &mut self.secret_generator,
        ))
    }
}
