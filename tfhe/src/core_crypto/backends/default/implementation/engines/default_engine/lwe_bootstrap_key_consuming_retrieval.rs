use crate::core_crypto::backends::default::implementation::engines::DefaultEngine;
use crate::core_crypto::backends::default::implementation::entities::{
    LweBootstrapKey32, LweBootstrapKey64, LweBootstrapKeyMutView32, LweBootstrapKeyMutView64,
    LweBootstrapKeyView32, LweBootstrapKeyView64,
};
use crate::core_crypto::commons::math::tensor::IntoTensor;
use crate::core_crypto::specification::engines::{
    LweBootstrapKeyConsumingRetrievalEngine, LweBootstrapKeyConsumingRetrievalError,
};

impl LweBootstrapKeyConsumingRetrievalEngine<LweBootstrapKey32, Vec<u32>> for DefaultEngine {
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
    ///     *,
    /// };
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(2);
    /// let glwe_size = GlweSize(2);
    /// let polynomial_size = PolynomialSize(256);
    /// let level = DecompositionLevelCount(2);
    /// let base_log = DecompositionBaseLog(1);
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    ///
    /// let owned_container =
    ///     vec![0_u32; lwe_dimension.0 * level.0 * glwe_size.0 * glwe_size.0 * polynomial_size.0];
    /// let original_vec_ptr = owned_container.as_ptr();
    ///
    /// let lwe_bootstrap_key: LweBootstrapKey32 = engine.create_lwe_bootstrap_key_from(
    ///     owned_container,
    ///     glwe_size,
    ///     polynomial_size,
    ///     base_log,
    ///     level,
    /// )?;
    /// let retrieved_container = engine.consume_retrieve_lwe_bootstrap_key(lwe_bootstrap_key)?;
    /// assert_eq!(original_vec_ptr, retrieved_container.as_ptr());
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn consume_retrieve_lwe_bootstrap_key(
        &mut self,
        bootstrap_key: LweBootstrapKey32,
    ) -> Result<Vec<u32>, LweBootstrapKeyConsumingRetrievalError<Self::EngineError>> {
        Ok(unsafe { self.consume_retrieve_lwe_bootstrap_key_unchecked(bootstrap_key) })
    }

    unsafe fn consume_retrieve_lwe_bootstrap_key_unchecked(
        &mut self,
        bootstrap_key: LweBootstrapKey32,
    ) -> Vec<u32> {
        bootstrap_key.0.into_tensor().into_container()
    }
}

impl LweBootstrapKeyConsumingRetrievalEngine<LweBootstrapKey64, Vec<u64>> for DefaultEngine {
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
    ///     *,
    /// };
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(2);
    /// let glwe_size = GlweSize(2);
    /// let polynomial_size = PolynomialSize(256);
    /// let level = DecompositionLevelCount(2);
    /// let base_log = DecompositionBaseLog(1);
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    ///
    /// let owned_container =
    ///     vec![0_u64; lwe_dimension.0 * level.0 * glwe_size.0 * glwe_size.0 * polynomial_size.0];
    /// let original_vec_ptr = owned_container.as_ptr();
    ///
    /// let lwe_bootstrap_key: LweBootstrapKey64 = engine.create_lwe_bootstrap_key_from(
    ///     owned_container,
    ///     glwe_size,
    ///     polynomial_size,
    ///     base_log,
    ///     level,
    /// )?;
    /// let retrieved_container = engine.consume_retrieve_lwe_bootstrap_key(lwe_bootstrap_key)?;
    /// assert_eq!(original_vec_ptr, retrieved_container.as_ptr());
    /// # Ok(())
    /// # }
    /// ```
    fn consume_retrieve_lwe_bootstrap_key(
        &mut self,
        bootstrap_key: LweBootstrapKey64,
    ) -> Result<Vec<u64>, LweBootstrapKeyConsumingRetrievalError<Self::EngineError>> {
        Ok(unsafe { self.consume_retrieve_lwe_bootstrap_key_unchecked(bootstrap_key) })
    }

    unsafe fn consume_retrieve_lwe_bootstrap_key_unchecked(
        &mut self,
        bootstrap_key: LweBootstrapKey64,
    ) -> Vec<u64> {
        bootstrap_key.0.into_tensor().into_container()
    }
}

impl<'data>
    LweBootstrapKeyConsumingRetrievalEngine<LweBootstrapKeyMutView32<'data>, &'data mut [u32]>
    for DefaultEngine
{
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
    ///     *,
    /// };
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(2);
    /// let glwe_size = GlweSize(2);
    /// let polynomial_size = PolynomialSize(256);
    /// let level = DecompositionLevelCount(2);
    /// let base_log = DecompositionBaseLog(1);
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    ///
    /// let mut owned_container =
    ///     vec![0_u32; lwe_dimension.0 * level.0 * glwe_size.0 * glwe_size.0 * polynomial_size.0];
    ///
    /// let mut slice = owned_container.as_mut_slice();
    /// // Required as we can't borrow a mut slice more than once
    /// let underlying_ptr = slice.as_ptr();
    ///
    /// let lwe_bootstrap_key: LweBootstrapKeyMutView32 =
    ///     engine.create_lwe_bootstrap_key_from(slice, glwe_size, polynomial_size, base_log, level)?;
    /// let retrieved_slice = engine.consume_retrieve_lwe_bootstrap_key(lwe_bootstrap_key)?;
    ///
    /// assert_eq!(underlying_ptr, retrieved_slice.as_ptr());
    /// # Ok(())
    /// # }
    /// ```
    fn consume_retrieve_lwe_bootstrap_key(
        &mut self,
        bootstrap_key: LweBootstrapKeyMutView32<'data>,
    ) -> Result<&'data mut [u32], LweBootstrapKeyConsumingRetrievalError<Self::EngineError>> {
        Ok(unsafe { self.consume_retrieve_lwe_bootstrap_key_unchecked(bootstrap_key) })
    }

    unsafe fn consume_retrieve_lwe_bootstrap_key_unchecked(
        &mut self,
        bootstrap_key: LweBootstrapKeyMutView32<'data>,
    ) -> &'data mut [u32] {
        bootstrap_key.0.into_tensor().into_container()
    }
}

impl<'data>
    LweBootstrapKeyConsumingRetrievalEngine<LweBootstrapKeyMutView64<'data>, &'data mut [u64]>
    for DefaultEngine
{
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
    ///     *,
    /// };
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(2);
    /// let glwe_size = GlweSize(2);
    /// let polynomial_size = PolynomialSize(256);
    /// let level = DecompositionLevelCount(2);
    /// let base_log = DecompositionBaseLog(1);
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    ///
    /// let mut owned_container =
    ///     vec![0_u64; lwe_dimension.0 * level.0 * glwe_size.0 * glwe_size.0 * polynomial_size.0];
    ///
    /// let mut slice = owned_container.as_mut_slice();
    /// // Required as we can't borrow a mut slice more than once
    /// let underlying_ptr = slice.as_ptr();
    ///
    /// let lwe_bootstrap_key: LweBootstrapKeyMutView64 =
    ///     engine.create_lwe_bootstrap_key_from(slice, glwe_size, polynomial_size, base_log, level)?;
    /// let retrieved_slice = engine.consume_retrieve_lwe_bootstrap_key(lwe_bootstrap_key)?;
    ///
    /// assert_eq!(underlying_ptr, retrieved_slice.as_ptr());
    /// # Ok(())
    /// # }
    /// ```
    fn consume_retrieve_lwe_bootstrap_key(
        &mut self,
        bootstrap_key: LweBootstrapKeyMutView64<'data>,
    ) -> Result<&'data mut [u64], LweBootstrapKeyConsumingRetrievalError<Self::EngineError>> {
        Ok(unsafe { self.consume_retrieve_lwe_bootstrap_key_unchecked(bootstrap_key) })
    }

    unsafe fn consume_retrieve_lwe_bootstrap_key_unchecked(
        &mut self,
        bootstrap_key: LweBootstrapKeyMutView64<'data>,
    ) -> &'data mut [u64] {
        bootstrap_key.0.into_tensor().into_container()
    }
}

impl<'data> LweBootstrapKeyConsumingRetrievalEngine<LweBootstrapKeyView32<'data>, &'data [u32]>
    for DefaultEngine
{
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
    ///     *,
    /// };
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(2);
    /// let glwe_size = GlweSize(2);
    /// let polynomial_size = PolynomialSize(256);
    /// let level = DecompositionLevelCount(2);
    /// let base_log = DecompositionBaseLog(1);
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    ///
    /// let owned_container =
    ///     vec![0_u32; lwe_dimension.0 * level.0 * glwe_size.0 * glwe_size.0 * polynomial_size.0];
    ///
    /// let slice = owned_container.as_slice();
    ///
    /// let lwe_bootstrap_key: LweBootstrapKeyView32 =
    ///     engine.create_lwe_bootstrap_key_from(slice, glwe_size, polynomial_size, base_log, level)?;
    /// let retrieved_slice = engine.consume_retrieve_lwe_bootstrap_key(lwe_bootstrap_key)?;
    ///
    /// assert_eq!(slice, retrieved_slice);
    /// # Ok(())
    /// # }
    /// ```
    fn consume_retrieve_lwe_bootstrap_key(
        &mut self,
        bootstrap_key: LweBootstrapKeyView32<'data>,
    ) -> Result<&'data [u32], LweBootstrapKeyConsumingRetrievalError<Self::EngineError>> {
        Ok(unsafe { self.consume_retrieve_lwe_bootstrap_key_unchecked(bootstrap_key) })
    }

    unsafe fn consume_retrieve_lwe_bootstrap_key_unchecked(
        &mut self,
        bootstrap_key: LweBootstrapKeyView32<'data>,
    ) -> &'data [u32] {
        bootstrap_key.0.into_tensor().into_container()
    }
}

impl<'data> LweBootstrapKeyConsumingRetrievalEngine<LweBootstrapKeyView64<'data>, &'data [u64]>
    for DefaultEngine
{
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
    ///     *,
    /// };
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(2);
    /// let glwe_size = GlweSize(2);
    /// let polynomial_size = PolynomialSize(256);
    /// let level = DecompositionLevelCount(2);
    /// let base_log = DecompositionBaseLog(1);
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    ///
    /// let owned_container =
    ///     vec![0_u64; lwe_dimension.0 * level.0 * glwe_size.0 * glwe_size.0 * polynomial_size.0];
    ///
    /// let slice = owned_container.as_slice();
    ///
    /// let lwe_bootstrap_key: LweBootstrapKeyView64 =
    ///     engine.create_lwe_bootstrap_key_from(slice, glwe_size, polynomial_size, base_log, level)?;
    /// let retrieved_slice = engine.consume_retrieve_lwe_bootstrap_key(lwe_bootstrap_key)?;
    ///
    /// assert_eq!(slice, retrieved_slice);
    /// # Ok(())
    /// # }
    /// ```
    fn consume_retrieve_lwe_bootstrap_key(
        &mut self,
        bootstrap_key: LweBootstrapKeyView64<'data>,
    ) -> Result<&'data [u64], LweBootstrapKeyConsumingRetrievalError<Self::EngineError>> {
        Ok(unsafe { self.consume_retrieve_lwe_bootstrap_key_unchecked(bootstrap_key) })
    }

    unsafe fn consume_retrieve_lwe_bootstrap_key_unchecked(
        &mut self,
        bootstrap_key: LweBootstrapKeyView64<'data>,
    ) -> &'data [u64] {
        bootstrap_key.0.into_tensor().into_container()
    }
}
