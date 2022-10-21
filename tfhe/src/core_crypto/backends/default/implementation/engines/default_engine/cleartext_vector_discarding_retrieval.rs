use crate::core_crypto::backends::default::implementation::engines::DefaultEngine;
use crate::core_crypto::backends::default::implementation::entities::{
    CleartextVector32, CleartextVector64,
};
use crate::core_crypto::commons::math::tensor::AsRefTensor;
use crate::core_crypto::prelude::CleartextVectorF64;
use crate::core_crypto::specification::engines::{
    CleartextVectorDiscardingRetrievalEngine, CleartextVectorDiscardingRetrievalError,
};

/// # Description:
/// Implementation of [`CleartextVectorDiscardingRetrievalEngine`] for [`DefaultEngine`] that
/// operates on 32 bits integers.
impl CleartextVectorDiscardingRetrievalEngine<CleartextVector32, u32> for DefaultEngine {
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{CleartextCount, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// let input = vec![3_u32; 100];
    /// let mut retrieved = vec![0_u32; 100];
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let cleartext_vector: CleartextVector32 = engine.create_cleartext_vector_from(&input)?;
    /// engine.discard_retrieve_cleartext_vector(retrieved.as_mut_slice(), &cleartext_vector)?;
    ///
    /// assert_eq!(retrieved[0], 3_u32);
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_retrieve_cleartext_vector(
        &mut self,
        output: &mut [u32],
        input: &CleartextVector32,
    ) -> Result<(), CleartextVectorDiscardingRetrievalError<Self::EngineError>> {
        CleartextVectorDiscardingRetrievalError::perform_generic_checks(output, input)?;
        unsafe { self.discard_retrieve_cleartext_vector_unchecked(output, input) };
        Ok(())
    }

    unsafe fn discard_retrieve_cleartext_vector_unchecked(
        &mut self,
        output: &mut [u32],
        input: &CleartextVector32,
    ) {
        output.copy_from_slice(input.0.as_tensor().as_container().as_slice());
    }
}

/// # Description:
/// Implementation of [`CleartextVectorDiscardingRetrievalEngine`] for [`DefaultEngine`] that
/// operates on 32 bits integers.
impl CleartextVectorDiscardingRetrievalEngine<CleartextVector64, u64> for DefaultEngine {
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{CleartextCount, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// let input = vec![3_u64; 100];
    /// let mut retrieved = vec![0_u64; 100];
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let cleartext_vector: CleartextVector64 = engine.create_cleartext_vector_from(&input)?;
    /// engine.discard_retrieve_cleartext_vector(retrieved.as_mut_slice(), &cleartext_vector)?;
    ///
    /// assert_eq!(retrieved[0], 3_u64);
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_retrieve_cleartext_vector(
        &mut self,
        output: &mut [u64],
        input: &CleartextVector64,
    ) -> Result<(), CleartextVectorDiscardingRetrievalError<Self::EngineError>> {
        CleartextVectorDiscardingRetrievalError::perform_generic_checks(output, input)?;
        unsafe { self.discard_retrieve_cleartext_vector_unchecked(output, input) };
        Ok(())
    }

    unsafe fn discard_retrieve_cleartext_vector_unchecked(
        &mut self,
        output: &mut [u64],
        input: &CleartextVector64,
    ) {
        output.copy_from_slice(input.0.as_tensor().as_container().as_slice());
    }
}

/// # Description:
/// Implementation of [`CleartextVectorDiscardingRetrievalEngine`] for [`DefaultEngine`] that
/// operates on 64 bits floating point numbers.
impl CleartextVectorDiscardingRetrievalEngine<CleartextVectorF64, f64> for DefaultEngine {
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{CleartextCount, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// let input = vec![3.0_f64; 100];
    /// let mut retrieved = vec![0.0_f64; 100];
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let cleartext_vector: CleartextVectorF64 = engine.create_cleartext_vector_from(&input)?;
    /// engine.discard_retrieve_cleartext_vector(retrieved.as_mut_slice(), &cleartext_vector)?;
    ///
    /// assert_eq!(retrieved[0], 3.0_f64);
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_retrieve_cleartext_vector(
        &mut self,
        output: &mut [f64],
        input: &CleartextVectorF64,
    ) -> Result<(), CleartextVectorDiscardingRetrievalError<Self::EngineError>> {
        CleartextVectorDiscardingRetrievalError::perform_generic_checks(output, input)?;
        unsafe { self.discard_retrieve_cleartext_vector_unchecked(output, input) };
        Ok(())
    }

    unsafe fn discard_retrieve_cleartext_vector_unchecked(
        &mut self,
        output: &mut [f64],
        input: &CleartextVectorF64,
    ) {
        output.copy_from_slice(input.0.as_tensor().as_container().as_slice());
    }
}
