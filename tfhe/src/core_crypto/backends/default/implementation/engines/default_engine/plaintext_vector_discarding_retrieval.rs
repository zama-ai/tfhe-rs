use crate::core_crypto::backends::default::implementation::engines::DefaultEngine;
use crate::core_crypto::backends::default::implementation::entities::{
    PlaintextVector32, PlaintextVector64,
};
use crate::core_crypto::commons::math::tensor::AsRefTensor;
use crate::core_crypto::specification::engines::{
    PlaintextVectorDiscardingRetrievalEngine, PlaintextVectorDiscardingRetrievalError,
};

/// # Description:
/// Implementation of [`PlaintextVectorDiscardingRetrievalEngine`] for [`DefaultEngine`] that
/// operates on 32 bits integers.
impl PlaintextVectorDiscardingRetrievalEngine<PlaintextVector32, u32> for DefaultEngine {
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{PlaintextCount, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u32 << 20; 3];
    /// let mut output = vec![0_u32; 3];
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let plaintext_vector: PlaintextVector32 = engine.create_plaintext_vector_from(&input)?;
    /// engine.discard_retrieve_plaintext_vector(output.as_mut_slice(), &plaintext_vector)?;
    /// #
    /// assert_eq!(output[0], 3_u32 << 20);
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_retrieve_plaintext_vector(
        &mut self,
        output: &mut [u32],
        input: &PlaintextVector32,
    ) -> Result<(), PlaintextVectorDiscardingRetrievalError<Self::EngineError>> {
        PlaintextVectorDiscardingRetrievalError::perform_generic_checks(output, input)?;
        unsafe { self.discard_retrieve_plaintext_vector_unchecked(output, input) };
        Ok(())
    }

    unsafe fn discard_retrieve_plaintext_vector_unchecked(
        &mut self,
        output: &mut [u32],
        input: &PlaintextVector32,
    ) {
        output.copy_from_slice(input.0.as_tensor().as_container().as_slice());
    }
}

/// # Description:
/// Implementation of [`PlaintextVectorDiscardingRetrievalEngine`] for [`DefaultEngine`] that
/// operates on 64 bits integers.
impl PlaintextVectorDiscardingRetrievalEngine<PlaintextVector64, u64> for DefaultEngine {
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{PlaintextCount, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u64 << 20; 3];
    /// let mut output = vec![0_u64; 3];
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let plaintext_vector: PlaintextVector64 = engine.create_plaintext_vector_from(&input)?;
    /// engine.discard_retrieve_plaintext_vector(output.as_mut_slice(), &plaintext_vector)?;
    /// #
    /// assert_eq!(output[0], 3_u64 << 20);
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_retrieve_plaintext_vector(
        &mut self,
        output: &mut [u64],
        input: &PlaintextVector64,
    ) -> Result<(), PlaintextVectorDiscardingRetrievalError<Self::EngineError>> {
        PlaintextVectorDiscardingRetrievalError::perform_generic_checks(output, input)?;
        unsafe { self.discard_retrieve_plaintext_vector_unchecked(output, input) };
        Ok(())
    }

    unsafe fn discard_retrieve_plaintext_vector_unchecked(
        &mut self,
        output: &mut [u64],
        input: &PlaintextVector64,
    ) {
        output.copy_from_slice(input.0.as_tensor().as_container().as_slice());
    }
}
