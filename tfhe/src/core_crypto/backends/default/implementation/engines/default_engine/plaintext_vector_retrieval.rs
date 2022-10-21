use crate::core_crypto::backends::default::implementation::engines::DefaultEngine;
use crate::core_crypto::backends::default::implementation::entities::{
    PlaintextVector32, PlaintextVector64,
};
use crate::core_crypto::commons::math::tensor::AsRefTensor;
use crate::core_crypto::specification::engines::{
    PlaintextVectorRetrievalEngine, PlaintextVectorRetrievalError,
};

/// # Description:
/// Implementation of [`PlaintextVectorRetrievalEngine`] for [`DefaultEngine`] that operates on 32
/// bits integers.
impl PlaintextVectorRetrievalEngine<PlaintextVector32, u32> for DefaultEngine {
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{PlaintextCount, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u32 << 20; 3];
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let plaintext_vector: PlaintextVector32 = engine.create_plaintext_vector_from(&input)?;
    /// let output: Vec<u32> = engine.retrieve_plaintext_vector(&plaintext_vector)?;
    /// #
    /// assert_eq!(output[0], 3_u32 << 20);
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn retrieve_plaintext_vector(
        &mut self,
        plaintext: &PlaintextVector32,
    ) -> Result<Vec<u32>, PlaintextVectorRetrievalError<Self::EngineError>> {
        Ok(unsafe { self.retrieve_plaintext_vector_unchecked(plaintext) })
    }

    unsafe fn retrieve_plaintext_vector_unchecked(
        &mut self,
        plaintext: &PlaintextVector32,
    ) -> Vec<u32> {
        plaintext.0.as_tensor().as_container().to_vec()
    }
}

/// # Description:
/// Implementation of [`PlaintextVectorRetrievalEngine`] for [`DefaultEngine`] that operates on 64
/// bits integers.
impl PlaintextVectorRetrievalEngine<PlaintextVector64, u64> for DefaultEngine {
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{PlaintextCount, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u64 << 20; 3];
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let plaintext_vector: PlaintextVector64 = engine.create_plaintext_vector_from(&input)?;
    /// let output: Vec<u64> = engine.retrieve_plaintext_vector(&plaintext_vector)?;
    /// #
    /// assert_eq!(output[0], 3_u64 << 20);
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn retrieve_plaintext_vector(
        &mut self,
        plaintext: &PlaintextVector64,
    ) -> Result<Vec<u64>, PlaintextVectorRetrievalError<Self::EngineError>> {
        Ok(unsafe { self.retrieve_plaintext_vector_unchecked(plaintext) })
    }

    unsafe fn retrieve_plaintext_vector_unchecked(
        &mut self,
        plaintext: &PlaintextVector64,
    ) -> Vec<u64> {
        plaintext.0.as_tensor().as_container().to_vec()
    }
}
