use crate::core_crypto::backends::default::implementation::engines::DefaultEngine;
use crate::core_crypto::backends::default::implementation::entities::{
    PlaintextVector32, PlaintextVector64,
};
use crate::core_crypto::commons::crypto::encoding::PlaintextList as ImplPlaintextList;
use crate::core_crypto::specification::engines::{
    PlaintextVectorCreationEngine, PlaintextVectorCreationError,
};

/// # Description:
/// Implementation of [`PlaintextVectorCreationEngine`] for [`DefaultEngine`] that operates on
/// 32 bits integers.
impl PlaintextVectorCreationEngine<u32, PlaintextVector32> for DefaultEngine {
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
    /// #
    /// assert_eq!(plaintext_vector.plaintext_count(), PlaintextCount(3));
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn create_plaintext_vector_from(
        &mut self,
        input: &[u32],
    ) -> Result<PlaintextVector32, PlaintextVectorCreationError<Self::EngineError>> {
        if input.is_empty() {
            return Err(PlaintextVectorCreationError::EmptyInput);
        }
        Ok(unsafe { self.create_plaintext_vector_from_unchecked(input) })
    }

    unsafe fn create_plaintext_vector_from_unchecked(
        &mut self,
        input: &[u32],
    ) -> PlaintextVector32 {
        PlaintextVector32(ImplPlaintextList::from_container(input.to_vec()))
    }
}

/// # Description:
/// Implementation of [`PlaintextVectorCreationEngine`] for [`DefaultEngine`] that operates on
/// 64 bits integers.
impl PlaintextVectorCreationEngine<u64, PlaintextVector64> for DefaultEngine {
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{PlaintextCount, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = vec![3_u64 << 50; 3];
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let plaintext_vector: PlaintextVector64 = engine.create_plaintext_vector_from(&input)?;
    /// #
    /// assert_eq!(plaintext_vector.plaintext_count(), PlaintextCount(3));
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn create_plaintext_vector_from(
        &mut self,
        input: &[u64],
    ) -> Result<PlaintextVector64, PlaintextVectorCreationError<Self::EngineError>> {
        if input.is_empty() {
            return Err(PlaintextVectorCreationError::EmptyInput);
        }
        Ok(unsafe { self.create_plaintext_vector_from_unchecked(input) })
    }

    unsafe fn create_plaintext_vector_from_unchecked(
        &mut self,
        input: &[u64],
    ) -> PlaintextVector64 {
        PlaintextVector64(ImplPlaintextList::from_container(input.to_vec()))
    }
}
