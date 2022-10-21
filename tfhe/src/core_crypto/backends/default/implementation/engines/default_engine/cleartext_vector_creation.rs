use crate::core_crypto::backends::default::implementation::engines::DefaultEngine;
use crate::core_crypto::backends::default::implementation::entities::{
    CleartextVector32, CleartextVector64,
};
use crate::core_crypto::commons::crypto::encoding::CleartextList as ImplCleartextList;
use crate::core_crypto::prelude::CleartextVectorF64;
use crate::core_crypto::specification::engines::{
    CleartextVectorCreationEngine, CleartextVectorCreationError,
};

/// # Description:
/// Implementation of [`CleartextVectorCreationEngine`] for [`DefaultEngine`] that operates on 32
/// bits integers.
impl CleartextVectorCreationEngine<u32, CleartextVector32> for DefaultEngine {
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{CleartextCount, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// let input = vec![3_u32; 100];
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let cleartext_vector: CleartextVector32 = engine.create_cleartext_vector_from(&input)?;
    /// #
    /// assert_eq!(cleartext_vector.cleartext_count(), CleartextCount(100));
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn create_cleartext_vector_from(
        &mut self,
        input: &[u32],
    ) -> Result<CleartextVector32, CleartextVectorCreationError<Self::EngineError>> {
        CleartextVectorCreationError::perform_generic_checks(input)?;
        Ok(unsafe { self.create_cleartext_vector_from_unchecked(input) })
    }

    unsafe fn create_cleartext_vector_from_unchecked(
        &mut self,
        input: &[u32],
    ) -> CleartextVector32 {
        CleartextVector32(ImplCleartextList::from_container(input.to_vec()))
    }
}

/// # Description:
/// Implementation of [`CleartextVectorCreationEngine`] for [`DefaultEngine`] that operates on 64
/// bits integers.
impl CleartextVectorCreationEngine<u64, CleartextVector64> for DefaultEngine {
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{CleartextCount, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// let input = vec![3_u64; 100];
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let cleartext_vector: CleartextVector64 = engine.create_cleartext_vector_from(&input)?;
    /// #
    /// assert_eq!(cleartext_vector.cleartext_count(), CleartextCount(100));
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn create_cleartext_vector_from(
        &mut self,
        input: &[u64],
    ) -> Result<CleartextVector64, CleartextVectorCreationError<Self::EngineError>> {
        CleartextVectorCreationError::perform_generic_checks(input)?;
        Ok(unsafe { self.create_cleartext_vector_from_unchecked(input) })
    }

    unsafe fn create_cleartext_vector_from_unchecked(
        &mut self,
        input: &[u64],
    ) -> CleartextVector64 {
        CleartextVector64(ImplCleartextList::from_container(input.to_vec()))
    }
}

/// # Description:
/// Implementation of [`CleartextVectorCreationEngine`] for [`DefaultEngine`] that operates on 64
/// bits floating point numbers.
impl CleartextVectorCreationEngine<f64, CleartextVectorF64> for DefaultEngine {
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{CleartextCount, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// let input = vec![3.0_f64; 100];
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let cleartext_vector: CleartextVectorF64 = engine.create_cleartext_vector_from(&input)?;
    /// #
    /// assert_eq!(cleartext_vector.cleartext_count(), CleartextCount(100));
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn create_cleartext_vector_from(
        &mut self,
        values: &[f64],
    ) -> Result<CleartextVectorF64, CleartextVectorCreationError<Self::EngineError>> {
        CleartextVectorCreationError::perform_generic_checks(values)?;
        Ok(unsafe { self.create_cleartext_vector_from_unchecked(values) })
    }

    unsafe fn create_cleartext_vector_from_unchecked(
        &mut self,
        values: &[f64],
    ) -> CleartextVectorF64 {
        CleartextVectorF64(ImplCleartextList::from_container(values.to_vec()))
    }
}
