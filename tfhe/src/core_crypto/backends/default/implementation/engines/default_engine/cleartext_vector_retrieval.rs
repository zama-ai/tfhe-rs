use crate::core_crypto::backends::default::implementation::engines::DefaultEngine;
use crate::core_crypto::backends::default::implementation::entities::{
    CleartextVector32, CleartextVector64,
};
use crate::core_crypto::commons::math::tensor::AsRefTensor;
use crate::core_crypto::prelude::CleartextVectorF64;
use crate::core_crypto::specification::engines::{
    CleartextVectorRetrievalEngine, CleartextVectorRetrievalError,
};

/// # Description:
/// Implementation of [`CleartextVectorRetrievalEngine`] for [`DefaultEngine`] that operates on 64
/// bits integers.
impl CleartextVectorRetrievalEngine<CleartextVector32, u32> for DefaultEngine {
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
    /// let retrieved: Vec<u32> = engine.retrieve_cleartext_vector(&cleartext_vector)?;
    ///
    /// assert_eq!(retrieved[0], 3_u32);
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn retrieve_cleartext_vector(
        &mut self,
        cleartext: &CleartextVector32,
    ) -> Result<Vec<u32>, CleartextVectorRetrievalError<Self::EngineError>> {
        Ok(unsafe { self.retrieve_cleartext_vector_unchecked(cleartext) })
    }

    unsafe fn retrieve_cleartext_vector_unchecked(
        &mut self,
        cleartext: &CleartextVector32,
    ) -> Vec<u32> {
        cleartext.0.as_tensor().as_container().to_vec()
    }
}

/// # Description:
/// Implementation of [`CleartextVectorRetrievalEngine`] for [`DefaultEngine`] that operates on 32
/// bits integers.
impl CleartextVectorRetrievalEngine<CleartextVector64, u64> for DefaultEngine {
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
    /// let retrieved: Vec<u64> = engine.retrieve_cleartext_vector(&cleartext_vector)?;
    ///
    /// assert_eq!(retrieved[0], 3_u64);
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn retrieve_cleartext_vector(
        &mut self,
        cleartext: &CleartextVector64,
    ) -> Result<Vec<u64>, CleartextVectorRetrievalError<Self::EngineError>> {
        Ok(unsafe { self.retrieve_cleartext_vector_unchecked(cleartext) })
    }

    unsafe fn retrieve_cleartext_vector_unchecked(
        &mut self,
        cleartext: &CleartextVector64,
    ) -> Vec<u64> {
        cleartext.0.as_tensor().as_container().to_vec()
    }
}

/// # Description:
/// Implementation of [`CleartextVectorRetrievalEngine`] for [`DefaultEngine`] that operates on 64
/// bits floating point numbers.
impl CleartextVectorRetrievalEngine<CleartextVectorF64, f64> for DefaultEngine {
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
    /// let retrieved: Vec<f64> = engine.retrieve_cleartext_vector(&cleartext_vector)?;
    ///
    /// assert_eq!(retrieved[0], 3.0_f64);
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn retrieve_cleartext_vector(
        &mut self,
        cleartext: &CleartextVectorF64,
    ) -> Result<Vec<f64>, CleartextVectorRetrievalError<Self::EngineError>> {
        Ok(unsafe { self.retrieve_cleartext_vector_unchecked(cleartext) })
    }

    unsafe fn retrieve_cleartext_vector_unchecked(
        &mut self,
        cleartext: &CleartextVectorF64,
    ) -> Vec<f64> {
        cleartext.0.as_tensor().as_container().to_vec()
    }
}
