use crate::core_crypto::backends::default::implementation::engines::DefaultEngine;
use crate::core_crypto::backends::default::implementation::entities::{
    Plaintext32, Plaintext64,
};
use crate::core_crypto::specification::engines::{
    PlaintextDiscardingRetrievalEngine, PlaintextDiscardingRetrievalError,
};

/// # Description:
/// Implementation of [`PlaintextDiscardingRetrievalEngine`] for [`DefaultEngine`] that operates on
/// 32 bits integers.
impl PlaintextDiscardingRetrievalEngine<Plaintext32, u32> for DefaultEngine {
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = 3_u32 << 20;
    /// let mut output = 0_u32;
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let plaintext: Plaintext32 = engine.create_plaintext_from(&input)?;
    /// engine.discard_retrieve_plaintext(&mut output, &plaintext)?;
    ///
    /// assert_eq!(output, 3_u32 << 20);
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_retrieve_plaintext(
        &mut self,
        output: &mut u32,
        input: &Plaintext32,
    ) -> Result<(), PlaintextDiscardingRetrievalError<Self::EngineError>> {
        unsafe { self.discard_retrieve_plaintext_unchecked(output, input) };
        Ok(())
    }

    unsafe fn discard_retrieve_plaintext_unchecked(
        &mut self,
        output: &mut u32,
        input: &Plaintext32,
    ) {
        *output = input.0 .0;
    }
}

impl PlaintextDiscardingRetrievalEngine<Plaintext64, u64> for DefaultEngine {
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = 3_u64 << 20;
    /// let mut output = 0_u64;
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let plaintext: Plaintext64 = engine.create_plaintext_from(&input)?;
    /// engine.discard_retrieve_plaintext(&mut output, &plaintext)?;
    ///
    /// assert_eq!(output, 3_u64 << 20);
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_retrieve_plaintext(
        &mut self,
        output: &mut u64,
        input: &Plaintext64,
    ) -> Result<(), PlaintextDiscardingRetrievalError<Self::EngineError>> {
        unsafe { self.discard_retrieve_plaintext_unchecked(output, input) };
        Ok(())
    }

    unsafe fn discard_retrieve_plaintext_unchecked(
        &mut self,
        output: &mut u64,
        input: &Plaintext64,
    ) {
        *output = input.0 .0;
    }
}
