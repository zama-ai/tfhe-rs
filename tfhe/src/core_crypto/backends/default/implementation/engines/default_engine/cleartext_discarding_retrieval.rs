use crate::core_crypto::backends::default::implementation::engines::DefaultEngine;
use crate::core_crypto::backends::default::implementation::entities::{
    Cleartext32, Cleartext64,
};
use crate::core_crypto::prelude::CleartextF64;
use crate::core_crypto::specification::engines::{
    CleartextDiscardingRetrievalEngine, CleartextDiscardingRetrievalError,
};

/// # Description:
/// Implementation of [`CleartextDiscardingRetrievalEngine`] for [`DefaultEngine`] that operates on
/// 32 bits integers.
impl CleartextDiscardingRetrievalEngine<Cleartext32, u32> for DefaultEngine {
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// let input: u32 = 3;
    /// let mut output: u32 = 0;
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let cleartext: Cleartext32 = engine.create_cleartext_from(&input)?;
    /// engine.discard_retrieve_cleartext(&mut output, &cleartext)?;
    ///
    /// assert_eq!(output, 3_u32);
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_retrieve_cleartext(
        &mut self,
        output: &mut u32,
        input: &Cleartext32,
    ) -> Result<(), CleartextDiscardingRetrievalError<Self::EngineError>> {
        unsafe { self.discard_retrieve_cleartext_unchecked(output, input) };
        Ok(())
    }

    unsafe fn discard_retrieve_cleartext_unchecked(
        &mut self,
        output: &mut u32,
        input: &Cleartext32,
    ) {
        *output = input.0 .0;
    }
}

/// # Description:
/// Implementation of [`CleartextDiscardingRetrievalEngine`] for [`DefaultEngine`] that operates on
/// 32 bits integers.
impl CleartextDiscardingRetrievalEngine<Cleartext64, u64> for DefaultEngine {
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// let input: u64 = 3;
    /// let mut output: u64 = 0;
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let cleartext: Cleartext64 = engine.create_cleartext_from(&input)?;
    /// engine.discard_retrieve_cleartext(&mut output, &cleartext)?;
    ///
    /// assert_eq!(output, 3_u64);
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_retrieve_cleartext(
        &mut self,
        output: &mut u64,
        input: &Cleartext64,
    ) -> Result<(), CleartextDiscardingRetrievalError<Self::EngineError>> {
        unsafe { self.discard_retrieve_cleartext_unchecked(output, input) };
        Ok(())
    }

    unsafe fn discard_retrieve_cleartext_unchecked(
        &mut self,
        output: &mut u64,
        input: &Cleartext64,
    ) {
        *output = input.0 .0;
    }
}

/// # Description:
/// Implementation of [`CleartextDiscardingRetrievalEngine`] for [`DefaultEngine`] that operates on
/// 64 bits floating point numbers.
impl CleartextDiscardingRetrievalEngine<CleartextF64, f64> for DefaultEngine {
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// let input: f64 = 3.;
    /// let mut output: f64 = 0.;
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let cleartext: CleartextF64 = engine.create_cleartext_from(&input)?;
    /// engine.discard_retrieve_cleartext(&mut output, &cleartext)?;
    ///
    /// assert_eq!(output, 3.0);
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_retrieve_cleartext(
        &mut self,
        output: &mut f64,
        input: &CleartextF64,
    ) -> Result<(), CleartextDiscardingRetrievalError<Self::EngineError>> {
        unsafe { self.discard_retrieve_cleartext_unchecked(output, input) };
        Ok(())
    }

    unsafe fn discard_retrieve_cleartext_unchecked(
        &mut self,
        output: &mut f64,
        input: &CleartextF64,
    ) {
        *output = input.0 .0;
    }
}
