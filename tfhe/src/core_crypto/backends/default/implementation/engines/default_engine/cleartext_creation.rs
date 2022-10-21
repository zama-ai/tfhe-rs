use crate::core_crypto::backends::default::implementation::engines::DefaultEngine;
use crate::core_crypto::backends::default::implementation::entities::{Cleartext32, Cleartext64};
use crate::core_crypto::commons::crypto::encoding::Cleartext as ImplCleartext;
use crate::core_crypto::prelude::CleartextF64;
use crate::core_crypto::specification::engines::{CleartextCreationEngine, CleartextCreationError};

/// # Description:
/// Implementation of [`CleartextCreationEngine`] for [`DefaultEngine`] that operates on 32 bits
/// integers.
impl CleartextCreationEngine<u32, Cleartext32> for DefaultEngine {
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// let input: u32 = 3;
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let cleartext: Cleartext32 = engine.create_cleartext_from(&input)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn create_cleartext_from(
        &mut self,
        input: &u32,
    ) -> Result<Cleartext32, CleartextCreationError<Self::EngineError>> {
        Ok(unsafe { self.create_cleartext_from_unchecked(input) })
    }

    unsafe fn create_cleartext_from_unchecked(&mut self, input: &u32) -> Cleartext32 {
        Cleartext32(ImplCleartext(*input))
    }
}

/// # Description:
/// Implementation of [`CleartextCreationEngine`] for [`DefaultEngine`] that operates on 64 bits
/// integers.
impl CleartextCreationEngine<u64, Cleartext64> for DefaultEngine {
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// let input: u64 = 3;
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let cleartext: Cleartext64 = engine.create_cleartext_from(&input)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn create_cleartext_from(
        &mut self,
        input: &u64,
    ) -> Result<Cleartext64, CleartextCreationError<Self::EngineError>> {
        Ok(unsafe { self.create_cleartext_from_unchecked(input) })
    }

    unsafe fn create_cleartext_from_unchecked(&mut self, input: &u64) -> Cleartext64 {
        Cleartext64(ImplCleartext(*input))
    }
}

/// # Description:
/// Implementation of [`CleartextCreationEngine`] for [`DefaultEngine`] that operates on 64 bits
/// floating point numbers.
impl CleartextCreationEngine<f64, CleartextF64> for DefaultEngine {
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// let input: f64 = 3.;
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let cleartext: CleartextF64 = engine.create_cleartext_from(&input)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn create_cleartext_from(
        &mut self,
        value: &f64,
    ) -> Result<CleartextF64, CleartextCreationError<Self::EngineError>> {
        Ok(unsafe { self.create_cleartext_from_unchecked(value) })
    }

    unsafe fn create_cleartext_from_unchecked(&mut self, value: &f64) -> CleartextF64 {
        CleartextF64(ImplCleartext(*value))
    }
}
