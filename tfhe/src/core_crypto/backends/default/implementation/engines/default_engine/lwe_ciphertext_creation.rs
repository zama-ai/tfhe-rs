use crate::core_crypto::backends::default::implementation::engines::DefaultEngine;
use crate::core_crypto::backends::default::implementation::entities::{
    LweCiphertext32, LweCiphertext64, LweCiphertextMutView32, LweCiphertextMutView64,
    LweCiphertextView32, LweCiphertextView64,
};
use crate::core_crypto::commons::crypto::lwe::LweCiphertext as ImplLweCiphertext;
use crate::core_crypto::specification::engines::{
    LweCiphertextCreationEngine, LweCiphertextCreationError,
};

/// # Description:
/// Implementation of [`LweCiphertextCreationEngine`] for [`DefaultEngine`] which returns an
/// [`LweCiphertext32`].
impl LweCiphertextCreationEngine<Vec<u32>, LweCiphertext32> for DefaultEngine {
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{LweSize, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // Here we create a container outside of the engine
    /// // Note that the size here is just for demonstration purposes and should not be chosen
    /// // without proper security analysis for production
    /// let lwe_size = LweSize(128);
    /// let owned_container = vec![0_u32; lwe_size.0];
    ///
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let ciphertext: LweCiphertext32 = engine.create_lwe_ciphertext_from(owned_container)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn create_lwe_ciphertext_from(
        &mut self,
        container: Vec<u32>,
    ) -> Result<LweCiphertext32, LweCiphertextCreationError<Self::EngineError>> {
        LweCiphertextCreationError::<Self::EngineError>::perform_generic_checks(container.len())?;
        Ok(unsafe { self.create_lwe_ciphertext_from_unchecked(container) })
    }

    unsafe fn create_lwe_ciphertext_from_unchecked(
        &mut self,
        container: Vec<u32>,
    ) -> LweCiphertext32 {
        LweCiphertext32(ImplLweCiphertext::from_container(container))
    }
}

/// # Description:
/// Implementation of [`LweCiphertextCreationEngine`] for [`DefaultEngine`] which returns an
/// [`LweCiphertext64`].
impl LweCiphertextCreationEngine<Vec<u64>, LweCiphertext64> for DefaultEngine {
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{LweSize, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // Here we create a container outside of the engine
    /// // Note that the size here is just for demonstration purposes and should not be chosen
    /// // without proper security analysis for production
    /// let lwe_size = LweSize(128);
    /// let owned_container = vec![0_u64; lwe_size.0];
    ///
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let ciphertext: LweCiphertext64 = engine.create_lwe_ciphertext_from(owned_container)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn create_lwe_ciphertext_from(
        &mut self,
        container: Vec<u64>,
    ) -> Result<LweCiphertext64, LweCiphertextCreationError<Self::EngineError>> {
        LweCiphertextCreationError::<Self::EngineError>::perform_generic_checks(container.len())?;
        Ok(unsafe { self.create_lwe_ciphertext_from_unchecked(container) })
    }

    unsafe fn create_lwe_ciphertext_from_unchecked(
        &mut self,
        container: Vec<u64>,
    ) -> LweCiphertext64 {
        LweCiphertext64(ImplLweCiphertext::from_container(container))
    }
}

/// # Description:
/// Implementation of [`LweCiphertextCreationEngine`] for [`DefaultEngine`] which returns an
/// immutable [`LweCiphertextView32`] that does not own its memory.
impl<'data> LweCiphertextCreationEngine<&'data [u32], LweCiphertextView32<'data>>
    for DefaultEngine
{
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{LweSize, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // Here we create a container outside of the engine
    /// // Note that the size here is just for demonstration purposes and should not be chosen
    /// // without proper security analysis for production
    /// let lwe_size = LweSize(128);
    /// let mut owned_container = vec![0_u32; lwe_size.0];
    ///
    /// let slice = &owned_container[..];
    ///
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let ciphertext_view: LweCiphertextView32 = engine.create_lwe_ciphertext_from(slice)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn create_lwe_ciphertext_from(
        &mut self,
        container: &'data [u32],
    ) -> Result<LweCiphertextView32<'data>, LweCiphertextCreationError<Self::EngineError>> {
        LweCiphertextCreationError::<Self::EngineError>::perform_generic_checks(container.len())?;
        Ok(unsafe { self.create_lwe_ciphertext_from_unchecked(container) })
    }

    unsafe fn create_lwe_ciphertext_from_unchecked(
        &mut self,
        container: &'data [u32],
    ) -> LweCiphertextView32<'data> {
        LweCiphertextView32(ImplLweCiphertext::from_container(container))
    }
}

/// # Description:
/// Implementation of [`LweCiphertextCreationEngine`] for [`DefaultEngine`] which returns a mutable
/// [`LweCiphertextMutView32`] that does not own its memory.
impl<'data> LweCiphertextCreationEngine<&'data mut [u32], LweCiphertextMutView32<'data>>
    for DefaultEngine
{
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{LweSize, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // Here we create a container outside of the engine
    /// // Note that the size here is just for demonstration purposes and should not be chosen
    /// // without proper security analysis for production
    /// let lwe_size = LweSize(128);
    /// let mut owned_container = vec![0_u32; lwe_size.0];
    ///
    /// let slice = &mut owned_container[..];
    ///
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let ciphertext_view: LweCiphertextMutView32 = engine.create_lwe_ciphertext_from(slice)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn create_lwe_ciphertext_from(
        &mut self,
        container: &'data mut [u32],
    ) -> Result<LweCiphertextMutView32<'data>, LweCiphertextCreationError<Self::EngineError>> {
        LweCiphertextCreationError::<Self::EngineError>::perform_generic_checks(container.len())?;
        Ok(unsafe { self.create_lwe_ciphertext_from_unchecked(container) })
    }

    unsafe fn create_lwe_ciphertext_from_unchecked(
        &mut self,
        container: &'data mut [u32],
    ) -> LweCiphertextMutView32<'data> {
        LweCiphertextMutView32(ImplLweCiphertext::from_container(container))
    }
}

/// # Description:
/// Implementation of [`LweCiphertextCreationEngine`] for [`DefaultEngine`] which returns an
/// immutable [`LweCiphertextView64`] that does not own its memory.
impl<'data> LweCiphertextCreationEngine<&'data [u64], LweCiphertextView64<'data>>
    for DefaultEngine
{
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // Here we create a container outside of the engine
    /// // Note that the size here is just for demonstration purposes and should not be chosen
    /// // without proper security analysis for production
    /// let mut owned_container = vec![0_u64; 128];
    ///
    /// let slice = &owned_container[..];
    ///
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let ciphertext_view: LweCiphertextView64 = engine.create_lwe_ciphertext_from(slice)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn create_lwe_ciphertext_from(
        &mut self,
        container: &'data [u64],
    ) -> Result<LweCiphertextView64<'data>, LweCiphertextCreationError<Self::EngineError>> {
        LweCiphertextCreationError::<Self::EngineError>::perform_generic_checks(container.len())?;
        Ok(unsafe { self.create_lwe_ciphertext_from_unchecked(container) })
    }

    unsafe fn create_lwe_ciphertext_from_unchecked(
        &mut self,
        container: &'data [u64],
    ) -> LweCiphertextView64<'data> {
        LweCiphertextView64(ImplLweCiphertext::from_container(container))
    }
}

/// # Description:
/// Implementation of [`LweCiphertextCreationEngine`] for [`DefaultEngine`] which returns a mutable
/// [`LweCiphertextMutView64`] that does not own its memory.
impl<'data> LweCiphertextCreationEngine<&'data mut [u64], LweCiphertextMutView64<'data>>
    for DefaultEngine
{
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{LweSize, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // Here we create a container outside of the engine
    /// // Note that the size here is just for demonstration purposes and should not be chosen
    /// // without proper security analysis for production
    /// let lwe_size = LweSize(128);
    /// let mut owned_container = vec![0_u64; lwe_size.0];
    ///
    /// let slice = &mut owned_container[..];
    ///
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let ciphertext_view: LweCiphertextMutView64 = engine.create_lwe_ciphertext_from(slice)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn create_lwe_ciphertext_from(
        &mut self,
        container: &'data mut [u64],
    ) -> Result<LweCiphertextMutView64<'data>, LweCiphertextCreationError<Self::EngineError>> {
        LweCiphertextCreationError::<Self::EngineError>::perform_generic_checks(container.len())?;
        Ok(unsafe { self.create_lwe_ciphertext_from_unchecked(container) })
    }

    unsafe fn create_lwe_ciphertext_from_unchecked(
        &mut self,
        container: &'data mut [u64],
    ) -> LweCiphertextMutView64<'data> {
        LweCiphertextMutView64(ImplLweCiphertext::from_container(container))
    }
}
