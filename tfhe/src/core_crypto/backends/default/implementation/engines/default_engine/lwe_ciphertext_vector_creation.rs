use crate::core_crypto::backends::default::implementation::engines::DefaultEngine;
use crate::core_crypto::backends::default::implementation::entities::{
    LweCiphertextVectorMutView64, LweCiphertextVectorView64,
};
use crate::core_crypto::commons::crypto::lwe::LweList as ImplLweList;
use crate::core_crypto::prelude::{
    LweCiphertextVector32, LweCiphertextVector64, LweCiphertextVectorMutView32,
    LweCiphertextVectorView32, LweSize,
};
use crate::core_crypto::specification::engines::{
    LweCiphertextVectorCreationEngine, LweCiphertextVectorCreationError,
};

/// # Description:
/// Implementation of [`LweCiphertextVectorCreationEngine`] for [`DefaultEngine`] which returns a
/// [`LweCiphertextVector32`].
impl LweCiphertextVectorCreationEngine<Vec<u32>, LweCiphertextVector32> for DefaultEngine {
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // Here we create a container outside of the engine
    /// // Note that the size here is just for demonstration purposes and should not be chosen
    /// // without proper security analysis for production
    /// let lwe_size = LweSize(16);
    /// let lwe_count = LweCiphertextCount(3);
    /// let mut owned_container = vec![0_u32; lwe_size.0 * lwe_count.0];
    ///
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let ciphertext_vector: LweCiphertextVector32 =
    ///     engine.create_lwe_ciphertext_vector_from(owned_container, lwe_size)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn create_lwe_ciphertext_vector_from(
        &mut self,
        container: Vec<u32>,
        lwe_size: LweSize,
    ) -> Result<LweCiphertextVector32, LweCiphertextVectorCreationError<Self::EngineError>> {
        LweCiphertextVectorCreationError::<Self::EngineError>::perform_generic_checks(
            container.len(),
        )?;
        Ok(unsafe { self.create_lwe_ciphertext_vector_from_unchecked(container, lwe_size) })
    }

    unsafe fn create_lwe_ciphertext_vector_from_unchecked(
        &mut self,
        container: Vec<u32>,
        lwe_size: LweSize,
    ) -> LweCiphertextVector32 {
        LweCiphertextVector32(ImplLweList::from_container(container, lwe_size))
    }
}

/// # Description:
/// Implementation of [`LweCiphertextVectorCreationEngine`] for [`DefaultEngine`] which returns a
/// [`LweCiphertextVector64`].
impl LweCiphertextVectorCreationEngine<Vec<u64>, LweCiphertextVector64> for DefaultEngine {
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // Here we create a container outside of the engine
    /// // Note that the size here is just for demonstration purposes and should not be chosen
    /// // without proper security analysis for production
    /// let lwe_size = LweSize(16);
    /// let lwe_count = LweCiphertextCount(3);
    /// let mut owned_container = vec![0_u64; lwe_size.0 * lwe_count.0];
    ///
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let ciphertext_vector: LweCiphertextVector64 =
    ///     engine.create_lwe_ciphertext_vector_from(owned_container, lwe_size)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn create_lwe_ciphertext_vector_from(
        &mut self,
        container: Vec<u64>,
        lwe_size: LweSize,
    ) -> Result<LweCiphertextVector64, LweCiphertextVectorCreationError<Self::EngineError>> {
        LweCiphertextVectorCreationError::<Self::EngineError>::perform_generic_checks(
            container.len(),
        )?;
        Ok(unsafe { self.create_lwe_ciphertext_vector_from_unchecked(container, lwe_size) })
    }

    unsafe fn create_lwe_ciphertext_vector_from_unchecked(
        &mut self,
        container: Vec<u64>,
        lwe_size: LweSize,
    ) -> LweCiphertextVector64 {
        LweCiphertextVector64(ImplLweList::from_container(container, lwe_size))
    }
}

/// # Description:
/// Implementation of [`LweCiphertextVectorCreationEngine`] for [`DefaultEngine`] which returns an
/// immutable [`LweCiphertextVectorView32`] that does not own its memory.
impl<'data> LweCiphertextVectorCreationEngine<&'data [u32], LweCiphertextVectorView32<'data>>
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
    /// let lwe_size = LweSize(16);
    /// let lwe_count = LweCiphertextCount(3);
    /// let mut owned_container = vec![0_u32; lwe_size.0 * lwe_count.0];
    ///
    /// let slice = &owned_container[..];
    ///
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let ciphertext_vector_view: LweCiphertextVectorView32 =
    ///     engine.create_lwe_ciphertext_vector_from(slice, lwe_size)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn create_lwe_ciphertext_vector_from(
        &mut self,
        container: &'data [u32],
        lwe_size: LweSize,
    ) -> Result<LweCiphertextVectorView32<'data>, LweCiphertextVectorCreationError<Self::EngineError>>
    {
        LweCiphertextVectorCreationError::<Self::EngineError>::perform_generic_checks(
            container.len(),
        )?;
        Ok(unsafe { self.create_lwe_ciphertext_vector_from_unchecked(container, lwe_size) })
    }

    unsafe fn create_lwe_ciphertext_vector_from_unchecked(
        &mut self,
        container: &'data [u32],
        lwe_size: LweSize,
    ) -> LweCiphertextVectorView32<'data> {
        LweCiphertextVectorView32(ImplLweList::from_container(container, lwe_size))
    }
}

/// # Description:
/// Implementation of [`LweCiphertextVectorCreationEngine`] for [`DefaultEngine`] which returns a
/// mutable [`LweCiphertextVectorMutView32`] that does not own its memory.
impl<'data> LweCiphertextVectorCreationEngine<&'data mut [u32], LweCiphertextVectorMutView32<'data>>
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
    /// let lwe_size = LweSize(16);
    /// let lwe_count = LweCiphertextCount(3);
    /// let mut owned_container = vec![0_u32; lwe_size.0 * lwe_count.0];
    ///
    /// let slice = &mut owned_container[..];
    ///
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let ciphertext_vector_view: LweCiphertextVectorMutView32 =
    ///     engine.create_lwe_ciphertext_vector_from(slice, lwe_size)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn create_lwe_ciphertext_vector_from(
        &mut self,
        container: &'data mut [u32],
        lwe_size: LweSize,
    ) -> Result<
        LweCiphertextVectorMutView32<'data>,
        LweCiphertextVectorCreationError<Self::EngineError>,
    > {
        LweCiphertextVectorCreationError::<Self::EngineError>::perform_generic_checks(
            container.len(),
        )?;
        Ok(unsafe { self.create_lwe_ciphertext_vector_from_unchecked(container, lwe_size) })
    }

    unsafe fn create_lwe_ciphertext_vector_from_unchecked(
        &mut self,
        container: &'data mut [u32],
        lwe_size: LweSize,
    ) -> LweCiphertextVectorMutView32<'data> {
        LweCiphertextVectorMutView32(ImplLweList::from_container(container, lwe_size))
    }
}

/// # Description:
/// Implementation of [`LweCiphertextVectorCreationEngine`] for [`DefaultEngine`] which returns an
/// immutable [`LweCiphertextVectorView64`] that does not own its memory.
impl<'data> LweCiphertextVectorCreationEngine<&'data [u64], LweCiphertextVectorView64<'data>>
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
    /// let lwe_size = LweSize(16);
    /// let lwe_count = LweCiphertextCount(3);
    /// let mut owned_container = vec![0_u64; lwe_size.0 * lwe_count.0];
    ///
    /// let slice = &owned_container[..];
    ///
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let ciphertext_vector_view: LweCiphertextVectorView64 =
    ///     engine.create_lwe_ciphertext_vector_from(slice, lwe_size)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn create_lwe_ciphertext_vector_from(
        &mut self,
        container: &'data [u64],
        lwe_size: LweSize,
    ) -> Result<LweCiphertextVectorView64<'data>, LweCiphertextVectorCreationError<Self::EngineError>>
    {
        LweCiphertextVectorCreationError::<Self::EngineError>::perform_generic_checks(
            container.len(),
        )?;
        Ok(unsafe { self.create_lwe_ciphertext_vector_from_unchecked(container, lwe_size) })
    }

    unsafe fn create_lwe_ciphertext_vector_from_unchecked(
        &mut self,
        container: &'data [u64],
        lwe_size: LweSize,
    ) -> LweCiphertextVectorView64<'data> {
        LweCiphertextVectorView64(ImplLweList::from_container(container, lwe_size))
    }
}

/// # Description:
/// Implementation of [`LweCiphertextVectorCreationEngine`] for [`DefaultEngine`] which returns a
/// mutable [`LweCiphertextVectorMutView64`] that does not own its memory.
impl<'data> LweCiphertextVectorCreationEngine<&'data mut [u64], LweCiphertextVectorMutView64<'data>>
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
    /// let lwe_size = LweSize(16);
    /// let lwe_count = LweCiphertextCount(3);
    /// let mut owned_container = vec![0_u64; lwe_size.0 * lwe_count.0];
    ///
    /// let slice = &mut owned_container[..];
    ///
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let ciphertext_vector_view: LweCiphertextVectorMutView64 =
    ///     engine.create_lwe_ciphertext_vector_from(slice, lwe_size)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn create_lwe_ciphertext_vector_from(
        &mut self,
        container: &'data mut [u64],
        lwe_size: LweSize,
    ) -> Result<
        LweCiphertextVectorMutView64<'data>,
        LweCiphertextVectorCreationError<Self::EngineError>,
    > {
        LweCiphertextVectorCreationError::<Self::EngineError>::perform_generic_checks(
            container.len(),
        )?;
        Ok(unsafe { self.create_lwe_ciphertext_vector_from_unchecked(container, lwe_size) })
    }

    unsafe fn create_lwe_ciphertext_vector_from_unchecked(
        &mut self,
        container: &'data mut [u64],
        lwe_size: LweSize,
    ) -> LweCiphertextVectorMutView64<'data> {
        LweCiphertextVectorMutView64(ImplLweList::from_container(container, lwe_size))
    }
}
