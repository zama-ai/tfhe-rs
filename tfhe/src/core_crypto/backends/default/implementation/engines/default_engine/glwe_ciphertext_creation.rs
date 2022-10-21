use crate::core_crypto::backends::default::implementation::engines::DefaultEngine;
use crate::core_crypto::backends::default::implementation::entities::{
    GlweCiphertext32, GlweCiphertext64, GlweCiphertextMutView32, GlweCiphertextMutView64,
    GlweCiphertextView32, GlweCiphertextView64,
};
use crate::core_crypto::commons::crypto::glwe::GlweCiphertext as ImplGlweCiphertext;
use crate::core_crypto::prelude::PolynomialSize;
use crate::core_crypto::specification::engines::{
    GlweCiphertextCreationEngine, GlweCiphertextCreationError,
};

/// # Description:
/// Implementation of [`GlweCiphertextCreationEngine`] for [`DefaultEngine`] which returns a
/// [`GlweCiphertext32`].
impl GlweCiphertextCreationEngine<Vec<u32>, GlweCiphertext32> for DefaultEngine {
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{GlweSize, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // Here we create a container outside of the engine
    /// // Note that the size here is just for demonstration purposes and should not be chosen
    /// // without proper security analysis for production
    /// let glwe_size = GlweSize(600);
    /// let polynomial_size = PolynomialSize(1024);
    ///
    /// // You have to make sure you size the container properly
    /// let owned_container = vec![0_u32; glwe_size.0 * polynomial_size.0];
    ///
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let ciphertext: GlweCiphertext32 =
    ///     engine.create_glwe_ciphertext_from(owned_container, polynomial_size)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn create_glwe_ciphertext_from(
        &mut self,
        container: Vec<u32>,
        polynomial_size: PolynomialSize,
    ) -> Result<GlweCiphertext32, GlweCiphertextCreationError<Self::EngineError>> {
        GlweCiphertextCreationError::<Self::EngineError>::perform_generic_checks(
            container.len(),
            polynomial_size,
        )?;
        Ok(unsafe { self.create_glwe_ciphertext_from_unchecked(container, polynomial_size) })
    }

    unsafe fn create_glwe_ciphertext_from_unchecked(
        &mut self,
        container: Vec<u32>,
        polynomial_size: PolynomialSize,
    ) -> GlweCiphertext32 {
        GlweCiphertext32(ImplGlweCiphertext::from_container(
            container,
            polynomial_size,
        ))
    }
}

/// # Description:
/// Implementation of [`GlweCiphertextCreationEngine`] for [`DefaultEngine`] which returns a
/// [`GlweCiphertext64`].
impl GlweCiphertextCreationEngine<Vec<u64>, GlweCiphertext64> for DefaultEngine {
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{GlweSize, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // Here we create a container outside of the engine
    /// // Note that the size here is just for demonstration purposes and should not be chosen
    /// // without proper security analysis for production
    /// let glwe_size = GlweSize(600);
    /// let polynomial_size = PolynomialSize(1024);
    ///
    /// // You have to make sure you size the container properly
    /// let owned_container = vec![0_u64; glwe_size.0 * polynomial_size.0];
    ///
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let ciphertext: GlweCiphertext64 =
    ///     engine.create_glwe_ciphertext_from(owned_container, polynomial_size)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn create_glwe_ciphertext_from(
        &mut self,
        container: Vec<u64>,
        polynomial_size: PolynomialSize,
    ) -> Result<GlweCiphertext64, GlweCiphertextCreationError<Self::EngineError>> {
        GlweCiphertextCreationError::<Self::EngineError>::perform_generic_checks(
            container.len(),
            polynomial_size,
        )?;
        Ok(unsafe { self.create_glwe_ciphertext_from_unchecked(container, polynomial_size) })
    }

    unsafe fn create_glwe_ciphertext_from_unchecked(
        &mut self,
        container: Vec<u64>,
        polynomial_size: PolynomialSize,
    ) -> GlweCiphertext64 {
        GlweCiphertext64(ImplGlweCiphertext::from_container(
            container,
            polynomial_size,
        ))
    }
}

/// # Description:
/// Implementation of [`GlweCiphertextCreationEngine`] for [`DefaultEngine`] which returns an
/// immutable [`GlweCiphertextView32`] that does not own its memory.
impl<'data> GlweCiphertextCreationEngine<&'data [u32], GlweCiphertextView32<'data>>
    for DefaultEngine
{
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{GlweSize, PolynomialSize, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // Here we create a container outside of the engine
    /// // Note that the size here is just for demonstration purposes and should not be chosen
    /// // without proper security analysis for production
    /// let glwe_size = GlweSize(600);
    /// let polynomial_size = PolynomialSize(1024);
    ///
    /// // You have to make sure you size the container properly
    /// let mut owned_container = vec![0_u32; glwe_size.0 * polynomial_size.0];
    ///
    /// let slice = &owned_container[..];
    ///
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let ciphertext_view: GlweCiphertextView32 =
    ///     engine.create_glwe_ciphertext_from(slice, polynomial_size)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn create_glwe_ciphertext_from(
        &mut self,
        container: &'data [u32],
        polynomial_size: PolynomialSize,
    ) -> Result<GlweCiphertextView32<'data>, GlweCiphertextCreationError<Self::EngineError>> {
        GlweCiphertextCreationError::<Self::EngineError>::perform_generic_checks(
            container.len(),
            polynomial_size,
        )?;
        Ok(unsafe { self.create_glwe_ciphertext_from_unchecked(container, polynomial_size) })
    }

    unsafe fn create_glwe_ciphertext_from_unchecked(
        &mut self,
        container: &'data [u32],
        polynomial_size: PolynomialSize,
    ) -> GlweCiphertextView32<'data> {
        GlweCiphertextView32(ImplGlweCiphertext::from_container(
            container,
            polynomial_size,
        ))
    }
}

/// # Description:
/// Implementation of [`GlweCiphertextCreationEngine`] for [`DefaultEngine`] which returns a mutable
/// [`GlweCiphertextMutView32`] that does not own its memory.
impl<'data> GlweCiphertextCreationEngine<&'data mut [u32], GlweCiphertextMutView32<'data>>
    for DefaultEngine
{
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{GlweSize, PolynomialSize, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // Here we create a container outside of the engine
    /// // Note that the size here is just for demonstration purposes and should not be chosen
    /// // without proper security analysis for production
    /// let glwe_size = GlweSize(600);
    /// let polynomial_size = PolynomialSize(1024);
    ///
    /// // You have to make sure you size the container properly
    /// let mut owned_container = vec![0_u32; glwe_size.0 * polynomial_size.0];
    ///
    /// let slice = &mut owned_container[..];
    ///
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let ciphertext_view: GlweCiphertextMutView32 =
    ///     engine.create_glwe_ciphertext_from(slice, polynomial_size)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn create_glwe_ciphertext_from(
        &mut self,
        container: &'data mut [u32],
        polynomial_size: PolynomialSize,
    ) -> Result<GlweCiphertextMutView32<'data>, GlweCiphertextCreationError<Self::EngineError>>
    {
        GlweCiphertextCreationError::<Self::EngineError>::perform_generic_checks(
            container.len(),
            polynomial_size,
        )?;
        Ok(unsafe { self.create_glwe_ciphertext_from_unchecked(container, polynomial_size) })
    }

    unsafe fn create_glwe_ciphertext_from_unchecked(
        &mut self,
        container: &'data mut [u32],
        polynomial_size: PolynomialSize,
    ) -> GlweCiphertextMutView32<'data> {
        GlweCiphertextMutView32(ImplGlweCiphertext::from_container(
            container,
            polynomial_size,
        ))
    }
}

/// # Description:
/// Implementation of [`GlweCiphertextCreationEngine`] for [`DefaultEngine`] which returns an
/// immutable [`GlweCiphertextView64`] that does not own its memory.
impl<'data> GlweCiphertextCreationEngine<&'data [u64], GlweCiphertextView64<'data>>
    for DefaultEngine
{
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{PolynomialSize, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // Here we create a container outside of the engine
    /// // Note that the size here is just for demonstration purposes and should not be chosen
    /// // without proper security analysis for production
    /// let glwe_size = 600_usize;
    /// let polynomial_size = PolynomialSize(1024);
    ///
    /// // You have to make sure you size the container properly
    /// let mut owned_container = vec![0_u64; (glwe_size + 1) * polynomial_size.0];
    ///
    /// let slice = &owned_container[..];
    ///
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let ciphertext_view: GlweCiphertextView64 =
    ///     engine.create_glwe_ciphertext_from(slice, polynomial_size)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn create_glwe_ciphertext_from(
        &mut self,
        container: &'data [u64],
        polynomial_size: PolynomialSize,
    ) -> Result<GlweCiphertextView64<'data>, GlweCiphertextCreationError<Self::EngineError>> {
        GlweCiphertextCreationError::<Self::EngineError>::perform_generic_checks(
            container.len(),
            polynomial_size,
        )?;
        Ok(unsafe { self.create_glwe_ciphertext_from_unchecked(container, polynomial_size) })
    }

    unsafe fn create_glwe_ciphertext_from_unchecked(
        &mut self,
        container: &'data [u64],
        polynomial_size: PolynomialSize,
    ) -> GlweCiphertextView64<'data> {
        GlweCiphertextView64(ImplGlweCiphertext::from_container(
            container,
            polynomial_size,
        ))
    }
}

/// # Description:
/// Implementation of [`GlweCiphertextCreationEngine`] for [`DefaultEngine`] which returns a mutable
/// [`GlweCiphertextMutView64`] that does not own its memory.
impl<'data> GlweCiphertextCreationEngine<&'data mut [u64], GlweCiphertextMutView64<'data>>
    for DefaultEngine
{
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{GlweSize, PolynomialSize, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // Here we create a container outside of the engine
    /// // Note that the size here is just for demonstration purposes and should not be chosen
    /// // without proper security analysis for production
    /// let glwe_size = GlweSize(600);
    /// let polynomial_size = PolynomialSize(1024);
    ///
    /// // You have to make sure you size the container properly
    /// let mut owned_container = vec![0_u64; glwe_size.0 * polynomial_size.0];
    ///
    /// let slice = &mut owned_container[..];
    ///
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let ciphertext_view: GlweCiphertextMutView64 =
    ///     engine.create_glwe_ciphertext_from(slice, polynomial_size)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn create_glwe_ciphertext_from(
        &mut self,
        container: &'data mut [u64],
        polynomial_size: PolynomialSize,
    ) -> Result<GlweCiphertextMutView64<'data>, GlweCiphertextCreationError<Self::EngineError>>
    {
        GlweCiphertextCreationError::<Self::EngineError>::perform_generic_checks(
            container.len(),
            polynomial_size,
        )?;
        Ok(unsafe { self.create_glwe_ciphertext_from_unchecked(container, polynomial_size) })
    }

    unsafe fn create_glwe_ciphertext_from_unchecked(
        &mut self,
        container: &'data mut [u64],
        polynomial_size: PolynomialSize,
    ) -> GlweCiphertextMutView64<'data> {
        GlweCiphertextMutView64(ImplGlweCiphertext::from_container(
            container,
            polynomial_size,
        ))
    }
}
