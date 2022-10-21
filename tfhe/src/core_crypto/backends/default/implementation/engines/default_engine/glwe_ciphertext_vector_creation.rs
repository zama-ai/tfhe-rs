use crate::core_crypto::backends::default::implementation::engines::DefaultEngine;
use crate::core_crypto::backends::default::implementation::entities::{
    GlweCiphertextVectorMutView64, GlweCiphertextVectorView64,
};
use crate::core_crypto::commons::crypto::glwe::GlweList as ImplGlweList;
use crate::core_crypto::prelude::{
    GlweCiphertextVector32, GlweCiphertextVector64, GlweCiphertextVectorMutView32,
    GlweCiphertextVectorView32, GlweDimension, PolynomialSize,
};
use crate::core_crypto::specification::engines::{
    GlweCiphertextVectorCreationEngine, GlweCiphertextVectorCreationError,
};

/// # Description:
/// Implementation of [`GlweCiphertextVectorCreationEngine`] for [`DefaultEngine`] which returns an
/// [`GlweCiphertextVector32`].
impl GlweCiphertextVectorCreationEngine<Vec<u32>, GlweCiphertextVector32> for DefaultEngine {
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // Here we create a container outside of the engine
    /// // Note that the size here is just for demonstration purposes and should not be chosen
    /// // without proper security analysis for production
    /// let glwe_size = GlweSize(6);
    /// let polynomial_size = PolynomialSize(512);
    /// let glwe_count = GlweCiphertextCount(2);
    ///
    /// // You have to make sure you size the container properly
    /// let mut owned_container = vec![0_u32; glwe_size.0 * polynomial_size.0 * glwe_count.0];
    ///
    /// let slice = &owned_container[..];
    ///
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let ciphertext_view: GlweCiphertextVector32 = engine.create_glwe_ciphertext_vector_from(
    ///     slice.to_vec(),
    ///     glwe_size.to_glwe_dimension(),
    ///     polynomial_size,
    /// )?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn create_glwe_ciphertext_vector_from(
        &mut self,
        container: Vec<u32>,
        glwe_dimension: GlweDimension,
        polynomial_size: PolynomialSize,
    ) -> Result<GlweCiphertextVector32, GlweCiphertextVectorCreationError<Self::EngineError>> {
        GlweCiphertextVectorCreationError::<Self::EngineError>::perform_generic_checks(
            container.len(),
            polynomial_size,
            glwe_dimension.to_glwe_size(),
        )?;
        Ok(unsafe {
            self.create_glwe_ciphertext_vector_from_unchecked(
                container,
                glwe_dimension,
                polynomial_size,
            )
        })
    }

    unsafe fn create_glwe_ciphertext_vector_from_unchecked(
        &mut self,
        container: Vec<u32>,
        glwe_dimension: GlweDimension,
        polynomial_size: PolynomialSize,
    ) -> GlweCiphertextVector32 {
        GlweCiphertextVector32(ImplGlweList::from_container(
            container,
            glwe_dimension,
            polynomial_size,
        ))
    }
}

/// # Description:
/// Implementation of [`GlweCiphertextVectorCreationEngine`] for [`DefaultEngine`] which returns an
/// [`GlweCiphertextVector64`].
impl GlweCiphertextVectorCreationEngine<Vec<u64>, GlweCiphertextVector64> for DefaultEngine {
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // Here we create a container outside of the engine
    /// // Note that the size here is just for demonstration purposes and should not be chosen
    /// // without proper security analysis for production
    /// let glwe_size = GlweSize(6);
    /// let polynomial_size = PolynomialSize(512);
    /// let glwe_count = GlweCiphertextCount(2);
    ///
    /// // You have to make sure you size the container properly
    /// let mut owned_container = vec![0_u64; glwe_size.0 * polynomial_size.0 * glwe_count.0];
    ///
    /// let slice = &owned_container[..];
    ///
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let ciphertext_view: GlweCiphertextVector64 = engine.create_glwe_ciphertext_vector_from(
    ///     slice.to_vec(),
    ///     glwe_size.to_glwe_dimension(),
    ///     polynomial_size,
    /// )?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn create_glwe_ciphertext_vector_from(
        &mut self,
        container: Vec<u64>,
        glwe_dimension: GlweDimension,
        polynomial_size: PolynomialSize,
    ) -> Result<GlweCiphertextVector64, GlweCiphertextVectorCreationError<Self::EngineError>> {
        GlweCiphertextVectorCreationError::<Self::EngineError>::perform_generic_checks(
            container.len(),
            polynomial_size,
            glwe_dimension.to_glwe_size(),
        )?;
        Ok(unsafe {
            self.create_glwe_ciphertext_vector_from_unchecked(
                container,
                glwe_dimension,
                polynomial_size,
            )
        })
    }

    unsafe fn create_glwe_ciphertext_vector_from_unchecked(
        &mut self,
        container: Vec<u64>,
        glwe_dimension: GlweDimension,
        polynomial_size: PolynomialSize,
    ) -> GlweCiphertextVector64 {
        GlweCiphertextVector64(ImplGlweList::from_container(
            container,
            glwe_dimension,
            polynomial_size,
        ))
    }
}

/// # Description:
/// Implementation of [`GlweCiphertextVectorCreationEngine`] for [`DefaultEngine`] which returns an
/// immutable [`GlweCiphertextVectorView32`] that does not own its memory.
impl<'data> GlweCiphertextVectorCreationEngine<&'data [u32], GlweCiphertextVectorView32<'data>>
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
    /// let glwe_size = GlweSize(6);
    /// let polynomial_size = PolynomialSize(512);
    /// let glwe_count = GlweCiphertextCount(2);
    ///
    /// // You have to make sure you size the container properly
    /// let mut owned_container = vec![0_u32; glwe_size.0 * polynomial_size.0 * glwe_count.0];
    ///
    /// let slice = &owned_container[..];
    ///
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let ciphertext_view: GlweCiphertextVectorView32 = engine.create_glwe_ciphertext_vector_from(
    ///     slice,
    ///     glwe_size.to_glwe_dimension(),
    ///     polynomial_size,
    /// )?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn create_glwe_ciphertext_vector_from(
        &mut self,
        container: &'data [u32],
        glwe_dimension: GlweDimension,
        polynomial_size: PolynomialSize,
    ) -> Result<
        GlweCiphertextVectorView32<'data>,
        GlweCiphertextVectorCreationError<Self::EngineError>,
    > {
        GlweCiphertextVectorCreationError::<Self::EngineError>::perform_generic_checks(
            container.len(),
            polynomial_size,
            glwe_dimension.to_glwe_size(),
        )?;
        Ok(unsafe {
            self.create_glwe_ciphertext_vector_from_unchecked(
                container,
                glwe_dimension,
                polynomial_size,
            )
        })
    }

    unsafe fn create_glwe_ciphertext_vector_from_unchecked(
        &mut self,
        container: &'data [u32],
        glwe_dimension: GlweDimension,
        polynomial_size: PolynomialSize,
    ) -> GlweCiphertextVectorView32<'data> {
        GlweCiphertextVectorView32(ImplGlweList::from_container(
            container,
            glwe_dimension,
            polynomial_size,
        ))
    }
}

/// # Description:
/// Implementation of [`GlweCiphertextVectorCreationEngine`] for [`DefaultEngine`] which returns an
/// immutable [`GlweCiphertextVectorView64`] that does not own its memory.
impl<'data> GlweCiphertextVectorCreationEngine<&'data [u64], GlweCiphertextVectorView64<'data>>
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
    /// let glwe_size = GlweSize(6);
    /// let polynomial_size = PolynomialSize(512);
    /// let glwe_count = GlweCiphertextCount(2);
    ///
    /// // You have to make sure you size the container properly
    /// let mut owned_container = vec![0_u64; glwe_size.0 * polynomial_size.0 * glwe_count.0];
    ///
    /// let slice = &owned_container[..];
    ///
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let ciphertext_view: GlweCiphertextVectorView64 = engine.create_glwe_ciphertext_vector_from(
    ///     slice,
    ///     glwe_size.to_glwe_dimension(),
    ///     polynomial_size,
    /// )?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn create_glwe_ciphertext_vector_from(
        &mut self,
        container: &'data [u64],
        glwe_dimension: GlweDimension,
        polynomial_size: PolynomialSize,
    ) -> Result<
        GlweCiphertextVectorView64<'data>,
        GlweCiphertextVectorCreationError<Self::EngineError>,
    > {
        GlweCiphertextVectorCreationError::<Self::EngineError>::perform_generic_checks(
            container.len(),
            polynomial_size,
            glwe_dimension.to_glwe_size(),
        )?;
        Ok(unsafe {
            self.create_glwe_ciphertext_vector_from_unchecked(
                container,
                glwe_dimension,
                polynomial_size,
            )
        })
    }

    unsafe fn create_glwe_ciphertext_vector_from_unchecked(
        &mut self,
        container: &'data [u64],
        glwe_dimension: GlweDimension,
        polynomial_size: PolynomialSize,
    ) -> GlweCiphertextVectorView64<'data> {
        GlweCiphertextVectorView64(ImplGlweList::from_container(
            container,
            glwe_dimension,
            polynomial_size,
        ))
    }
}

/// # Description:
/// Implementation of [`GlweCiphertextVectorCreationEngine`] for [`DefaultEngine`] which returns a
/// mutable
/// [`GlweCiphertextVectorMutView32`] that does not own its memory.
impl<'data>
    GlweCiphertextVectorCreationEngine<&'data mut [u32], GlweCiphertextVectorMutView32<'data>>
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
    /// let glwe_size = GlweSize(6);
    /// let polynomial_size = PolynomialSize(512);
    /// let glwe_count = GlweCiphertextCount(2);
    ///
    /// // You have to make sure you size the container properly
    /// let mut owned_container = vec![0_u32; glwe_size.0 * polynomial_size.0 * glwe_count.0];
    ///
    /// let slice = &mut owned_container[..];
    ///
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let ciphertext_view: GlweCiphertextVectorMutView32 = engine
    ///     .create_glwe_ciphertext_vector_from(
    ///         slice,
    ///         glwe_size.to_glwe_dimension(),
    ///         polynomial_size,
    ///     )?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn create_glwe_ciphertext_vector_from(
        &mut self,
        container: &'data mut [u32],
        glwe_dimension: GlweDimension,
        polynomial_size: PolynomialSize,
    ) -> Result<
        GlweCiphertextVectorMutView32<'data>,
        GlweCiphertextVectorCreationError<Self::EngineError>,
    > {
        GlweCiphertextVectorCreationError::<Self::EngineError>::perform_generic_checks(
            container.len(),
            polynomial_size,
            glwe_dimension.to_glwe_size(),
        )?;
        Ok(unsafe {
            self.create_glwe_ciphertext_vector_from_unchecked(
                container,
                glwe_dimension,
                polynomial_size,
            )
        })
    }

    unsafe fn create_glwe_ciphertext_vector_from_unchecked(
        &mut self,
        container: &'data mut [u32],
        glwe_dimension: GlweDimension,
        polynomial_size: PolynomialSize,
    ) -> GlweCiphertextVectorMutView32<'data> {
        GlweCiphertextVectorMutView32(ImplGlweList::from_container(
            container,
            glwe_dimension,
            polynomial_size,
        ))
    }
}

/// # Description:
/// Implementation of [`GlweCiphertextVectorCreationEngine`] for [`DefaultEngine`] which returns a
/// mutable
/// [`GlweCiphertextVectorMutView64`] that does not own its memory.
impl<'data>
    GlweCiphertextVectorCreationEngine<&'data mut [u64], GlweCiphertextVectorMutView64<'data>>
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
    /// let glwe_size = GlweSize(6);
    /// let polynomial_size = PolynomialSize(512);
    /// let glwe_count = GlweCiphertextCount(2);
    ///
    /// // You have to make sure you size the container properly
    /// let mut owned_container = vec![0_u64; glwe_size.0 * polynomial_size.0 * glwe_count.0];
    ///
    /// let slice = &mut owned_container[..];
    ///
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let ciphertext_view: GlweCiphertextVectorMutView64 = engine
    ///     .create_glwe_ciphertext_vector_from(
    ///         slice,
    ///         glwe_size.to_glwe_dimension(),
    ///         polynomial_size,
    ///     )?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn create_glwe_ciphertext_vector_from(
        &mut self,
        container: &'data mut [u64],
        glwe_dimension: GlweDimension,
        polynomial_size: PolynomialSize,
    ) -> Result<
        GlweCiphertextVectorMutView64<'data>,
        GlweCiphertextVectorCreationError<Self::EngineError>,
    > {
        GlweCiphertextVectorCreationError::<Self::EngineError>::perform_generic_checks(
            container.len(),
            polynomial_size,
            glwe_dimension.to_glwe_size(),
        )?;
        Ok(unsafe {
            self.create_glwe_ciphertext_vector_from_unchecked(
                container,
                glwe_dimension,
                polynomial_size,
            )
        })
    }

    unsafe fn create_glwe_ciphertext_vector_from_unchecked(
        &mut self,
        container: &'data mut [u64],
        glwe_dimension: GlweDimension,
        polynomial_size: PolynomialSize,
    ) -> GlweCiphertextVectorMutView64<'data> {
        GlweCiphertextVectorMutView64(ImplGlweList::from_container(
            container,
            glwe_dimension,
            polynomial_size,
        ))
    }
}
