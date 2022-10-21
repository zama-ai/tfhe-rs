use crate::core_crypto::backends::default::implementation::engines::DefaultEngine;
use crate::core_crypto::backends::default::implementation::entities::{
    GlweCiphertextVectorMutView64, GlweCiphertextVectorView64,
};
use crate::core_crypto::commons::math::tensor::IntoTensor;
use crate::core_crypto::prelude::{
    GlweCiphertextVector32, GlweCiphertextVector64, GlweCiphertextVectorMutView32,
    GlweCiphertextVectorView32,
};
use crate::core_crypto::specification::engines::{
    GlweCiphertextVectorConsumingRetrievalEngine, GlweCiphertextVectorConsumingRetrievalError,
};

/// # Description:
/// Implementation of [`GlweCiphertextVectorConsumingRetrievalEngine`] for [`DefaultEngine`] that
/// returns the underlying slice of a [`GlweCiphertextVector32`] consuming it in the process
impl GlweCiphertextVectorConsumingRetrievalEngine<GlweCiphertextVector32, Vec<u32>>
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
    /// let original_vec_ptr = owned_container.as_ptr();
    ///
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let ciphertext_vector: GlweCiphertextVector32 = engine.create_glwe_ciphertext_vector_from(
    ///     owned_container,
    ///     glwe_size.to_glwe_dimension(),
    ///     polynomial_size,
    /// )?;
    /// let retrieved_container = engine.consume_retrieve_glwe_ciphertext_vector(ciphertext_vector)?;
    /// assert_eq!(original_vec_ptr, retrieved_container.as_ptr());
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn consume_retrieve_glwe_ciphertext_vector(
        &mut self,
        ciphertext_vector: GlweCiphertextVector32,
    ) -> Result<Vec<u32>, GlweCiphertextVectorConsumingRetrievalError<Self::EngineError>> {
        Ok(unsafe { self.consume_retrieve_glwe_ciphertext_vector_unchecked(ciphertext_vector) })
    }

    unsafe fn consume_retrieve_glwe_ciphertext_vector_unchecked(
        &mut self,
        ciphertext_vector: GlweCiphertextVector32,
    ) -> Vec<u32> {
        ciphertext_vector.0.into_tensor().into_container()
    }
}

/// # Description:
/// Implementation of [`GlweCiphertextVectorConsumingRetrievalEngine`] for [`DefaultEngine`] that
/// returns the underlying slice of a [`GlweCiphertextVector64`] consuming it in the process
impl GlweCiphertextVectorConsumingRetrievalEngine<GlweCiphertextVector64, Vec<u64>>
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
    /// let original_vec_ptr = owned_container.as_ptr();
    ///
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let ciphertext_vector: GlweCiphertextVector64 = engine.create_glwe_ciphertext_vector_from(
    ///     owned_container,
    ///     glwe_size.to_glwe_dimension(),
    ///     polynomial_size,
    /// )?;
    /// let retrieved_container = engine.consume_retrieve_glwe_ciphertext_vector(ciphertext_vector)?;
    /// assert_eq!(original_vec_ptr, retrieved_container.as_ptr());
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn consume_retrieve_glwe_ciphertext_vector(
        &mut self,
        ciphertext_vector: GlweCiphertextVector64,
    ) -> Result<Vec<u64>, GlweCiphertextVectorConsumingRetrievalError<Self::EngineError>> {
        Ok(unsafe { self.consume_retrieve_glwe_ciphertext_vector_unchecked(ciphertext_vector) })
    }

    unsafe fn consume_retrieve_glwe_ciphertext_vector_unchecked(
        &mut self,
        ciphertext_vector: GlweCiphertextVector64,
    ) -> Vec<u64> {
        ciphertext_vector.0.into_tensor().into_container()
    }
}

/// # Description:
/// Implementation of [`GlweCiphertextVectorConsumingRetrievalEngine`] for [`DefaultEngine`] that
/// returns the underlying slice of a [`GlweCiphertextVectorView32`] consuming it in the process
impl<'data>
    GlweCiphertextVectorConsumingRetrievalEngine<GlweCiphertextVectorView32<'data>, &'data [u32]>
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
    /// let original_vec_ptr = owned_container.as_ptr();
    ///
    /// let slice = &owned_container[..];
    ///
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let ciphertext_vector: GlweCiphertextVector32 = engine.create_glwe_ciphertext_vector_from(
    ///     slice.to_vec(),
    ///     glwe_size.to_glwe_dimension(),
    ///     polynomial_size,
    /// )?;
    /// let retrieved_slice = engine.consume_retrieve_glwe_ciphertext_vector(ciphertext_vector)?;
    /// assert_eq!(slice, retrieved_slice);
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn consume_retrieve_glwe_ciphertext_vector(
        &mut self,
        ciphertext_vector: GlweCiphertextVectorView32<'data>,
    ) -> Result<&'data [u32], GlweCiphertextVectorConsumingRetrievalError<Self::EngineError>> {
        Ok(unsafe { self.consume_retrieve_glwe_ciphertext_vector_unchecked(ciphertext_vector) })
    }

    unsafe fn consume_retrieve_glwe_ciphertext_vector_unchecked(
        &mut self,
        ciphertext_vector: GlweCiphertextVectorView32<'data>,
    ) -> &'data [u32] {
        ciphertext_vector.0.into_tensor().into_container()
    }
}

/// # Description:
/// Implementation of [`GlweCiphertextVectorConsumingRetrievalEngine`] for [`DefaultEngine`] that
/// returns the underlying slice of a [`GlweCiphertextVectorView64`] consuming it in the process
impl<'data>
    GlweCiphertextVectorConsumingRetrievalEngine<GlweCiphertextVectorView64<'data>, &'data [u64]>
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
    /// let original_vec_ptr = owned_container.as_ptr();
    ///
    /// let slice = &owned_container[..];
    ///
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let ciphertext_vector: GlweCiphertextVector64 = engine.create_glwe_ciphertext_vector_from(
    ///     slice.to_vec(),
    ///     glwe_size.to_glwe_dimension(),
    ///     polynomial_size,
    /// )?;
    /// let retrieved_slice = engine.consume_retrieve_glwe_ciphertext_vector(ciphertext_vector)?;
    /// assert_eq!(slice, retrieved_slice);
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn consume_retrieve_glwe_ciphertext_vector(
        &mut self,
        ciphertext_vector: GlweCiphertextVectorView64<'data>,
    ) -> Result<&'data [u64], GlweCiphertextVectorConsumingRetrievalError<Self::EngineError>> {
        Ok(unsafe { self.consume_retrieve_glwe_ciphertext_vector_unchecked(ciphertext_vector) })
    }

    unsafe fn consume_retrieve_glwe_ciphertext_vector_unchecked(
        &mut self,
        ciphertext_vector: GlweCiphertextVectorView64<'data>,
    ) -> &'data [u64] {
        ciphertext_vector.0.into_tensor().into_container()
    }
}

/// # Description:
/// Implementation of [`GlweCiphertextVectorConsumingRetrievalEngine`] for [`DefaultEngine`] that
/// returns
/// the underlying slice of a [`GlweCiphertextVectorMutView32`] consuming it in the process
impl<'data>
    GlweCiphertextVectorConsumingRetrievalEngine<
        GlweCiphertextVectorMutView32<'data>,
        &'data mut [u32],
    > for DefaultEngine
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
    /// // Required as we can't borrow a mut slice more than once
    /// let underlying_ptr = slice.as_ptr();
    ///
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let ciphertext_vector_view: GlweCiphertextVectorMutView32 = engine
    ///     .create_glwe_ciphertext_vector_from(
    ///         slice,
    ///         glwe_size.to_glwe_dimension(),
    ///         polynomial_size,
    ///     )?;
    /// let retrieved_slice = engine.consume_retrieve_glwe_ciphertext_vector(ciphertext_vector_view)?;
    /// assert_eq!(underlying_ptr, retrieved_slice.as_ptr());
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn consume_retrieve_glwe_ciphertext_vector(
        &mut self,
        ciphertext_vector: GlweCiphertextVectorMutView32<'data>,
    ) -> Result<&'data mut [u32], GlweCiphertextVectorConsumingRetrievalError<Self::EngineError>>
    {
        Ok(unsafe { self.consume_retrieve_glwe_ciphertext_vector_unchecked(ciphertext_vector) })
    }

    unsafe fn consume_retrieve_glwe_ciphertext_vector_unchecked(
        &mut self,
        ciphertext_vector: GlweCiphertextVectorMutView32<'data>,
    ) -> &'data mut [u32] {
        ciphertext_vector.0.into_tensor().into_container()
    }
}

/// # Description:
/// Implementation of [`GlweCiphertextVectorConsumingRetrievalEngine`] for [`DefaultEngine`] that
/// returns
/// the underlying slice of a [`GlweCiphertextVectorMutView64`] consuming it in the process
impl<'data>
    GlweCiphertextVectorConsumingRetrievalEngine<
        GlweCiphertextVectorMutView64<'data>,
        &'data mut [u64],
    > for DefaultEngine
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
    /// // Required as we can't borrow a mut slice more than once
    /// let underlying_ptr = slice.as_ptr();
    ///
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let ciphertext_vector_view: GlweCiphertextVectorMutView64 = engine
    ///     .create_glwe_ciphertext_vector_from(
    ///         slice,
    ///         glwe_size.to_glwe_dimension(),
    ///         polynomial_size,
    ///     )?;
    /// let retrieved_slice = engine.consume_retrieve_glwe_ciphertext_vector(ciphertext_vector_view)?;
    /// assert_eq!(underlying_ptr, retrieved_slice.as_ptr());
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn consume_retrieve_glwe_ciphertext_vector(
        &mut self,
        ciphertext_vector: GlweCiphertextVectorMutView64<'data>,
    ) -> Result<&'data mut [u64], GlweCiphertextVectorConsumingRetrievalError<Self::EngineError>>
    {
        Ok(unsafe { self.consume_retrieve_glwe_ciphertext_vector_unchecked(ciphertext_vector) })
    }

    unsafe fn consume_retrieve_glwe_ciphertext_vector_unchecked(
        &mut self,
        ciphertext_vector: GlweCiphertextVectorMutView64<'data>,
    ) -> &'data mut [u64] {
        ciphertext_vector.0.into_tensor().into_container()
    }
}
