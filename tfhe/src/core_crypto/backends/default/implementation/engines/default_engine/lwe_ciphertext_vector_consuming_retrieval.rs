use crate::core_crypto::backends::default::implementation::engines::DefaultEngine;
use crate::core_crypto::backends::default::implementation::entities::{
    LweCiphertextVector64, LweCiphertextVectorMutView64, LweCiphertextVectorView64,
};
use crate::core_crypto::commons::math::tensor::IntoTensor;
use crate::core_crypto::prelude::{
    LweCiphertextVector32, LweCiphertextVectorMutView32, LweCiphertextVectorView32,
};
use crate::core_crypto::specification::engines::{
    LweCiphertextVectorConsumingRetrievalEngine, LweCiphertextVectorConsumingRetrievalError,
};

/// # Description:
/// Implementation of [`LweCiphertextVectorConsumingRetrievalEngine`] for [`DefaultEngine`] that
/// returns the underlying slice of a [`LweCiphertextVector32`] consuming it in the process
impl LweCiphertextVectorConsumingRetrievalEngine<LweCiphertextVector32, Vec<u32>>
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
    /// use tfhe::core_crypto::commons::crypto::lwe::LweCiphertext;
    /// let lwe_size = LweSize(128);
    /// let lwe_count = LweCiphertextCount(8);
    /// let mut owned_container = vec![0_u32; lwe_size.0 * lwe_count.0];
    /// let original_vec_ptr = owned_container.as_ptr();
    ///
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let ciphertext_vector: LweCiphertextVector32 =
    ///     engine.create_lwe_ciphertext_vector_from(owned_container, lwe_size)?;
    /// let retrieved_container = engine.consume_retrieve_lwe_ciphertext_vector(ciphertext_vector)?;
    /// assert_eq!(original_vec_ptr, retrieved_container.as_ptr());
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn consume_retrieve_lwe_ciphertext_vector(
        &mut self,
        ciphertext: LweCiphertextVector32,
    ) -> Result<Vec<u32>, LweCiphertextVectorConsumingRetrievalError<Self::EngineError>> {
        Ok(unsafe { self.consume_retrieve_lwe_ciphertext_vector_unchecked(ciphertext) })
    }

    unsafe fn consume_retrieve_lwe_ciphertext_vector_unchecked(
        &mut self,
        ciphertext: LweCiphertextVector32,
    ) -> Vec<u32> {
        ciphertext.0.into_tensor().into_container()
    }
}

/// # Description:
/// Implementation of [`LweCiphertextVectorConsumingRetrievalEngine`] for [`DefaultEngine`] that
/// returns the underlying slice of a [`LweCiphertextVector64`] consuming it in the process
impl LweCiphertextVectorConsumingRetrievalEngine<LweCiphertextVector64, Vec<u64>>
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
    /// use tfhe::core_crypto::commons::crypto::lwe::LweCiphertext;
    /// let lwe_size = LweSize(128);
    /// let lwe_count = LweCiphertextCount(8);
    /// let mut owned_container = vec![0_u64; lwe_size.0 * lwe_count.0];
    /// let original_vec_ptr = owned_container.as_ptr();
    ///
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let ciphertext_vector: LweCiphertextVector64 =
    ///     engine.create_lwe_ciphertext_vector_from(owned_container, lwe_size)?;
    /// let retrieved_container = engine.consume_retrieve_lwe_ciphertext_vector(ciphertext_vector)?;
    /// assert_eq!(original_vec_ptr, retrieved_container.as_ptr());
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn consume_retrieve_lwe_ciphertext_vector(
        &mut self,
        ciphertext: LweCiphertextVector64,
    ) -> Result<Vec<u64>, LweCiphertextVectorConsumingRetrievalError<Self::EngineError>> {
        Ok(unsafe { self.consume_retrieve_lwe_ciphertext_vector_unchecked(ciphertext) })
    }

    unsafe fn consume_retrieve_lwe_ciphertext_vector_unchecked(
        &mut self,
        ciphertext: LweCiphertextVector64,
    ) -> Vec<u64> {
        ciphertext.0.into_tensor().into_container()
    }
}

/// # Description:
/// Implementation of [`LweCiphertextVectorConsumingRetrievalEngine`] for [`DefaultEngine`] that
/// returns the underlying slice of a [`LweCiphertextVectorView32`] consuming it in the process
impl<'data>
    LweCiphertextVectorConsumingRetrievalEngine<LweCiphertextVectorView32<'data>, &'data [u32]>
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
    /// let lwe_ciphertext_count = LweCiphertextCount(8);
    /// let mut owned_container = vec![0_u32; lwe_size.0 * lwe_ciphertext_count.0];
    ///
    /// let slice = &owned_container[..];
    ///
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let ciphertext_vector_view: LweCiphertextVectorView32 =
    ///     engine.create_lwe_ciphertext_vector_from(slice, lwe_size)?;
    /// let retrieved_slice = engine.consume_retrieve_lwe_ciphertext_vector(ciphertext_vector_view)?;
    /// assert_eq!(slice, retrieved_slice);
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn consume_retrieve_lwe_ciphertext_vector(
        &mut self,
        ciphertext: LweCiphertextVectorView32<'data>,
    ) -> Result<&'data [u32], LweCiphertextVectorConsumingRetrievalError<Self::EngineError>> {
        Ok(unsafe { self.consume_retrieve_lwe_ciphertext_vector_unchecked(ciphertext) })
    }

    unsafe fn consume_retrieve_lwe_ciphertext_vector_unchecked(
        &mut self,
        ciphertext: LweCiphertextVectorView32<'data>,
    ) -> &'data [u32] {
        ciphertext.0.into_tensor().into_container()
    }
}

/// # Description:
/// Implementation of [`LweCiphertextVectorConsumingRetrievalEngine`] for [`DefaultEngine`] that
/// returns the underlying slice of a [`LweCiphertextVectorView64`] consuming it in the process
impl<'data>
    LweCiphertextVectorConsumingRetrievalEngine<LweCiphertextVectorView64<'data>, &'data [u64]>
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
    /// let lwe_ciphertext_count = LweCiphertextCount(8);
    /// let mut owned_container = vec![0_u64; lwe_size.0 * lwe_ciphertext_count.0];
    ///
    /// let slice = &owned_container[..];
    ///
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let ciphertext_vector_view: LweCiphertextVectorView64 =
    ///     engine.create_lwe_ciphertext_vector_from(slice, lwe_size)?;
    /// let retrieved_slice = engine.consume_retrieve_lwe_ciphertext_vector(ciphertext_vector_view)?;
    /// assert_eq!(slice, retrieved_slice);
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn consume_retrieve_lwe_ciphertext_vector(
        &mut self,
        ciphertext: LweCiphertextVectorView64<'data>,
    ) -> Result<&'data [u64], LweCiphertextVectorConsumingRetrievalError<Self::EngineError>> {
        Ok(unsafe { self.consume_retrieve_lwe_ciphertext_vector_unchecked(ciphertext) })
    }

    unsafe fn consume_retrieve_lwe_ciphertext_vector_unchecked(
        &mut self,
        ciphertext: LweCiphertextVectorView64<'data>,
    ) -> &'data [u64] {
        ciphertext.0.into_tensor().into_container()
    }
}

/// # Description:
/// Implementation of [`LweCiphertextVectorConsumingRetrievalEngine`] for [`DefaultEngine`] that
/// returns the underlying slice of a [`LweCiphertextVectorMutView32`] consuming it in the process
impl<'data>
    LweCiphertextVectorConsumingRetrievalEngine<
        LweCiphertextVectorMutView32<'data>,
        &'data mut [u32],
    > for DefaultEngine
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
    /// let lwe_ciphertext_count = LweCiphertextCount(8);
    /// let mut owned_container = vec![0_u32; lwe_size.0 * lwe_ciphertext_count.0];
    ///
    /// let slice = &mut owned_container[..];
    /// // Required as we can't borrow a mut slice more than once
    /// let underlying_ptr = slice.as_ptr();
    ///
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let ciphertext_vector_view: LweCiphertextVectorMutView32 =
    ///     engine.create_lwe_ciphertext_vector_from(slice, lwe_size)?;
    /// let retrieved_slice = engine.consume_retrieve_lwe_ciphertext_vector(ciphertext_vector_view)?;
    /// assert_eq!(underlying_ptr, retrieved_slice.as_ptr());
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn consume_retrieve_lwe_ciphertext_vector(
        &mut self,
        ciphertext: LweCiphertextVectorMutView32<'data>,
    ) -> Result<&'data mut [u32], LweCiphertextVectorConsumingRetrievalError<Self::EngineError>>
    {
        Ok(unsafe { self.consume_retrieve_lwe_ciphertext_vector_unchecked(ciphertext) })
    }

    unsafe fn consume_retrieve_lwe_ciphertext_vector_unchecked(
        &mut self,
        ciphertext: LweCiphertextVectorMutView32<'data>,
    ) -> &'data mut [u32] {
        ciphertext.0.into_tensor().into_container()
    }
}

/// # Description:
/// Implementation of [`LweCiphertextVectorConsumingRetrievalEngine`] for [`DefaultEngine`] that
/// returns the underlying slice of a [`LweCiphertextVectorMutView64`] consuming it in the process
impl<'data>
    LweCiphertextVectorConsumingRetrievalEngine<
        LweCiphertextVectorMutView64<'data>,
        &'data mut [u64],
    > for DefaultEngine
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
    /// let lwe_ciphertext_count = LweCiphertextCount(8);
    /// let mut owned_container = vec![0_u64; lwe_size.0 * lwe_ciphertext_count.0];
    ///
    /// let slice = &mut owned_container[..];
    /// // Required as we can't borrow a mut slice more than once
    /// let underlying_ptr = slice.as_ptr();
    ///
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let ciphertext_vector_view: LweCiphertextVectorMutView64 =
    ///     engine.create_lwe_ciphertext_vector_from(slice, lwe_size)?;
    /// let retrieved_slice = engine.consume_retrieve_lwe_ciphertext_vector(ciphertext_vector_view)?;
    /// assert_eq!(underlying_ptr, retrieved_slice.as_ptr());
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn consume_retrieve_lwe_ciphertext_vector(
        &mut self,
        ciphertext: LweCiphertextVectorMutView64<'data>,
    ) -> Result<&'data mut [u64], LweCiphertextVectorConsumingRetrievalError<Self::EngineError>>
    {
        Ok(unsafe { self.consume_retrieve_lwe_ciphertext_vector_unchecked(ciphertext) })
    }

    unsafe fn consume_retrieve_lwe_ciphertext_vector_unchecked(
        &mut self,
        ciphertext: LweCiphertextVectorMutView64<'data>,
    ) -> &'data mut [u64] {
        ciphertext.0.into_tensor().into_container()
    }
}
