use crate::core_crypto::backends::cuda::engines::{CudaEngine, CudaError};
use crate::core_crypto::backends::cuda::implementation::entities::{
    CudaGlweCiphertextVector32, CudaGlweCiphertextVector64,
};
use crate::core_crypto::backends::cuda::private::crypto::glwe::list::CudaGlweList;
use crate::core_crypto::commons::crypto::glwe::GlweList;
use crate::core_crypto::commons::math::tensor::{AsRefSlice, AsRefTensor};
use crate::core_crypto::prelude::{
    GlweCiphertextVector32, GlweCiphertextVector64, GlweCiphertextVectorMutView32,
    GlweCiphertextVectorMutView64, GlweCiphertextVectorView32, GlweCiphertextVectorView64,
};
use crate::core_crypto::specification::engines::{
    GlweCiphertextVectorConversionEngine, GlweCiphertextVectorConversionError,
};
use crate::core_crypto::specification::entities::GlweCiphertextVectorEntity;

impl From<CudaError> for GlweCiphertextVectorConversionError<CudaError> {
    fn from(err: CudaError) -> Self {
        Self::Engine(err)
    }
}

/// # Description
/// Convert a GLWE ciphertext vector with 32 bits of precision from CPU to GPU.
/// Only this conversion is necessary to run the bootstrap on the GPU.
/// The whole vector of GLWE ciphertexts is copied to all the GPUS: it corresponds
/// to the input vector of lookup tables for the bootstrap.
impl GlweCiphertextVectorConversionEngine<GlweCiphertextVector32, CudaGlweCiphertextVector32>
    for CudaEngine
{
    /// # Example
    /// ```
    /// use tfhe::core_crypto::prelude::{
    ///     GlweCiphertextCount, GlweDimension, PolynomialSize, Variance, *,
    /// };
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(3);
    /// let glwe_count = GlweCiphertextCount(2);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u32 << 20; polynomial_size.0 * glwe_count.0];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let h_key: GlweSecretKey32 =
    ///     default_engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let h_plaintext_vector: PlaintextVector32 =
    ///     default_engine.create_plaintext_vector_from(&input)?;
    /// let mut h_ciphertext_vector: GlweCiphertextVector32 =
    ///     default_engine.encrypt_glwe_ciphertext_vector(&h_key, &h_plaintext_vector, noise)?;
    ///
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_ciphertext_vector: CudaGlweCiphertextVector32 =
    ///     cuda_engine.convert_glwe_ciphertext_vector(&h_ciphertext_vector)?;
    ///
    /// assert_eq!(d_ciphertext_vector.glwe_dimension(), glwe_dimension);
    /// assert_eq!(d_ciphertext_vector.glwe_ciphertext_count(), glwe_count,);
    /// assert_eq!(d_ciphertext_vector.polynomial_size(), polynomial_size);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_glwe_ciphertext_vector(
        &mut self,
        input: &GlweCiphertextVector32,
    ) -> Result<CudaGlweCiphertextVector32, GlweCiphertextVectorConversionError<CudaError>> {
        for gpu_index in 0..self.get_number_of_gpus().0 {
            let stream = &self.streams[gpu_index];
            let data_per_gpu = input.glwe_dimension().to_glwe_size().0
                * input.glwe_ciphertext_count().0
                * input.polynomial_size().0;
            let size = data_per_gpu as u64 * std::mem::size_of::<u32>() as u64;
            stream.check_device_memory(size)?;
        }
        Ok(unsafe { self.convert_glwe_ciphertext_vector_unchecked(input) })
    }

    unsafe fn convert_glwe_ciphertext_vector_unchecked(
        &mut self,
        input: &GlweCiphertextVector32,
    ) -> CudaGlweCiphertextVector32 {
        // Copy the entire input vector over all GPUs
        let mut vecs = Vec::with_capacity(self.get_number_of_gpus().0);
        let data_per_gpu = input.glwe_ciphertext_count().0
            * input.glwe_dimension().to_glwe_size().0
            * input.polynomial_size().0;
        for gpu_index in 0..self.get_number_of_gpus().0 {
            let stream = &self.streams[gpu_index];
            let mut vec = stream.malloc::<u32>(data_per_gpu as u32);
            let input_slice = input.0.as_tensor().as_slice();
            stream.copy_to_gpu::<u32>(&mut vec, input_slice);
            vecs.push(vec);
        }
        CudaGlweCiphertextVector32(CudaGlweList::<u32> {
            d_vecs: vecs,
            glwe_ciphertext_count: input.glwe_ciphertext_count(),
            glwe_dimension: input.glwe_dimension(),
            polynomial_size: input.polynomial_size(),
        })
    }
}

/// # Description
/// Convert a GLWE ciphertext vector with 32 bits of precision from GPU to CPU.
/// This conversion is not necessary to run the bootstrap on the GPU.
/// It is implemented for testing purposes only.
impl GlweCiphertextVectorConversionEngine<CudaGlweCiphertextVector32, GlweCiphertextVector32>
    for CudaEngine
{
    /// # Example
    /// ```
    /// use tfhe::core_crypto::prelude::{
    ///     GlweCiphertextCount, GlweDimension, PolynomialSize, Variance, *,
    /// };
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(3);
    /// let glwe_count = GlweCiphertextCount(2);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u32 << 20; polynomial_size.0 * glwe_count.0];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let h_key: GlweSecretKey32 =
    ///     default_engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let h_plaintext_vector: PlaintextVector32 =
    ///     default_engine.create_plaintext_vector_from(&input)?;
    /// let mut h_ciphertext_vector: GlweCiphertextVector32 =
    ///     default_engine.encrypt_glwe_ciphertext_vector(&h_key, &h_plaintext_vector, noise)?;
    ///
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_ciphertext_vector: CudaGlweCiphertextVector32 =
    ///     cuda_engine.convert_glwe_ciphertext_vector(&h_ciphertext_vector)?;
    /// let h_output_ciphertext_vector: GlweCiphertextVector32 =
    ///     cuda_engine.convert_glwe_ciphertext_vector(&d_ciphertext_vector)?;
    ///
    /// assert_eq!(d_ciphertext_vector.glwe_dimension(), glwe_dimension);
    /// assert_eq!(d_ciphertext_vector.glwe_ciphertext_count(), glwe_count,);
    /// assert_eq!(d_ciphertext_vector.polynomial_size(), polynomial_size);
    /// assert_eq!(h_ciphertext_vector, h_output_ciphertext_vector);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_glwe_ciphertext_vector(
        &mut self,
        input: &CudaGlweCiphertextVector32,
    ) -> Result<GlweCiphertextVector32, GlweCiphertextVectorConversionError<CudaError>> {
        Ok(unsafe { self.convert_glwe_ciphertext_vector_unchecked(input) })
    }

    unsafe fn convert_glwe_ciphertext_vector_unchecked(
        &mut self,
        input: &CudaGlweCiphertextVector32,
    ) -> GlweCiphertextVector32 {
        // Copy the data from GPU 0 back to the CPU
        let mut output = vec![
            0u32;
            input.glwe_dimension().to_glwe_size().0
                * input.glwe_ciphertext_count().0
                * input.polynomial_size().0
        ];
        let stream = &self.streams[0];
        stream.copy_to_cpu::<u32>(&mut output, input.0.d_vecs.first().unwrap());
        GlweCiphertextVector32(GlweList::from_container(
            output,
            input.glwe_dimension(),
            input.polynomial_size(),
        ))
    }
}

/// # Description
/// Convert a GLWE ciphertext vector with 64 bits of precision from CPU to GPU.
/// Only this conversion is necessary to run the bootstrap on the GPU.
/// The whole vector of GLWE ciphertexts is copied to all the GPUS: it corresponds
/// to the input vector of lookup tables for the bootstrap.
impl GlweCiphertextVectorConversionEngine<GlweCiphertextVector64, CudaGlweCiphertextVector64>
    for CudaEngine
{
    /// # Example
    /// ```
    /// use tfhe::core_crypto::prelude::{
    ///     GlweCiphertextCount, GlweDimension, PolynomialSize, Variance, *,
    /// };
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(3);
    /// let glwe_count = GlweCiphertextCount(2);
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = vec![3_u64 << 50; polynomial_size.0 * glwe_count.0];
    /// let noise = Variance(2_f64.powf(-50.));
    ///
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let h_key: GlweSecretKey64 =
    ///     default_engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let h_plaintext_vector: PlaintextVector64 =
    ///     default_engine.create_plaintext_vector_from(&input)?;
    /// let mut h_ciphertext_vector: GlweCiphertextVector64 =
    ///     default_engine.encrypt_glwe_ciphertext_vector(&h_key, &h_plaintext_vector, noise)?;
    ///
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_ciphertext_vector: CudaGlweCiphertextVector64 =
    ///     cuda_engine.convert_glwe_ciphertext_vector(&h_ciphertext_vector)?;
    ///
    /// assert_eq!(d_ciphertext_vector.glwe_dimension(), glwe_dimension);
    /// assert_eq!(d_ciphertext_vector.glwe_ciphertext_count(), glwe_count);
    /// assert_eq!(d_ciphertext_vector.polynomial_size(), polynomial_size);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_glwe_ciphertext_vector(
        &mut self,
        input: &GlweCiphertextVector64,
    ) -> Result<CudaGlweCiphertextVector64, GlweCiphertextVectorConversionError<CudaError>> {
        for gpu_index in 0..self.get_number_of_gpus().0 {
            let stream = &self.streams[gpu_index];
            let data_per_gpu = input.glwe_dimension().to_glwe_size().0
                * input.glwe_ciphertext_count().0
                * input.polynomial_size().0;
            let size = data_per_gpu as u64 * std::mem::size_of::<u64>() as u64;
            stream.check_device_memory(size)?;
        }
        Ok(unsafe { self.convert_glwe_ciphertext_vector_unchecked(input) })
    }

    unsafe fn convert_glwe_ciphertext_vector_unchecked(
        &mut self,
        input: &GlweCiphertextVector64,
    ) -> CudaGlweCiphertextVector64 {
        // Copy the entire input vector over all GPUs
        let mut vecs = Vec::with_capacity(self.get_number_of_gpus().0);
        let data_per_gpu = input.glwe_ciphertext_count().0
            * input.glwe_dimension().to_glwe_size().0
            * input.polynomial_size().0;
        for gpu_index in 0..self.get_number_of_gpus().0 {
            let stream = &self.streams[gpu_index];
            let mut vec = stream.malloc::<u64>(data_per_gpu as u32);
            let input_slice = input.0.as_tensor().as_slice();
            stream.copy_to_gpu::<u64>(&mut vec, input_slice);
            vecs.push(vec);
        }
        CudaGlweCiphertextVector64(CudaGlweList::<u64> {
            d_vecs: vecs,
            glwe_ciphertext_count: input.glwe_ciphertext_count(),
            glwe_dimension: input.glwe_dimension(),
            polynomial_size: input.polynomial_size(),
        })
    }
}

/// # Description
/// Convert a GLWE ciphertext vector with 64 bits of precision from GPU to CPU.
/// This conversion is not necessary to run the bootstrap on the GPU.
/// It is implemented for testing purposes only.
impl GlweCiphertextVectorConversionEngine<CudaGlweCiphertextVector64, GlweCiphertextVector64>
    for CudaEngine
{
    /// # Example
    /// ```
    /// use tfhe::core_crypto::prelude::{
    ///     GlweCiphertextCount, GlweDimension, PolynomialSize, Variance, *,
    /// };
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(3);
    /// let glwe_count = GlweCiphertextCount(2);
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = vec![3_u64 << 50; polynomial_size.0 * glwe_count.0];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let h_key: GlweSecretKey64 =
    ///     default_engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let h_plaintext_vector: PlaintextVector64 =
    ///     default_engine.create_plaintext_vector_from(&input)?;
    /// let mut h_ciphertext_vector: GlweCiphertextVector64 =
    ///     default_engine.encrypt_glwe_ciphertext_vector(&h_key, &h_plaintext_vector, noise)?;
    ///
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_ciphertext_vector: CudaGlweCiphertextVector64 =
    ///     cuda_engine.convert_glwe_ciphertext_vector(&h_ciphertext_vector)?;
    /// let h_output_ciphertext_vector: GlweCiphertextVector64 =
    ///     cuda_engine.convert_glwe_ciphertext_vector(&d_ciphertext_vector)?;
    ///
    /// assert_eq!(d_ciphertext_vector.glwe_dimension(), glwe_dimension);
    /// assert_eq!(d_ciphertext_vector.glwe_ciphertext_count(), glwe_count);
    /// assert_eq!(d_ciphertext_vector.polynomial_size(), polynomial_size);
    /// assert_eq!(h_ciphertext_vector, h_output_ciphertext_vector);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_glwe_ciphertext_vector(
        &mut self,
        input: &CudaGlweCiphertextVector64,
    ) -> Result<GlweCiphertextVector64, GlweCiphertextVectorConversionError<CudaError>> {
        Ok(unsafe { self.convert_glwe_ciphertext_vector_unchecked(input) })
    }

    unsafe fn convert_glwe_ciphertext_vector_unchecked(
        &mut self,
        input: &CudaGlweCiphertextVector64,
    ) -> GlweCiphertextVector64 {
        // Copy the data from GPU 0 back to the CPU
        let mut output = vec![
            0u64;
            input.glwe_dimension().to_glwe_size().0
                * input.glwe_ciphertext_count().0
                * input.polynomial_size().0
        ];
        let stream = &self.streams[0];
        stream.copy_to_cpu::<u64>(&mut output, input.0.d_vecs.first().unwrap());
        GlweCiphertextVector64(GlweList::from_container(
            output,
            input.glwe_dimension(),
            input.polynomial_size(),
        ))
    }
}

/// # Description
/// Convert a GLWE ciphertext vector view with 32 bits of precision from CPU to GPU.
/// The whole vector of GLWE ciphertexts is copied to all the GPUS: it corresponds
/// to the input vector of lookup tables for the bootstrap.
impl
    GlweCiphertextVectorConversionEngine<GlweCiphertextVectorView32<'_>, CudaGlweCiphertextVector32>
    for CudaEngine
{
    /// # Example
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(3);
    /// let glwe_count = GlweCiphertextCount(2);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u32 << 20; polynomial_size.0 * glwe_count.0];
    /// let noise = Variance(2_f64.powf(-50.));
    ///
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let h_key: GlweSecretKey32 =
    ///     default_engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let h_plaintext_vector: PlaintextVector32 =
    ///     default_engine.create_plaintext_vector_from(&input)?;
    /// let mut h_ciphertext_vector: GlweCiphertextVector32 =
    ///     default_engine.encrypt_glwe_ciphertext_vector(&h_key, &h_plaintext_vector, noise)?;
    ///
    /// let h_raw_ciphertext_vector: Vec<u32> =
    ///     default_engine.consume_retrieve_glwe_ciphertext_vector(h_ciphertext_vector)?;
    /// let mut h_view_ciphertext_vector: GlweCiphertextVectorView32 = default_engine
    ///     .create_glwe_ciphertext_vector_from(
    ///         h_raw_ciphertext_vector.as_slice(),
    ///         glwe_dimension,
    ///         polynomial_size,
    ///     )?;
    ///
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_ciphertext_vector: CudaGlweCiphertextVector32 =
    ///     cuda_engine.convert_glwe_ciphertext_vector(&h_view_ciphertext_vector)?;
    ///
    /// assert_eq!(d_ciphertext_vector.glwe_dimension(), glwe_dimension);
    /// assert_eq!(d_ciphertext_vector.glwe_ciphertext_count(), glwe_count,);
    /// assert_eq!(d_ciphertext_vector.polynomial_size(), polynomial_size);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_glwe_ciphertext_vector(
        &mut self,
        input: &GlweCiphertextVectorView32,
    ) -> Result<CudaGlweCiphertextVector32, GlweCiphertextVectorConversionError<CudaError>> {
        for gpu_index in 0..self.get_number_of_gpus().0 {
            let stream = &self.streams[gpu_index];
            let data_per_gpu = input.glwe_dimension().to_glwe_size().0
                * input.glwe_ciphertext_count().0
                * input.polynomial_size().0;
            let size = data_per_gpu as u64 * std::mem::size_of::<u32>() as u64;
            stream.check_device_memory(size)?;
        }
        Ok(unsafe { self.convert_glwe_ciphertext_vector_unchecked(input) })
    }

    unsafe fn convert_glwe_ciphertext_vector_unchecked(
        &mut self,
        input: &GlweCiphertextVectorView32,
    ) -> CudaGlweCiphertextVector32 {
        // Copy the entire input vector over all GPUs
        let mut vecs = Vec::with_capacity(self.get_number_of_gpus().0);
        let data_per_gpu = input.glwe_ciphertext_count().0
            * input.glwe_dimension().to_glwe_size().0
            * input.polynomial_size().0;
        for gpu_index in 0..self.get_number_of_gpus().0 {
            let stream = &self.streams[gpu_index];
            let mut vec = stream.malloc::<u32>(data_per_gpu as u32);
            let input_slice = input.0.as_tensor().as_slice();
            stream.copy_to_gpu::<u32>(&mut vec, input_slice);
            vecs.push(vec);
        }
        CudaGlweCiphertextVector32(CudaGlweList::<u32> {
            d_vecs: vecs,
            glwe_ciphertext_count: input.glwe_ciphertext_count(),
            glwe_dimension: input.glwe_dimension(),
            polynomial_size: input.polynomial_size(),
        })
    }
}

/// # Description
/// Convert a GLWE ciphertext vector view with 64 bits of precision from CPU to GPU.
/// The whole vector of GLWE ciphertexts is copied to all the GPUS: it corresponds
/// to the input vector of lookup tables for the bootstrap.
impl
    GlweCiphertextVectorConversionEngine<GlweCiphertextVectorView64<'_>, CudaGlweCiphertextVector64>
    for CudaEngine
{
    /// # Example
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(3);
    /// let glwe_count = GlweCiphertextCount(2);
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = vec![3_u64 << 50; polynomial_size.0 * glwe_count.0];
    /// let noise = Variance(2_f64.powf(-50.));
    ///
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let h_key: GlweSecretKey64 =
    ///     default_engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let h_plaintext_vector: PlaintextVector64 =
    ///     default_engine.create_plaintext_vector_from(&input)?;
    /// let mut h_ciphertext_vector: GlweCiphertextVector64 =
    ///     default_engine.encrypt_glwe_ciphertext_vector(&h_key, &h_plaintext_vector, noise)?;
    ///
    /// let h_raw_ciphertext_vector: Vec<u64> =
    ///     default_engine.consume_retrieve_glwe_ciphertext_vector(h_ciphertext_vector)?;
    /// let mut h_view_ciphertext_vector: GlweCiphertextVectorView64 = default_engine
    ///     .create_glwe_ciphertext_vector_from(
    ///         h_raw_ciphertext_vector.as_slice(),
    ///         glwe_dimension,
    ///         polynomial_size,
    ///     )?;
    ///
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_ciphertext_vector: CudaGlweCiphertextVector64 =
    ///     cuda_engine.convert_glwe_ciphertext_vector(&h_view_ciphertext_vector)?;
    ///
    /// assert_eq!(d_ciphertext_vector.glwe_dimension(), glwe_dimension);
    /// assert_eq!(d_ciphertext_vector.glwe_ciphertext_count(), glwe_count,);
    /// assert_eq!(d_ciphertext_vector.polynomial_size(), polynomial_size);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_glwe_ciphertext_vector(
        &mut self,
        input: &GlweCiphertextVectorView64,
    ) -> Result<CudaGlweCiphertextVector64, GlweCiphertextVectorConversionError<CudaError>> {
        for gpu_index in 0..self.get_number_of_gpus().0 {
            let stream = &self.streams[gpu_index];
            let data_per_gpu = input.glwe_dimension().to_glwe_size().0
                * input.glwe_ciphertext_count().0
                * input.polynomial_size().0;
            let size = data_per_gpu as u64 * std::mem::size_of::<u64>() as u64;
            stream.check_device_memory(size)?;
        }
        Ok(unsafe { self.convert_glwe_ciphertext_vector_unchecked(input) })
    }

    unsafe fn convert_glwe_ciphertext_vector_unchecked(
        &mut self,
        input: &GlweCiphertextVectorView64,
    ) -> CudaGlweCiphertextVector64 {
        // Copy the entire input vector over all GPUs
        let mut vecs = Vec::with_capacity(self.get_number_of_gpus().0);
        let data_per_gpu = input.glwe_ciphertext_count().0
            * input.glwe_dimension().to_glwe_size().0
            * input.polynomial_size().0;
        for gpu_index in 0..self.get_number_of_gpus().0 {
            let stream = &self.streams[gpu_index];
            let mut vec = stream.malloc::<u64>(data_per_gpu as u32);
            let input_slice = input.0.as_tensor().as_slice();
            stream.copy_to_gpu::<u64>(&mut vec, input_slice);
            vecs.push(vec);
        }
        CudaGlweCiphertextVector64(CudaGlweList::<u64> {
            d_vecs: vecs,
            glwe_ciphertext_count: input.glwe_ciphertext_count(),
            glwe_dimension: input.glwe_dimension(),
            polynomial_size: input.polynomial_size(),
        })
    }
}

/// # Description
/// Convert a GLWE ciphertext vector view with 32 bits of precision from CPU to GPU.
/// The whole vector of GLWE ciphertexts is copied to all the GPUS: it corresponds
/// to the input vector of lookup tables for the bootstrap.
impl
    GlweCiphertextVectorConversionEngine<
        GlweCiphertextVectorMutView32<'_>,
        CudaGlweCiphertextVector32,
    > for CudaEngine
{
    /// # Example
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(3);
    /// let glwe_count = GlweCiphertextCount(2);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u32 << 20; polynomial_size.0 * glwe_count.0];
    /// let noise = Variance(2_f64.powf(-50.));
    ///
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let h_key: GlweSecretKey32 =
    ///     default_engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let h_plaintext_vector: PlaintextVector32 =
    ///     default_engine.create_plaintext_vector_from(&input)?;
    /// let mut h_ciphertext_vector: GlweCiphertextVector32 =
    ///     default_engine.encrypt_glwe_ciphertext_vector(&h_key, &h_plaintext_vector, noise)?;
    /// let glwe_ciphertext_count = h_ciphertext_vector.glwe_ciphertext_count();
    ///
    /// let mut h_raw_ciphertext_vector: Vec<u32> =
    ///     default_engine.consume_retrieve_glwe_ciphertext_vector(h_ciphertext_vector)?;
    /// let h_view_ciphertext_vector: GlweCiphertextVectorMutView32 = default_engine
    ///     .create_glwe_ciphertext_vector_from(
    ///         h_raw_ciphertext_vector.as_mut_slice(),
    ///         glwe_dimension,
    ///         polynomial_size,
    ///     )?;
    ///
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_ciphertext_vector: CudaGlweCiphertextVector32 =
    ///     cuda_engine.convert_glwe_ciphertext_vector(&h_view_ciphertext_vector)?;
    /// let h_output_ciphertext_vector: GlweCiphertextVector32 =
    ///     cuda_engine.convert_glwe_ciphertext_vector(&d_ciphertext_vector)?;
    ///
    /// assert_eq!(d_ciphertext_vector.glwe_dimension(), glwe_dimension);
    /// assert_eq!(
    ///     d_ciphertext_vector.glwe_ciphertext_count(),
    ///     glwe_ciphertext_count
    /// );
    /// assert_eq!(d_ciphertext_vector.polynomial_size(), polynomial_size);
    ///
    /// // Extracts the internal container
    /// let h_raw_output_ciphertext_vector: Vec<u32> =
    ///     default_engine.consume_retrieve_glwe_ciphertext_vector(h_output_ciphertext_vector)?;
    /// assert_eq!(
    ///     h_raw_ciphertext_vector,
    ///     h_raw_output_ciphertext_vector.to_vec()
    /// );
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_glwe_ciphertext_vector(
        &mut self,
        input: &GlweCiphertextVectorMutView32,
    ) -> Result<CudaGlweCiphertextVector32, GlweCiphertextVectorConversionError<CudaError>> {
        for gpu_index in 0..self.get_number_of_gpus().0 {
            let stream = &self.streams[gpu_index];
            let data_per_gpu = input.glwe_dimension().to_glwe_size().0
                * input.glwe_ciphertext_count().0
                * input.polynomial_size().0;
            let size = data_per_gpu as u64 * std::mem::size_of::<u32>() as u64;
            stream.check_device_memory(size)?;
        }
        Ok(unsafe { self.convert_glwe_ciphertext_vector_unchecked(input) })
    }

    unsafe fn convert_glwe_ciphertext_vector_unchecked(
        &mut self,
        input: &GlweCiphertextVectorMutView32,
    ) -> CudaGlweCiphertextVector32 {
        // Copy the entire input vector over all GPUs
        let mut vecs = Vec::with_capacity(self.get_number_of_gpus().0 as usize);
        let data_per_gpu = input.glwe_ciphertext_count().0
            * input.glwe_dimension().to_glwe_size().0
            * input.polynomial_size().0;
        for gpu_index in 0..self.get_number_of_gpus().0 {
            let stream = &self.streams[gpu_index];
            let mut vec = stream.malloc::<u32>(data_per_gpu as u32);
            let input_slice = input.0.as_tensor().as_slice();
            stream.copy_to_gpu::<u32>(&mut vec, input_slice);
            vecs.push(vec);
        }
        CudaGlweCiphertextVector32(CudaGlweList::<u32> {
            d_vecs: vecs,
            glwe_ciphertext_count: input.glwe_ciphertext_count(),
            glwe_dimension: input.glwe_dimension(),
            polynomial_size: input.polynomial_size(),
        })
    }
}

/// # Description
/// Convert a GLWE ciphertext vector view with 64 bits of precision from CPU to GPU.
/// The whole vector of GLWE ciphertexts is copied to all the GPUS: it corresponds
/// to the input vector of lookup tables for the bootstrap.
impl
    GlweCiphertextVectorConversionEngine<
        GlweCiphertextVectorMutView64<'_>,
        CudaGlweCiphertextVector64,
    > for CudaEngine
{
    /// # Example
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(3);
    /// let glwe_count = GlweCiphertextCount(2);
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = vec![3_u64 << 50; polynomial_size.0 * glwe_count.0];
    /// let noise = Variance(2_f64.powf(-50.));
    ///
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let h_key: GlweSecretKey64 =
    ///     default_engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let h_plaintext_vector: PlaintextVector64 =
    ///     default_engine.create_plaintext_vector_from(&input)?;
    /// let mut h_ciphertext_vector: GlweCiphertextVector64 =
    ///     default_engine.encrypt_glwe_ciphertext_vector(&h_key, &h_plaintext_vector, noise)?;
    /// let glwe_ciphertext_count = h_ciphertext_vector.glwe_ciphertext_count();
    ///
    /// let mut h_raw_ciphertext_vector: Vec<u64> =
    ///     default_engine.consume_retrieve_glwe_ciphertext_vector(h_ciphertext_vector)?;
    /// let h_view_ciphertext_vector: GlweCiphertextVectorMutView64 = default_engine
    ///     .create_glwe_ciphertext_vector_from(
    ///         h_raw_ciphertext_vector.as_mut_slice(),
    ///         glwe_dimension,
    ///         polynomial_size,
    ///     )?;
    ///
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_ciphertext_vector: CudaGlweCiphertextVector64 =
    ///     cuda_engine.convert_glwe_ciphertext_vector(&h_view_ciphertext_vector)?;
    /// let h_output_ciphertext_vector: GlweCiphertextVector64 =
    ///     cuda_engine.convert_glwe_ciphertext_vector(&d_ciphertext_vector)?;
    ///
    /// assert_eq!(d_ciphertext_vector.glwe_dimension(), glwe_dimension);
    /// assert_eq!(
    ///     d_ciphertext_vector.glwe_ciphertext_count(),
    ///     glwe_ciphertext_count
    /// );
    /// assert_eq!(d_ciphertext_vector.polynomial_size(), polynomial_size);
    ///
    /// // Extracts the internal container
    /// let h_raw_output_ciphertext_vector: Vec<u64> =
    ///     default_engine.consume_retrieve_glwe_ciphertext_vector(h_output_ciphertext_vector)?;
    /// assert_eq!(
    ///     h_raw_ciphertext_vector,
    ///     h_raw_output_ciphertext_vector.to_vec()
    /// );
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_glwe_ciphertext_vector(
        &mut self,
        input: &GlweCiphertextVectorMutView64,
    ) -> Result<CudaGlweCiphertextVector64, GlweCiphertextVectorConversionError<CudaError>> {
        for gpu_index in 0..self.get_number_of_gpus().0 {
            let stream = &self.streams[gpu_index];
            let data_per_gpu = input.glwe_dimension().to_glwe_size().0
                * input.glwe_ciphertext_count().0
                * input.polynomial_size().0;
            let size = data_per_gpu as u64 * std::mem::size_of::<u64>() as u64;
            stream.check_device_memory(size)?;
        }
        Ok(unsafe { self.convert_glwe_ciphertext_vector_unchecked(input) })
    }

    unsafe fn convert_glwe_ciphertext_vector_unchecked(
        &mut self,
        input: &GlweCiphertextVectorMutView64,
    ) -> CudaGlweCiphertextVector64 {
        // Copy the entire input vector over all GPUs
        let mut vecs = Vec::with_capacity(self.get_number_of_gpus().0 as usize);
        let data_per_gpu = input.glwe_ciphertext_count().0
            * input.glwe_dimension().to_glwe_size().0
            * input.polynomial_size().0;
        for gpu_index in 0..self.get_number_of_gpus().0 {
            let stream = &self.streams[gpu_index];
            let mut vec = stream.malloc::<u64>(data_per_gpu as u32);
            let input_slice = input.0.as_tensor().as_slice();
            stream.copy_to_gpu::<u64>(&mut vec, input_slice);
            vecs.push(vec);
        }
        CudaGlweCiphertextVector64(CudaGlweList::<u64> {
            d_vecs: vecs,
            glwe_ciphertext_count: input.glwe_ciphertext_count(),
            glwe_dimension: input.glwe_dimension(),
            polynomial_size: input.polynomial_size(),
        })
    }
}
