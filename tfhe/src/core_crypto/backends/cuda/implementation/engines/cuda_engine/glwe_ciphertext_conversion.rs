use crate::core_crypto::backends::cuda::engines::{CudaEngine, CudaError};
use crate::core_crypto::backends::cuda::implementation::entities::{
    CudaGlweCiphertext32, CudaGlweCiphertext64,
};
use crate::core_crypto::backends::cuda::private::crypto::glwe::ciphertext::CudaGlweCiphertext;
use crate::core_crypto::commons::crypto::glwe::GlweCiphertext;
use crate::core_crypto::commons::math::tensor::{AsRefSlice, AsRefTensor};
use crate::core_crypto::prelude::{GlweCiphertext32, GlweCiphertext64, GlweCiphertextView64};
use crate::core_crypto::specification::engines::{
    GlweCiphertextConversionEngine, GlweCiphertextConversionError,
};
use crate::core_crypto::specification::entities::GlweCiphertextEntity;

impl From<CudaError> for GlweCiphertextConversionError<CudaError> {
    fn from(err: CudaError) -> Self {
        Self::Engine(err)
    }
}

/// # Description
/// Convert a GLWE ciphertext with 32 bits of precision from CPU to GPU 0.
/// Only this conversion is necessary to run the bootstrap on the GPU.
impl GlweCiphertextConversionEngine<GlweCiphertext32, CudaGlweCiphertext32> for CudaEngine {
    /// # Example
    /// ```
    /// use tfhe::core_crypto::prelude:: *;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(4);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u32 << 20; polynomial_size.0];
    /// let noise = Variance(2_f64.powf(-50.));
    ///
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let h_plaintext_vector: PlaintextVector32 =
    ///     default_engine.create_plaintext_vector_from(&input)?;
    /// let mut h_ciphertext: GlweCiphertext32 = default_engine
    ///     .trivially_encrypt_glwe_ciphertext(glwe_dimension.to_glwe_size(), &h_plaintext_vector)?;
    ///
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_ciphertext: CudaGlweCiphertext32 = cuda_engine.convert_glwe_ciphertext(&h_ciphertext)?;
    ///
    /// assert_eq!(d_ciphertext.glwe_dimension(), glwe_dimension);
    /// assert_eq!(d_ciphertext.polynomial_size(), polynomial_size);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_glwe_ciphertext(
        &mut self,
        input: &GlweCiphertext32,
    ) -> Result<CudaGlweCiphertext32, GlweCiphertextConversionError<CudaError>> {
        let stream = &self.streams[0];
        let data_per_gpu = input.glwe_dimension().to_glwe_size().0 * input.polynomial_size().0;
        let size = data_per_gpu as u64 * std::mem::size_of::<u32>() as u64;
        stream.check_device_memory(size)?;
        Ok(unsafe { self.convert_glwe_ciphertext_unchecked(input) })
    }

    unsafe fn convert_glwe_ciphertext_unchecked(
        &mut self,
        input: &GlweCiphertext32,
    ) -> CudaGlweCiphertext32 {
        // Copy the entire input vector over all GPUs
        let data_per_gpu = input.glwe_dimension().to_glwe_size().0 * input.polynomial_size().0;
        let stream = &self.streams[0];
        let mut vec = stream.malloc::<u32>(data_per_gpu as u32);
        let input_slice = input.0.as_tensor().as_slice();
        stream.copy_to_gpu::<u32>(&mut vec, input_slice);
        CudaGlweCiphertext32(CudaGlweCiphertext::<u32> {
            d_vec: vec,
            glwe_dimension: input.glwe_dimension(),
            polynomial_size: input.polynomial_size(),
        })
    }
}

/// # Description
/// Convert a GLWE ciphertext vector with 32 bits of precision from GPU 0 to CPU.
/// This conversion is not necessary to run the bootstrap on the GPU.
/// It is implemented for testing purposes only.
impl GlweCiphertextConversionEngine<CudaGlweCiphertext32, GlweCiphertext32> for CudaEngine {
    /// # Example
    /// ```
    /// use tfhe::core_crypto::prelude:: *;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(4);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u32 << 20; polynomial_size.0];
    /// let noise = Variance(2_f64.powf(-50.));
    ///
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let h_plaintext_vector: PlaintextVector32 =
    ///     default_engine.create_plaintext_vector_from(&input)?;
    /// let mut h_ciphertext: GlweCiphertext32 = default_engine
    ///     .trivially_encrypt_glwe_ciphertext(glwe_dimension.to_glwe_size(), &h_plaintext_vector)?;
    ///
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_ciphertext: CudaGlweCiphertext32 = cuda_engine.convert_glwe_ciphertext(&h_ciphertext)?;
    /// let h_output_ciphertext: GlweCiphertext32 =
    ///     cuda_engine.convert_glwe_ciphertext(&d_ciphertext)?;
    ///
    /// assert_eq!(d_ciphertext.glwe_dimension(), glwe_dimension);
    /// assert_eq!(d_ciphertext.polynomial_size(), polynomial_size);
    /// assert_eq!(h_ciphertext, h_output_ciphertext);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_glwe_ciphertext(
        &mut self,
        input: &CudaGlweCiphertext32,
    ) -> Result<GlweCiphertext32, GlweCiphertextConversionError<CudaError>> {
        Ok(unsafe { self.convert_glwe_ciphertext_unchecked(input) })
    }

    unsafe fn convert_glwe_ciphertext_unchecked(
        &mut self,
        input: &CudaGlweCiphertext32,
    ) -> GlweCiphertext32 {
        // Copy the data from GPU 0 back to the CPU
        let mut output =
            vec![0u32; input.glwe_dimension().to_glwe_size().0 * input.polynomial_size().0];
        let stream = &self.streams[0];
        stream.copy_to_cpu::<u32>(&mut output, &input.0.d_vec);
        GlweCiphertext32(GlweCiphertext::from_container(
            output,
            input.polynomial_size(),
        ))
    }
}

/// # Description
/// Convert a GLWE ciphertext with 64 bits of precision from CPU to GPU 0.
/// Only this conversion is necessary to run the bootstrap on the GPU.
impl GlweCiphertextConversionEngine<GlweCiphertext64, CudaGlweCiphertext64> for CudaEngine {
    /// # Example
    /// ```
    /// use tfhe::core_crypto::prelude:: *;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(4);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u64 << 20; polynomial_size.0];
    /// let noise = Variance(2_f64.powf(-50.));
    ///
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let h_plaintext_vector: PlaintextVector64 =
    ///     default_engine.create_plaintext_vector_from(&input)?;
    /// let mut h_ciphertext: GlweCiphertext32 = default_engine
    ///     .trivially_encrypt_glwe_ciphertext(glwe_dimension.to_glwe_size(), &h_plaintext_vector)?;
    ///
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_ciphertext: CudaGlweCiphertext64 = cuda_engine.convert_glwe_ciphertext(&h_ciphertext)?;
    ///
    /// assert_eq!(d_ciphertext.glwe_dimension(), glwe_dimension);
    /// assert_eq!(d_ciphertext.polynomial_size(), polynomial_size);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_glwe_ciphertext(
        &mut self,
        input: &GlweCiphertext64,
    ) -> Result<CudaGlweCiphertext64, GlweCiphertextConversionError<CudaError>> {
        let stream = &self.streams[0];
        let data_per_gpu = input.glwe_dimension().to_glwe_size().0 * input.polynomial_size().0;
        let size = data_per_gpu as u64 * std::mem::size_of::<u64>() as u64;
        stream.check_device_memory(size)?;
        Ok(unsafe { self.convert_glwe_ciphertext_unchecked(input) })
    }

    unsafe fn convert_glwe_ciphertext_unchecked(
        &mut self,
        input: &GlweCiphertext64,
    ) -> CudaGlweCiphertext64 {
        // Copy the entire input vector over all GPUs
        let data_per_gpu = input.glwe_dimension().to_glwe_size().0 * input.polynomial_size().0;
        let stream = &self.streams[0];
        let mut vec = stream.malloc::<u64>(data_per_gpu as u32);
        let input_slice = input.0.as_tensor().as_slice();
        stream.copy_to_gpu::<u64>(&mut vec, input_slice);
        CudaGlweCiphertext64(CudaGlweCiphertext::<u64> {
            d_vec: vec,
            glwe_dimension: input.glwe_dimension(),
            polynomial_size: input.polynomial_size(),
        })
    }
}

/// # Description
/// Convert a GLWE ciphertext vector with 64 bits of precision from GPU 0 to CPU.
/// This conversion is not necessary to run the bootstrap on the GPU.
/// It is implemented for testing purposes only.
impl GlweCiphertextConversionEngine<CudaGlweCiphertext64, GlweCiphertext64> for CudaEngine {
    /// # Example
    /// ```
    /// use tfhe::core_crypto::prelude:: *;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(4);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u64 << 20; polynomial_size.0];
    /// let noise = Variance(2_f64.powf(-50.));
    ///
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let h_plaintext_vector: PlaintextVector64 =
    ///     default_engine.create_plaintext_vector_from(&input)?;
    /// let mut h_ciphertext: GlweCiphertext32 = default_engine
    ///     .trivially_encrypt_glwe_ciphertext(glwe_dimension.to_glwe_size(), &h_plaintext_vector)?;
    ///
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_ciphertext: CudaGlweCiphertext64 = cuda_engine.convert_glwe_ciphertext(&h_ciphertext)?;
    /// let h_output_ciphertext: GlweCiphertext64 =
    ///     cuda_engine.convert_glwe_ciphertext(&d_ciphertext)?;
    ///
    /// assert_eq!(d_ciphertext.glwe_dimension(), glwe_dimension);
    /// assert_eq!(d_ciphertext.polynomial_size(), polynomial_size);
    /// assert_eq!(h_ciphertext, h_output_ciphertext);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_glwe_ciphertext(
        &mut self,
        input: &CudaGlweCiphertext64,
    ) -> Result<GlweCiphertext64, GlweCiphertextConversionError<CudaError>> {
        Ok(unsafe { self.convert_glwe_ciphertext_unchecked(input) })
    }

    unsafe fn convert_glwe_ciphertext_unchecked(
        &mut self,
        input: &CudaGlweCiphertext64,
    ) -> GlweCiphertext64 {
        // Copy the data from GPU 0 back to the CPU
        let mut output =
            vec![0u64; input.glwe_dimension().to_glwe_size().0 * input.polynomial_size().0];
        let stream = &self.streams[0];
        stream.copy_to_cpu::<u64>(&mut output, &input.0.d_vec);
        GlweCiphertext64(GlweCiphertext::from_container(
            output,
            input.polynomial_size(),
        ))
    }
}

/// # Description
/// Convert a view of a GLWE ciphertext with 64 bits of precision from CPU to GPU 0.
impl GlweCiphertextConversionEngine<GlweCiphertextView64<'_>, CudaGlweCiphertext64> for CudaEngine {
    /// # Example
    /// ```
    /// use tfhe::core_crypto::prelude:: *;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(4);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u64 << 20; polynomial_size.0];
    /// let noise = Variance(2_f64.powf(-50.));
    ///
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let h_plaintext_vector: PlaintextVector64 =
    ///     default_engine.create_plaintext_vector_from(&input)?;
    /// let mut h_ciphertext: GlweCiphertext32 = default_engine
    ///     .trivially_encrypt_glwe_ciphertext(glwe_dimension.to_glwe_size(), &h_plaintext_vector)?;
    /// let h_raw_ciphertext: Vec<u64> =
    ///     default_engine.consume_retrieve_glwe_ciphertext(h_ciphertext)?;
    /// let mut h_view_ciphertext: GlweCiphertextView64 =
    ///     default_engine.create_glwe_ciphertext_from(h_raw_ciphertext.as_slice(), polynomial_size)?;
    ///
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_ciphertext: CudaGlweCiphertext64 =
    ///     cuda_engine.convert_glwe_ciphertext(&h_view_ciphertext)?;
    /// let h_output_ciphertext: GlweCiphertext64 =
    ///     cuda_engine.convert_glwe_ciphertext(&d_ciphertext)?;
    ///
    /// // Extracts the internal container
    /// let h_raw_output_ciphertext: Vec<u64> =
    ///     default_engine.consume_retrieve_glwe_ciphertext(h_output_ciphertext)?;
    ///
    /// assert_eq!(d_ciphertext.glwe_dimension(), glwe_dimension);
    /// assert_eq!(d_ciphertext.polynomial_size(), polynomial_size);
    /// assert_eq!(h_raw_ciphertext, h_raw_output_ciphertext);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_glwe_ciphertext(
        &mut self,
        input: &GlweCiphertextView64,
    ) -> Result<CudaGlweCiphertext64, GlweCiphertextConversionError<CudaError>> {
        let stream = &self.streams[0];
        let data_per_gpu = input.glwe_dimension().to_glwe_size().0 * input.polynomial_size().0;
        let size = data_per_gpu as u64 * std::mem::size_of::<u64>() as u64;
        stream.check_device_memory(size)?;
        Ok(unsafe { self.convert_glwe_ciphertext_unchecked(input) })
    }

    unsafe fn convert_glwe_ciphertext_unchecked(
        &mut self,
        input: &GlweCiphertextView64,
    ) -> CudaGlweCiphertext64 {
        // Copy the entire input vector over all GPUs
        let data_per_gpu = input.glwe_dimension().to_glwe_size().0 * input.polynomial_size().0;
        let stream = &self.streams[0];
        let mut vec = stream.malloc::<u64>(data_per_gpu as u32);
        let input_slice = input.0.as_tensor().as_slice();
        stream.copy_to_gpu::<u64>(&mut vec, input_slice);
        CudaGlweCiphertext64(CudaGlweCiphertext::<u64> {
            d_vec: vec,
            glwe_dimension: input.glwe_dimension(),
            polynomial_size: input.polynomial_size(),
        })
    }
}
