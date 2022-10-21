use crate::core_crypto::backends::cuda::engines::{CudaEngine, CudaError};
use crate::core_crypto::backends::cuda::implementation::entities::{
    CudaGgswCiphertext32, CudaGgswCiphertext64,
};
use crate::core_crypto::backends::cuda::private::crypto::ggsw::ciphertext::CudaGgswCiphertext;
use crate::core_crypto::commons::crypto::ggsw::StandardGgswCiphertext;
use crate::core_crypto::commons::math::tensor::{AsRefSlice, AsRefTensor};
use crate::core_crypto::prelude::{GgswCiphertext32, GgswCiphertext64};
use crate::core_crypto::specification::engines::{
    GgswCiphertextConversionEngine, GgswCiphertextConversionError,
};
use crate::core_crypto::specification::entities::GgswCiphertextEntity;

impl From<CudaError> for GgswCiphertextConversionError<CudaError> {
    fn from(err: CudaError) -> Self {
        Self::Engine(err)
    }
}

/// # Description
/// Convert a GGSW ciphertext with 32 bits of precision from CPU to GPU 0.
/// Only this conversion is necessary to run the WopPBS on the GPU.
impl GgswCiphertextConversionEngine<GgswCiphertext32, CudaGgswCiphertext32> for CudaEngine {
    /// # Example
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// use std::task::Poll;
    /// let glwe_dimension = GlweDimension(1);
    /// let polynomial_size = PolynomialSize(8);
    /// let level = DecompositionLevelCount(3);
    /// let base_log = DecompositionBaseLog(6);
    /// let std = LogStandardDev::from_log_standard_dev(-60.);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = 3_u32 << 20;
    /// let noise = Variance(2_f64.powf(-50.));
    ///
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let h_key: GlweSecretKey32 =
    ///     default_engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let h_plaintext: Plaintext32 = default_engine.create_plaintext_from(&input)?;
    /// let mut h_ciphertext: GgswCiphertext32 = default_engine.encrypt_scalar_ggsw_ciphertext(
    ///     &h_key,
    ///     &h_plaintext,
    ///     noise,
    ///     level,
    ///     base_log,
    /// )?;
    ///
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_ciphertext: CudaGgswCiphertext32 = cuda_engine.convert_ggsw_ciphertext(&h_ciphertext)?;
    ///
    /// assert_eq!(d_ciphertext.glwe_dimension(), glwe_dimension);
    /// assert_eq!(d_ciphertext.polynomial_size(), polynomial_size);
    /// assert_eq!(d_ciphertext.decomposition_level_count(), level);
    /// assert_eq!(d_ciphertext.decomposition_base_log(), base_log);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_ggsw_ciphertext(
        &mut self,
        input: &GgswCiphertext32,
    ) -> Result<CudaGgswCiphertext32, GgswCiphertextConversionError<CudaError>> {
        let stream = &self.streams[0];
        let data_per_gpu = input.polynomial_size().0
            * input.glwe_dimension().to_glwe_size().0
            * input.glwe_dimension().to_glwe_size().0
            * input.decomposition_level_count().0;
        let size = data_per_gpu as u64 * std::mem::size_of::<u32>() as u64;
        stream.check_device_memory(size)?;
        Ok(unsafe { self.convert_ggsw_ciphertext_unchecked(input) })
    }

    unsafe fn convert_ggsw_ciphertext_unchecked(
        &mut self,
        input: &GgswCiphertext32,
    ) -> CudaGgswCiphertext32 {
        // Copy the entire input vector over GPUs 0
        let data_per_gpu = input.polynomial_size().0
            * input.glwe_dimension().to_glwe_size().0
            * input.glwe_dimension().to_glwe_size().0
            * input.decomposition_level_count().0;
        let stream = &self.streams[0];
        let mut vec = stream.malloc::<u32>(data_per_gpu as u32);
        let input_slice = input.0.as_tensor().as_slice();
        stream.copy_to_gpu::<u32>(&mut vec, input_slice);
        CudaGgswCiphertext32(CudaGgswCiphertext::<u32> {
            d_vec: vec,
            glwe_dimension: input.glwe_dimension(),
            polynomial_size: input.polynomial_size(),
            decomposition_level_count: input.decomposition_level_count(),
            decomposition_base_log: input.decomposition_base_log(),
        })
    }
}

/// # Description
/// Convert a GGSW ciphertext vector with 32 bits of precision from GPU 0 to CPU.
/// This conversion is not necessary to run the bootstrap on the GPU.
/// It is implemented for testing purposes only.
impl GgswCiphertextConversionEngine<CudaGgswCiphertext32, GgswCiphertext32> for CudaEngine {
    /// # Example
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// use std::task::Poll;
    /// let glwe_dimension = GlweDimension(1);
    /// let polynomial_size = PolynomialSize(8);
    /// let level = DecompositionLevelCount(3);
    /// let base_log = DecompositionBaseLog(6);
    /// let std = LogStandardDev::from_log_standard_dev(-60.);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = 3_u32 << 20;
    /// let noise = Variance(2_f64.powf(-50.));
    ///
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let h_key: GlweSecretKey32 =
    ///     default_engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let h_plaintext: Plaintext32 = default_engine.create_plaintext_from(&input)?;
    /// let mut h_ciphertext: GgswCiphertext32 = default_engine.encrypt_scalar_ggsw_ciphertext(
    ///     &h_key,
    ///     &h_plaintext,
    ///     noise,
    ///     level,
    ///     base_log,
    /// )?;
    ///
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_ciphertext: CudaGgswCiphertext32 = cuda_engine.convert_ggsw_ciphertext(&h_ciphertext)?;
    /// let h_output_ciphertext: GgswCiphertext32 =
    ///     cuda_engine.convert_ggsw_ciphertext(&d_ciphertext)?;
    ///
    /// assert_eq!(d_ciphertext.glwe_dimension(), glwe_dimension);
    /// assert_eq!(d_ciphertext.polynomial_size(), polynomial_size);
    /// assert_eq!(d_ciphertext.decomposition_level_count(), level);
    /// assert_eq!(d_ciphertext.decomposition_base_log(), base_log);
    /// assert_eq!(h_ciphertext, h_output_ciphertext);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_ggsw_ciphertext(
        &mut self,
        input: &CudaGgswCiphertext32,
    ) -> Result<GgswCiphertext32, GgswCiphertextConversionError<CudaError>> {
        Ok(unsafe { self.convert_ggsw_ciphertext_unchecked(input) })
    }

    unsafe fn convert_ggsw_ciphertext_unchecked(
        &mut self,
        input: &CudaGgswCiphertext32,
    ) -> GgswCiphertext32 {
        // Copy the data from GPU 0 back to the CPU
        let data_per_gpu = input.polynomial_size().0
            * input.glwe_dimension().to_glwe_size().0
            * input.glwe_dimension().to_glwe_size().0
            * input.decomposition_level_count().0;
        let mut output = vec![0u32; data_per_gpu];
        let stream = &self.streams[0];
        stream.copy_to_cpu::<u32>(&mut output, &input.0.d_vec);
        GgswCiphertext32(StandardGgswCiphertext::from_container(
            output,
            input.glwe_dimension().to_glwe_size(),
            input.polynomial_size(),
            input.decomposition_base_log(),
        ))
    }
}

/// # Description
/// Convert a GGSW ciphertext with 64 bits of precision from CPU to GPU 0.
/// Only this conversion is necessary to run the WopPBS on the GPU.
impl GgswCiphertextConversionEngine<GgswCiphertext64, CudaGgswCiphertext64> for CudaEngine {
    /// # Example
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// use std::task::Poll;
    /// let glwe_dimension = GlweDimension(1);
    /// let polynomial_size = PolynomialSize(8);
    /// let level = DecompositionLevelCount(3);
    /// let base_log = DecompositionBaseLog(6);
    /// let std = LogStandardDev::from_log_standard_dev(-60.);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = 42_u64;
    /// let noise = Variance(2_f64.powf(-50.));
    ///
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let h_key: GlweSecretKey64 =
    ///     default_engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let h_plaintext: Plaintext64 = default_engine.create_plaintext_from(&input)?;
    /// let mut h_ciphertext: GgswCiphertext64 = default_engine.encrypt_scalar_ggsw_ciphertext(
    ///     &h_key,
    ///     &h_plaintext,
    ///     noise,
    ///     level,
    ///     base_log,
    /// )?;
    ///
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_ciphertext: CudaGgswCiphertext64 = cuda_engine.convert_ggsw_ciphertext(&h_ciphertext)?;
    ///
    /// assert_eq!(d_ciphertext.glwe_dimension(), glwe_dimension);
    /// assert_eq!(d_ciphertext.polynomial_size(), polynomial_size);
    /// assert_eq!(d_ciphertext.decomposition_level_count(), level);
    /// assert_eq!(d_ciphertext.decomposition_base_log(), base_log);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_ggsw_ciphertext(
        &mut self,
        input: &GgswCiphertext64,
    ) -> Result<CudaGgswCiphertext64, GgswCiphertextConversionError<CudaError>> {
        let stream = &self.streams[0];
        let data_per_gpu = input.polynomial_size().0
            * input.glwe_dimension().to_glwe_size().0
            * input.glwe_dimension().to_glwe_size().0
            * input.decomposition_level_count().0;
        let size = data_per_gpu as u64 * std::mem::size_of::<u64>() as u64;
        stream.check_device_memory(size)?;
        Ok(unsafe { self.convert_ggsw_ciphertext_unchecked(input) })
    }

    unsafe fn convert_ggsw_ciphertext_unchecked(
        &mut self,
        input: &GgswCiphertext64,
    ) -> CudaGgswCiphertext64 {
        // Copy the entire input vector over GPU 0
        let data_per_gpu = input.polynomial_size().0
            * input.glwe_dimension().to_glwe_size().0
            * input.glwe_dimension().to_glwe_size().0
            * input.decomposition_level_count().0;
        let stream = &self.streams[0];
        let mut vec = stream.malloc::<u64>(data_per_gpu as u32);
        let input_slice = input.0.as_tensor().as_slice();
        stream.copy_to_gpu::<u64>(&mut vec, input_slice);
        CudaGgswCiphertext64(CudaGgswCiphertext::<u64> {
            d_vec: vec,
            glwe_dimension: input.glwe_dimension(),
            polynomial_size: input.polynomial_size(),
            decomposition_level_count: input.decomposition_level_count(),
            decomposition_base_log: input.decomposition_base_log(),
        })
    }
}

/// # Description
/// Convert a GGSW ciphertext vector with 64 bits of precision from GPU 0 to CPU.
/// This conversion is not necessary to run the bootstrap on the GPU.
/// It is implemented for testing purposes only.
impl GgswCiphertextConversionEngine<CudaGgswCiphertext64, GgswCiphertext64> for CudaEngine {
    /// # Example
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// use std::task::Poll;
    /// let glwe_dimension = GlweDimension(1);
    /// let polynomial_size = PolynomialSize(8);
    /// let level = DecompositionLevelCount(3);
    /// let base_log = DecompositionBaseLog(6);
    /// let std = LogStandardDev::from_log_standard_dev(-60.);
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = 3_u64 << 50;
    /// let noise = Variance(2_f64.powf(-50.));
    ///
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let h_key: GlweSecretKey64 =
    ///     default_engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let h_plaintext: Plaintext64 = default_engine.create_plaintext_from(&input)?;
    /// let mut h_ciphertext: GgswCiphertext64 = default_engine.encrypt_scalar_ggsw_ciphertext(
    ///     &h_key,
    ///     &h_plaintext,
    ///     noise,
    ///     level,
    ///     base_log,
    /// )?;
    ///
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_ciphertext: CudaGgswCiphertext64 = cuda_engine.convert_ggsw_ciphertext(&h_ciphertext)?;
    /// let h_output_ciphertext: GgswCiphertext64 =
    ///     cuda_engine.convert_ggsw_ciphertext(&d_ciphertext)?;
    ///
    /// assert_eq!(d_ciphertext.glwe_dimension(), glwe_dimension);
    /// assert_eq!(d_ciphertext.polynomial_size(), polynomial_size);
    /// assert_eq!(d_ciphertext.decomposition_level_count(), level);
    /// assert_eq!(d_ciphertext.decomposition_base_log(), base_log);
    /// assert_eq!(h_ciphertext, h_output_ciphertext);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_ggsw_ciphertext(
        &mut self,
        input: &CudaGgswCiphertext64,
    ) -> Result<GgswCiphertext64, GgswCiphertextConversionError<CudaError>> {
        Ok(unsafe { self.convert_ggsw_ciphertext_unchecked(input) })
    }

    unsafe fn convert_ggsw_ciphertext_unchecked(
        &mut self,
        input: &CudaGgswCiphertext64,
    ) -> GgswCiphertext64 {
        // Copy the data from GPU 0 back to the CPU
        let data_per_gpu = input.polynomial_size().0
            * input.glwe_dimension().to_glwe_size().0
            * input.glwe_dimension().to_glwe_size().0
            * input.decomposition_level_count().0;
        let mut output = vec![0u64; data_per_gpu];
        let stream = &self.streams[0];
        stream.copy_to_cpu::<u64>(&mut output, &input.0.d_vec);
        GgswCiphertext64(StandardGgswCiphertext::from_container(
            output,
            input.glwe_dimension().to_glwe_size(),
            input.polynomial_size(),
            input.decomposition_base_log(),
        ))
    }
}
