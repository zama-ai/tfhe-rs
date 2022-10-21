use crate::core_crypto::backends::cuda::engines::CudaError;
use crate::core_crypto::backends::cuda::implementation::engines::CudaEngine;
use crate::core_crypto::backends::cuda::implementation::entities::{
    CudaLweKeyswitchKey32, CudaLweKeyswitchKey64,
};
use crate::core_crypto::backends::cuda::private::crypto::keyswitch::CudaLweKeyswitchKey;
use crate::core_crypto::commons::crypto::lwe::LweKeyswitchKey;
use crate::core_crypto::commons::math::tensor::{AsRefSlice, AsRefTensor};
use crate::core_crypto::prelude::{LweKeyswitchKey32, LweKeyswitchKey64};
use crate::core_crypto::specification::engines::{
    LweKeyswitchKeyConversionEngine, LweKeyswitchKeyConversionError,
};
use crate::core_crypto::specification::entities::LweKeyswitchKeyEntity;

impl From<CudaError> for LweKeyswitchKeyConversionError<CudaError> {
    fn from(err: CudaError) -> Self {
        Self::Engine(err)
    }
}

/// # Description
/// Convert an LWE keyswitch key corresponding to 32 bits of precision from the CPU to the GPU.
/// We only support the conversion from CPU to GPU: the conversion from GPU to CPU is not
/// necessary at this stage to support the keyswitch. The keyswitch key is copied entirely to all
/// the GPUs.
impl LweKeyswitchKeyConversionEngine<LweKeyswitchKey32, CudaLweKeyswitchKey32> for CudaEngine {
    /// # Example
    /// ```
    /// use tfhe::core_crypto::backends::cuda::private::device::GpuIndex;
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, LweDimension, Variance, *,
    /// };
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let input_lwe_dimension = LweDimension(6);
    /// let output_lwe_dimension = LweDimension(3);
    /// let decomposition_level_count = DecompositionLevelCount(2);
    /// let decomposition_base_log = DecompositionBaseLog(8);
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let input_key: LweSecretKey32 =
    ///     default_engine.generate_new_lwe_secret_key(input_lwe_dimension)?;
    /// let output_key: LweSecretKey32 =
    ///     default_engine.generate_new_lwe_secret_key(output_lwe_dimension)?;
    /// let ksk = default_engine.generate_new_lwe_keyswitch_key(
    ///     &input_key,
    ///     &output_key,
    ///     decomposition_level_count,
    ///     decomposition_base_log,
    ///     noise,
    /// )?;
    ///
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_ksk: CudaLweKeyswitchKey32 = cuda_engine.convert_lwe_keyswitch_key(&ksk)?;
    ///
    /// assert_eq!(d_ksk.input_lwe_dimension(), input_lwe_dimension);
    /// assert_eq!(d_ksk.output_lwe_dimension(), output_lwe_dimension);
    /// assert_eq!(d_ksk.decomposition_level_count(), decomposition_level_count);
    /// assert_eq!(d_ksk.decomposition_base_log(), decomposition_base_log);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_lwe_keyswitch_key(
        &mut self,
        input: &LweKeyswitchKey32,
    ) -> Result<CudaLweKeyswitchKey32, LweKeyswitchKeyConversionError<CudaError>> {
        for gpu_index in 0..self.get_number_of_gpus().0 {
            let stream = &self.streams[gpu_index];
            let data_per_gpu = input.decomposition_level_count().0
                * (input.output_lwe_dimension().0 + 1)
                * input.input_lwe_dimension().0;
            let size = data_per_gpu as u64 * std::mem::size_of::<u32>() as u64;
            stream.check_device_memory(size)?;
        }
        Ok(unsafe { self.convert_lwe_keyswitch_key_unchecked(input) })
    }

    unsafe fn convert_lwe_keyswitch_key_unchecked(
        &mut self,
        input: &LweKeyswitchKey32,
    ) -> CudaLweKeyswitchKey32 {
        // Copy the entire input vector over all GPUs
        let mut d_vecs = Vec::with_capacity(self.get_number_of_gpus().0);

        let data_per_gpu = input.decomposition_level_count().0
            * input.output_lwe_dimension().to_lwe_size().0
            * input.input_lwe_dimension().0;
        for stream in self.streams.iter() {
            let mut d_vec = stream.malloc::<u32>(data_per_gpu as u32);
            stream.copy_to_gpu(&mut d_vec, input.0.as_tensor().as_slice());
            d_vecs.push(d_vec);
        }
        CudaLweKeyswitchKey32(CudaLweKeyswitchKey::<u32> {
            d_vecs,
            input_lwe_dimension: input.input_lwe_dimension(),
            output_lwe_dimension: input.output_lwe_dimension(),
            decomp_level: input.decomposition_level_count(),
            decomp_base_log: input.decomposition_base_log(),
        })
    }
}

/// # Description
/// Convert an LWE keyswitch key corresponding to 32 bits of precision from the GPU to the CPU.
/// We assume consistency between all the available GPUs and simply copy what is in the one with
/// index 0.
impl LweKeyswitchKeyConversionEngine<CudaLweKeyswitchKey32, LweKeyswitchKey32> for CudaEngine {
    /// # Example
    /// ```
    /// use tfhe::core_crypto::backends::cuda::private::device::GpuIndex;
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, LweDimension, Variance, *,
    /// };
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let input_lwe_dimension = LweDimension(6);
    /// let output_lwe_dimension = LweDimension(3);
    /// let decomposition_level_count = DecompositionLevelCount(2);
    /// let decomposition_base_log = DecompositionBaseLog(8);
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let input_key: LweSecretKey32 =
    ///     default_engine.generate_new_lwe_secret_key(input_lwe_dimension)?;
    /// let output_key: LweSecretKey32 =
    ///     default_engine.generate_new_lwe_secret_key(output_lwe_dimension)?;
    /// let h_ksk = default_engine.generate_new_lwe_keyswitch_key(
    ///     &input_key,
    ///     &output_key,
    ///     decomposition_level_count,
    ///     decomposition_base_log,
    ///     noise,
    /// )?;
    ///
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_ksk: CudaLweKeyswitchKey32 = cuda_engine.convert_lwe_keyswitch_key(&h_ksk)?;
    /// let h_output_ksk: LweKeyswitchKey32 = cuda_engine.convert_lwe_keyswitch_key(&d_ksk)?;
    ///
    /// assert_eq!(d_ksk.input_lwe_dimension(), input_lwe_dimension);
    /// assert_eq!(d_ksk.output_lwe_dimension(), output_lwe_dimension);
    /// assert_eq!(d_ksk.decomposition_level_count(), decomposition_level_count);
    /// assert_eq!(d_ksk.decomposition_base_log(), decomposition_base_log);
    /// assert_eq!(h_output_ksk, h_ksk);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_lwe_keyswitch_key(
        &mut self,
        input: &CudaLweKeyswitchKey32,
    ) -> Result<LweKeyswitchKey32, LweKeyswitchKeyConversionError<CudaError>> {
        Ok(unsafe { self.convert_lwe_keyswitch_key_unchecked(input) })
    }

    unsafe fn convert_lwe_keyswitch_key_unchecked(
        &mut self,
        input: &CudaLweKeyswitchKey32,
    ) -> LweKeyswitchKey32 {
        let data_per_gpu = input.decomposition_level_count().0
            * input.output_lwe_dimension().to_lwe_size().0
            * input.input_lwe_dimension().0;

        // Copy the data from GPU 0 back to the CPU
        let mut output = vec![0u32; data_per_gpu];
        let stream = self.streams.first().unwrap();
        stream.copy_to_cpu::<u32>(&mut output, input.0.d_vecs.first().unwrap());

        LweKeyswitchKey32(LweKeyswitchKey::from_container(
            output,
            input.decomposition_base_log(),
            input.decomposition_level_count(),
            input.output_lwe_dimension(),
        ))
    }
}

/// # Description
/// Convert an LWE keyswitch key corresponding to 64 bits of precision from the CPU to the GPU.
/// We only support the conversion from CPU to GPU: the conversion from GPU to CPU is not
/// necessary at this stage to support the keyswitch. The keyswitch key is copied entirely to all
/// the GPUs.
impl LweKeyswitchKeyConversionEngine<LweKeyswitchKey64, CudaLweKeyswitchKey64> for CudaEngine {
    /// # Example
    /// ```
    /// use tfhe::core_crypto::backends::cuda::private::device::GpuIndex;
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, LweDimension, Variance, *,
    /// };
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let input_lwe_dimension = LweDimension(6);
    /// let output_lwe_dimension = LweDimension(3);
    /// let decomposition_level_count = DecompositionLevelCount(2);
    /// let decomposition_base_log = DecompositionBaseLog(8);
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let input_key: LweSecretKey64 =
    ///     default_engine.generate_new_lwe_secret_key(input_lwe_dimension)?;
    /// let output_key: LweSecretKey64 =
    ///     default_engine.generate_new_lwe_secret_key(output_lwe_dimension)?;
    /// let ksk = default_engine.generate_new_lwe_keyswitch_key(
    ///     &input_key,
    ///     &output_key,
    ///     decomposition_level_count,
    ///     decomposition_base_log,
    ///     noise,
    /// )?;
    ///
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_ksk: CudaLweKeyswitchKey64 = cuda_engine.convert_lwe_keyswitch_key(&ksk)?;
    ///
    /// assert_eq!(d_ksk.input_lwe_dimension(), input_lwe_dimension);
    /// assert_eq!(d_ksk.output_lwe_dimension(), output_lwe_dimension);
    /// assert_eq!(d_ksk.decomposition_level_count(), decomposition_level_count);
    /// assert_eq!(d_ksk.decomposition_base_log(), decomposition_base_log);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_lwe_keyswitch_key(
        &mut self,
        input: &LweKeyswitchKey64,
    ) -> Result<CudaLweKeyswitchKey64, LweKeyswitchKeyConversionError<CudaError>> {
        for stream in self.streams.iter() {
            let data_per_gpu = input.decomposition_level_count().0
                * input.output_lwe_dimension().to_lwe_size().0
                * input.input_lwe_dimension().0;
            let size = data_per_gpu as u64 * std::mem::size_of::<u64>() as u64;
            stream.check_device_memory(size)?;
        }
        Ok(unsafe { self.convert_lwe_keyswitch_key_unchecked(input) })
    }

    unsafe fn convert_lwe_keyswitch_key_unchecked(
        &mut self,
        input: &LweKeyswitchKey64,
    ) -> CudaLweKeyswitchKey64 {
        // Copy the entire input vector over all GPUs
        let mut d_vecs = Vec::with_capacity(self.get_number_of_gpus().0);

        let data_per_gpu = input.decomposition_level_count().0
            * input.output_lwe_dimension().to_lwe_size().0
            * input.input_lwe_dimension().0;
        for stream in self.streams.iter() {
            let mut d_vec = stream.malloc::<u64>(data_per_gpu as u32);
            stream.copy_to_gpu(&mut d_vec, input.0.as_tensor().as_slice());
            d_vecs.push(d_vec);
        }
        CudaLweKeyswitchKey64(CudaLweKeyswitchKey::<u64> {
            d_vecs,
            input_lwe_dimension: input.input_lwe_dimension(),
            output_lwe_dimension: input.output_lwe_dimension(),
            decomp_level: input.decomposition_level_count(),
            decomp_base_log: input.decomposition_base_log(),
        })
    }
}

impl LweKeyswitchKeyConversionEngine<CudaLweKeyswitchKey64, LweKeyswitchKey64> for CudaEngine {
    /// # Example
    /// ```
    /// use tfhe::core_crypto::backends::cuda::private::device::GpuIndex;
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, LweDimension, Variance, *,
    /// };
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let input_lwe_dimension = LweDimension(6);
    /// let output_lwe_dimension = LweDimension(3);
    /// let decomposition_level_count = DecompositionLevelCount(2);
    /// let decomposition_base_log = DecompositionBaseLog(8);
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let input_key: LweSecretKey64 =
    ///     default_engine.generate_new_lwe_secret_key(input_lwe_dimension)?;
    /// let output_key: LweSecretKey64 =
    ///     default_engine.generate_new_lwe_secret_key(output_lwe_dimension)?;
    /// let h_ksk = default_engine.generate_new_lwe_keyswitch_key(
    ///     &input_key,
    ///     &output_key,
    ///     decomposition_level_count,
    ///     decomposition_base_log,
    ///     noise,
    /// )?;
    ///
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_ksk: CudaLweKeyswitchKey64 = cuda_engine.convert_lwe_keyswitch_key(&h_ksk)?;
    /// let h_output_ksk: LweKeyswitchKey64 = cuda_engine.convert_lwe_keyswitch_key(&d_ksk)?;
    ///
    /// assert_eq!(d_ksk.input_lwe_dimension(), input_lwe_dimension);
    /// assert_eq!(d_ksk.output_lwe_dimension(), output_lwe_dimension);
    /// assert_eq!(d_ksk.decomposition_level_count(), decomposition_level_count);
    /// assert_eq!(d_ksk.decomposition_base_log(), decomposition_base_log);
    /// assert_eq!(h_output_ksk, h_ksk);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_lwe_keyswitch_key(
        &mut self,
        input: &CudaLweKeyswitchKey64,
    ) -> Result<LweKeyswitchKey64, LweKeyswitchKeyConversionError<CudaError>> {
        Ok(unsafe { self.convert_lwe_keyswitch_key_unchecked(input) })
    }

    unsafe fn convert_lwe_keyswitch_key_unchecked(
        &mut self,
        input: &CudaLweKeyswitchKey64,
    ) -> LweKeyswitchKey64 {
        let data_per_gpu = input.decomposition_level_count().0
            * input.output_lwe_dimension().to_lwe_size().0
            * input.input_lwe_dimension().0;

        // Copy the data from GPU 0 back to the CPU
        let mut output = vec![0u64; data_per_gpu];
        let stream = self.streams.first().unwrap();
        stream.copy_to_cpu::<u64>(&mut output, input.0.d_vecs.first().unwrap());

        LweKeyswitchKey64(LweKeyswitchKey::from_container(
            output,
            input.decomposition_base_log(),
            input.decomposition_level_count(),
            input.output_lwe_dimension(),
        ))
    }
}
