use crate::core_crypto::backends::cuda::implementation::engines::{CudaEngine, CudaError};
use crate::core_crypto::backends::cuda::implementation::entities::{
    CudaLweCiphertextVector32, CudaLweCiphertextVector64,
};
use crate::core_crypto::backends::cuda::private::crypto::lwe::list::{
    copy_lwe_ciphertext_vector_from_cpu_to_gpu, copy_lwe_ciphertext_vector_from_gpu_to_cpu,
    CudaLweList,
};
use crate::core_crypto::backends::cuda::private::device::GpuIndex;
use crate::core_crypto::backends::cuda::private::{
    compute_number_of_samples_on_gpu, number_of_active_gpus,
};
use crate::core_crypto::commons::crypto::lwe::LweList;
use crate::core_crypto::prelude::{
    CiphertextCount, LweCiphertextVector32, LweCiphertextVector64, LweCiphertextVectorMutView32,
    LweCiphertextVectorMutView64, LweCiphertextVectorView32, LweCiphertextVectorView64,
};
use crate::core_crypto::specification::engines::{
    LweCiphertextVectorConversionEngine, LweCiphertextVectorConversionError,
};
use crate::core_crypto::specification::entities::LweCiphertextVectorEntity;

impl From<CudaError> for LweCiphertextVectorConversionError<CudaError> {
    fn from(err: CudaError) -> Self {
        Self::Engine(err)
    }
}

/// # Description
/// Convert an LWE ciphertext vector with 32 bits of precision from CPU to GPU.
///
/// The input ciphertext vector is split over GPUs, so that each GPU contains
/// the total amount of ciphertexts divided by the number of GPUs on the machine.
/// The last GPU takes the remainder of the division if there is any.
impl LweCiphertextVectorConversionEngine<LweCiphertextVector32, CudaLweCiphertextVector32>
    for CudaEngine
{
    /// # Example
    /// ```
    /// use tfhe::core_crypto::prelude::{LweCiphertextCount, LweDimension, Variance, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(6);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u32 << 20; 3];
    /// let noise = Variance(2_f64.powf(-50.));
    ///
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let h_key: LweSecretKey32 = default_engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let h_plaintext_vector: PlaintextVector32 =
    ///     default_engine.create_plaintext_vector_from(&input)?;
    /// let mut h_ciphertext_vector: LweCiphertextVector32 =
    ///     default_engine.encrypt_lwe_ciphertext_vector(&h_key, &h_plaintext_vector, noise)?;
    ///
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_ciphertext_vector: CudaLweCiphertextVector32 =
    ///     cuda_engine.convert_lwe_ciphertext_vector(&h_ciphertext_vector)?;
    ///
    /// assert_eq!(d_ciphertext_vector.lwe_dimension(), lwe_dimension);
    /// assert_eq!(
    ///     d_ciphertext_vector.lwe_ciphertext_count(),
    ///     LweCiphertextCount(3)
    /// );
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_lwe_ciphertext_vector(
        &mut self,
        input: &LweCiphertextVector32,
    ) -> Result<CudaLweCiphertextVector32, LweCiphertextVectorConversionError<CudaError>> {
        let number_of_gpus = number_of_active_gpus(
            self.get_number_of_gpus(),
            CiphertextCount(input.lwe_ciphertext_count().0),
        );
        for gpu_index in 0..number_of_gpus.0 {
            let stream = &self.streams[gpu_index];
            let samples = compute_number_of_samples_on_gpu(
                self.get_number_of_gpus(),
                CiphertextCount(input.lwe_ciphertext_count().0),
                GpuIndex(gpu_index),
            );
            let data_per_gpu = samples.0 * input.lwe_dimension().to_lwe_size().0;
            let size = data_per_gpu as u64 * std::mem::size_of::<u32>() as u64;
            stream.check_device_memory(size)?;
        }
        Ok(unsafe { self.convert_lwe_ciphertext_vector_unchecked(input) })
    }

    unsafe fn convert_lwe_ciphertext_vector_unchecked(
        &mut self,
        input: &LweCiphertextVector32,
    ) -> CudaLweCiphertextVector32 {
        let vecs = copy_lwe_ciphertext_vector_from_cpu_to_gpu::<u32, _>(
            self.get_cuda_streams(),
            &input.0,
            self.get_number_of_gpus(),
        );
        CudaLweCiphertextVector32(CudaLweList::<u32> {
            d_vecs: vecs,
            lwe_ciphertext_count: input.lwe_ciphertext_count(),
            lwe_dimension: input.lwe_dimension(),
        })
    }
}

/// # Description
/// Convert an LWE ciphertext vector with 32 bits of precision from GPU to CPU.
/// The data from each GPU is copied into a part of an LweCiphertextVector32 on the CPU.
impl LweCiphertextVectorConversionEngine<CudaLweCiphertextVector32, LweCiphertextVector32>
    for CudaEngine
{
    /// # Example
    /// ```
    /// use tfhe::core_crypto::prelude::{LweCiphertextCount, LweDimension, Variance, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(6);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u32 << 20; 3];
    /// let noise = Variance(2_f64.powf(-50.));
    ///
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let h_key: LweSecretKey32 = default_engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let h_plaintext_vector: PlaintextVector32 =
    ///     default_engine.create_plaintext_vector_from(&input)?;
    /// let mut h_ciphertext_vector: LweCiphertextVector32 =
    ///     default_engine.encrypt_lwe_ciphertext_vector(&h_key, &h_plaintext_vector, noise)?;
    ///
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_ciphertext_vector: CudaLweCiphertextVector32 =
    ///     cuda_engine.convert_lwe_ciphertext_vector(&h_ciphertext_vector)?;
    ///
    /// let h_ciphertext_vector_output: LweCiphertextVector32 =
    ///     cuda_engine.convert_lwe_ciphertext_vector(&d_ciphertext_vector)?;
    /// assert_eq!(h_ciphertext_vector_output.lwe_dimension(), lwe_dimension);
    /// assert_eq!(
    ///     h_ciphertext_vector_output.lwe_ciphertext_count(),
    ///     LweCiphertextCount(3)
    /// );
    /// assert_eq!(h_ciphertext_vector, h_ciphertext_vector_output);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_lwe_ciphertext_vector(
        &mut self,
        input: &CudaLweCiphertextVector32,
    ) -> Result<LweCiphertextVector32, LweCiphertextVectorConversionError<CudaError>> {
        Ok(unsafe { self.convert_lwe_ciphertext_vector_unchecked(input) })
    }

    unsafe fn convert_lwe_ciphertext_vector_unchecked(
        &mut self,
        input: &CudaLweCiphertextVector32,
    ) -> LweCiphertextVector32 {
        let output = copy_lwe_ciphertext_vector_from_gpu_to_cpu::<u32>(
            self.get_cuda_streams(),
            &input.0,
            self.get_number_of_gpus(),
        );
        LweCiphertextVector32(LweList::from_container(
            output,
            input.lwe_dimension().to_lwe_size(),
        ))
    }
}

/// # Description
/// Convert an LWE ciphertext vector with 64 bits of precision from CPU to GPU.
///
/// The input ciphertext vector is split over GPUs, so that each GPU contains
/// the total amount of ciphertexts divided by the number of GPUs on the machine.
/// The last GPU takes the remainder of the division if there is any.
impl LweCiphertextVectorConversionEngine<LweCiphertextVector64, CudaLweCiphertextVector64>
    for CudaEngine
{
    /// # Example
    /// ```
    /// use tfhe::core_crypto::prelude::{LweCiphertextCount, LweDimension, Variance, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(6);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u64 << 20; 3];
    /// let noise = Variance(2_f64.powf(-50.));
    ///
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let h_key: LweSecretKey64 = default_engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let h_plaintext_vector: PlaintextVector64 =
    ///     default_engine.create_plaintext_vector_from(&input)?;
    /// let mut h_ciphertext_vector: LweCiphertextVector64 =
    ///     default_engine.encrypt_lwe_ciphertext_vector(&h_key, &h_plaintext_vector, noise)?;
    ///
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_ciphertext_vector: CudaLweCiphertextVector64 =
    ///     cuda_engine.convert_lwe_ciphertext_vector(&h_ciphertext_vector)?;
    ///
    /// assert_eq!(d_ciphertext_vector.lwe_dimension(), lwe_dimension);
    /// assert_eq!(
    ///     d_ciphertext_vector.lwe_ciphertext_count(),
    ///     LweCiphertextCount(3)
    /// );
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_lwe_ciphertext_vector(
        &mut self,
        input: &LweCiphertextVector64,
    ) -> Result<CudaLweCiphertextVector64, LweCiphertextVectorConversionError<CudaError>> {
        let number_of_gpus = number_of_active_gpus(
            self.get_number_of_gpus(),
            CiphertextCount(input.lwe_ciphertext_count().0),
        );
        for gpu_index in 0..number_of_gpus.0 {
            let stream = &self.streams[gpu_index];
            let samples = compute_number_of_samples_on_gpu(
                self.get_number_of_gpus(),
                CiphertextCount(input.lwe_ciphertext_count().0),
                GpuIndex(gpu_index),
            );
            let data_per_gpu = samples.0 * input.lwe_dimension().to_lwe_size().0;
            let size = data_per_gpu as u64 * std::mem::size_of::<u64>() as u64;
            stream.check_device_memory(size)?;
        }
        Ok(unsafe { self.convert_lwe_ciphertext_vector_unchecked(input) })
    }

    unsafe fn convert_lwe_ciphertext_vector_unchecked(
        &mut self,
        input: &LweCiphertextVector64,
    ) -> CudaLweCiphertextVector64 {
        let vecs = copy_lwe_ciphertext_vector_from_cpu_to_gpu::<u64, _>(
            self.get_cuda_streams(),
            &input.0,
            self.get_number_of_gpus(),
        );
        CudaLweCiphertextVector64(CudaLweList::<u64> {
            d_vecs: vecs,
            lwe_ciphertext_count: input.lwe_ciphertext_count(),
            lwe_dimension: input.lwe_dimension(),
        })
    }
}

/// # Description
/// Convert an LWE ciphertext vector with 64 bits of precision from GPU to CPU.
/// The data from each GPU is copied into a part of an LweCiphertextVector64 on the CPU.
impl LweCiphertextVectorConversionEngine<CudaLweCiphertextVector64, LweCiphertextVector64>
    for CudaEngine
{
    /// # Example
    /// ```
    /// use tfhe::core_crypto::prelude::{LweCiphertextCount, LweDimension, Variance, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(6);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u64 << 20; 3];
    /// let noise = Variance(2_f64.powf(-50.));
    ///
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let h_key: LweSecretKey64 = default_engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let h_plaintext_vector: PlaintextVector64 =
    ///     default_engine.create_plaintext_vector_from(&input)?;
    /// let mut h_ciphertext_vector: LweCiphertextVector64 =
    ///     default_engine.encrypt_lwe_ciphertext_vector(&h_key, &h_plaintext_vector, noise)?;
    ///
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_ciphertext_vector: CudaLweCiphertextVector64 =
    ///     cuda_engine.convert_lwe_ciphertext_vector(&h_ciphertext_vector)?;
    ///
    /// let h_ciphertext_vector_output: LweCiphertextVector64 =
    ///     cuda_engine.convert_lwe_ciphertext_vector(&d_ciphertext_vector)?;
    /// assert_eq!(h_ciphertext_vector_output.lwe_dimension(), lwe_dimension);
    /// assert_eq!(
    ///     h_ciphertext_vector_output.lwe_ciphertext_count(),
    ///     LweCiphertextCount(3)
    /// );
    /// assert_eq!(h_ciphertext_vector, h_ciphertext_vector_output);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_lwe_ciphertext_vector(
        &mut self,
        input: &CudaLweCiphertextVector64,
    ) -> Result<LweCiphertextVector64, LweCiphertextVectorConversionError<CudaError>> {
        Ok(unsafe { self.convert_lwe_ciphertext_vector_unchecked(input) })
    }

    unsafe fn convert_lwe_ciphertext_vector_unchecked(
        &mut self,
        input: &CudaLweCiphertextVector64,
    ) -> LweCiphertextVector64 {
        let output = copy_lwe_ciphertext_vector_from_gpu_to_cpu::<u64>(
            self.get_cuda_streams(),
            &input.0,
            self.get_number_of_gpus(),
        );
        LweCiphertextVector64(LweList::from_container(
            output,
            input.lwe_dimension().to_lwe_size(),
        ))
    }
}

/// # Description
/// Convert an LWE ciphertext vector view with 32 bits of precision from CPU to GPU.
///
/// The input ciphertext vector view is split over GPUs, so that each GPU contains
/// the total amount of ciphertexts divided by the number of GPUs on the machine.
/// The last GPU takes the remainder of the division if there is any.
impl LweCiphertextVectorConversionEngine<LweCiphertextVectorView32<'_>, CudaLweCiphertextVector32>
    for CudaEngine
{
    /// # Example
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(6);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u32 << 20; 3];
    /// let noise = Variance(2_f64.powf(-50.));
    ///
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let h_key: LweSecretKey32 = default_engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let h_plaintext_vector: PlaintextVector32 =
    ///     default_engine.create_plaintext_vector_from(&input)?;
    /// let mut h_ciphertext_vector: LweCiphertextVector32 =
    ///     default_engine.encrypt_lwe_ciphertext_vector(&h_key, &h_plaintext_vector, noise)?;
    /// let lwe_ciphertext_count = h_ciphertext_vector.lwe_ciphertext_count();
    /// let lwe_size = h_ciphertext_vector.lwe_dimension().to_lwe_size();
    ///
    /// let h_raw_ciphertext_vector: Vec<u32> =
    ///     default_engine.consume_retrieve_lwe_ciphertext_vector(h_ciphertext_vector)?;
    /// let mut h_view_ciphertext_vector: LweCiphertextVectorView32 = default_engine
    ///     .create_lwe_ciphertext_vector_from(h_raw_ciphertext_vector.as_slice(), lwe_size)?;
    ///
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_ciphertext_vector: CudaLweCiphertextVector32 =
    ///     cuda_engine.convert_lwe_ciphertext_vector(&h_view_ciphertext_vector)?;
    ///
    /// assert_eq!(d_ciphertext_vector.lwe_dimension(), lwe_dimension);
    /// assert_eq!(
    ///     d_ciphertext_vector.lwe_ciphertext_count(),
    ///     lwe_ciphertext_count
    /// );
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_lwe_ciphertext_vector(
        &mut self,
        input: &LweCiphertextVectorView32,
    ) -> Result<CudaLweCiphertextVector32, LweCiphertextVectorConversionError<CudaError>> {
        let number_of_gpus = number_of_active_gpus(
            self.get_number_of_gpus(),
            CiphertextCount(input.lwe_ciphertext_count().0),
        );
        for gpu_index in 0..number_of_gpus.0 {
            let stream = &self.streams[gpu_index];
            let samples = compute_number_of_samples_on_gpu(
                self.get_number_of_gpus(),
                CiphertextCount(input.lwe_ciphertext_count().0),
                GpuIndex(gpu_index),
            );
            let data_per_gpu = samples.0 * input.lwe_dimension().to_lwe_size().0;
            let size = data_per_gpu as u64 * std::mem::size_of::<u32>() as u64;
            stream.check_device_memory(size)?;
        }
        Ok(unsafe { self.convert_lwe_ciphertext_vector_unchecked(input) })
    }

    unsafe fn convert_lwe_ciphertext_vector_unchecked(
        &mut self,
        input: &LweCiphertextVectorView32,
    ) -> CudaLweCiphertextVector32 {
        let vecs = copy_lwe_ciphertext_vector_from_cpu_to_gpu::<u32, _>(
            self.get_cuda_streams(),
            &input.0,
            self.get_number_of_gpus(),
        );
        CudaLweCiphertextVector32(CudaLweList::<u32> {
            d_vecs: vecs,
            lwe_ciphertext_count: input.lwe_ciphertext_count(),
            lwe_dimension: input.lwe_dimension(),
        })
    }
}

/// # Description
/// Convert an LWE ciphertext vector view with 64 bits of precision from CPU to GPU.
///
/// The input ciphertext vector view is split over GPUs, so that each GPU contains
/// the total amount of ciphertexts divided by the number of GPUs on the machine.
/// The last GPU takes the remainder of the division if there is any.
impl LweCiphertextVectorConversionEngine<LweCiphertextVectorView64<'_>, CudaLweCiphertextVector64>
    for CudaEngine
{
    /// # Example
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(6);
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = vec![3_u64 << 50; 3];
    /// let noise = Variance(2_f64.powf(-50.));
    ///
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let h_key: LweSecretKey64 = default_engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let h_plaintext_vector: PlaintextVector64 =
    ///     default_engine.create_plaintext_vector_from(&input)?;
    /// let mut h_ciphertext_vector: LweCiphertextVector64 =
    ///     default_engine.encrypt_lwe_ciphertext_vector(&h_key, &h_plaintext_vector, noise)?;
    /// let lwe_ciphertext_count = h_ciphertext_vector.lwe_ciphertext_count();
    /// let lwe_size = h_ciphertext_vector.lwe_dimension().to_lwe_size();
    ///
    /// let h_raw_ciphertext_vector: Vec<u64> =
    ///     default_engine.consume_retrieve_lwe_ciphertext_vector(h_ciphertext_vector)?;
    /// let mut h_view_ciphertext_vector: LweCiphertextVectorView64 = default_engine
    ///     .create_lwe_ciphertext_vector_from(h_raw_ciphertext_vector.as_slice(), lwe_size)?;
    ///
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_ciphertext_vector: CudaLweCiphertextVector64 =
    ///     cuda_engine.convert_lwe_ciphertext_vector(&h_view_ciphertext_vector)?;
    ///
    /// assert_eq!(d_ciphertext_vector.lwe_dimension(), lwe_dimension);
    /// assert_eq!(
    ///     d_ciphertext_vector.lwe_ciphertext_count(),
    ///     lwe_ciphertext_count
    /// );
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_lwe_ciphertext_vector(
        &mut self,
        input: &LweCiphertextVectorView64,
    ) -> Result<CudaLweCiphertextVector64, LweCiphertextVectorConversionError<CudaError>> {
        let number_of_gpus = number_of_active_gpus(
            self.get_number_of_gpus(),
            CiphertextCount(input.lwe_ciphertext_count().0),
        );
        for gpu_index in 0..number_of_gpus.0 {
            let stream = &self.streams[gpu_index];
            let samples = compute_number_of_samples_on_gpu(
                self.get_number_of_gpus(),
                CiphertextCount(input.lwe_ciphertext_count().0),
                GpuIndex(gpu_index),
            );
            let data_per_gpu = samples.0 * input.lwe_dimension().to_lwe_size().0;
            let size = data_per_gpu as u64 * std::mem::size_of::<u64>() as u64;
            stream.check_device_memory(size)?;
        }
        Ok(unsafe { self.convert_lwe_ciphertext_vector_unchecked(input) })
    }

    unsafe fn convert_lwe_ciphertext_vector_unchecked(
        &mut self,
        input: &LweCiphertextVectorView64,
    ) -> CudaLweCiphertextVector64 {
        let vecs = copy_lwe_ciphertext_vector_from_cpu_to_gpu::<u64, _>(
            self.get_cuda_streams(),
            &input.0,
            self.get_number_of_gpus(),
        );
        CudaLweCiphertextVector64(CudaLweList::<u64> {
            d_vecs: vecs,
            lwe_ciphertext_count: input.lwe_ciphertext_count(),
            lwe_dimension: input.lwe_dimension(),
        })
    }
}
/// # Description
/// Convert a mutable LWE ciphertext vector view with 32 bits of precision from CPU to GPU.
///
/// The input ciphertext vector view is split over GPUs, so that each GPU contains
/// the total amount of ciphertexts divided by the number of GPUs on the machine.
/// The last GPU takes the remainder of the division if there is any.
impl
    LweCiphertextVectorConversionEngine<LweCiphertextVectorMutView32<'_>, CudaLweCiphertextVector32>
    for CudaEngine
{
    /// # Example
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(6);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u32 << 20; 3];
    /// let noise = Variance(2_f64.powf(-50.));
    ///
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let h_key: LweSecretKey32 = default_engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let h_plaintext_vector: PlaintextVector32 =
    ///     default_engine.create_plaintext_vector_from(&input)?;
    /// let mut h_ciphertext_vector: LweCiphertextVector32 =
    ///     default_engine.encrypt_lwe_ciphertext_vector(&h_key, &h_plaintext_vector, noise)?;
    /// let lwe_ciphertext_count = h_ciphertext_vector.lwe_ciphertext_count();
    /// let lwe_size = h_ciphertext_vector.lwe_dimension().to_lwe_size();
    ///
    /// let mut h_raw_ciphertext_vector: Vec<u32> =
    ///     default_engine.consume_retrieve_lwe_ciphertext_vector(h_ciphertext_vector)?;
    /// let mut h_view_ciphertext_vector: LweCiphertextVectorMutView32 = default_engine
    ///     .create_lwe_ciphertext_vector_from(h_raw_ciphertext_vector.as_mut_slice(), lwe_size)?;
    ///
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_ciphertext_vector: CudaLweCiphertextVector32 =
    ///     cuda_engine.convert_lwe_ciphertext_vector(&h_view_ciphertext_vector)?;
    ///
    /// assert_eq!(d_ciphertext_vector.lwe_dimension(), lwe_dimension);
    /// assert_eq!(
    ///     d_ciphertext_vector.lwe_ciphertext_count(),
    ///     lwe_ciphertext_count
    /// );
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_lwe_ciphertext_vector(
        &mut self,
        input: &LweCiphertextVectorMutView32,
    ) -> Result<CudaLweCiphertextVector32, LweCiphertextVectorConversionError<CudaError>> {
        let number_of_gpus = number_of_active_gpus(
            self.get_number_of_gpus(),
            CiphertextCount(input.lwe_ciphertext_count().0),
        );
        for gpu_index in 0..number_of_gpus.0 {
            let stream = &self.streams[gpu_index];
            let samples = compute_number_of_samples_on_gpu(
                self.get_number_of_gpus(),
                CiphertextCount(input.lwe_ciphertext_count().0),
                GpuIndex(gpu_index),
            );
            let data_per_gpu = samples.0 * input.lwe_dimension().to_lwe_size().0;
            let size = data_per_gpu as u64 * std::mem::size_of::<u32>() as u64;
            stream.check_device_memory(size)?;
        }
        Ok(unsafe { self.convert_lwe_ciphertext_vector_unchecked(input) })
    }

    unsafe fn convert_lwe_ciphertext_vector_unchecked(
        &mut self,
        input: &LweCiphertextVectorMutView32,
    ) -> CudaLweCiphertextVector32 {
        let vecs = copy_lwe_ciphertext_vector_from_cpu_to_gpu::<u32, _>(
            self.get_cuda_streams(),
            &input.0,
            self.get_number_of_gpus(),
        );
        CudaLweCiphertextVector32(CudaLweList::<u32> {
            d_vecs: vecs,
            lwe_ciphertext_count: input.lwe_ciphertext_count(),
            lwe_dimension: input.lwe_dimension(),
        })
    }
}

/// # Description
/// Convert a mutable LWE ciphertext vector view with 64 bits of precision from CPU to GPU.
///
/// The input ciphertext vector view is split over GPUs, so that each GPU contains
/// the total amount of ciphertexts divided by the number of GPUs on the machine.
/// The last GPU takes the remainder of the division if there is any.
impl
    LweCiphertextVectorConversionEngine<LweCiphertextVectorMutView64<'_>, CudaLweCiphertextVector64>
    for CudaEngine
{
    /// # Example
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(6);
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = vec![3_u64 << 50; 3];
    /// let noise = Variance(2_f64.powf(-50.));
    ///
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let h_key: LweSecretKey64 = default_engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let h_plaintext_vector: PlaintextVector64 =
    ///     default_engine.create_plaintext_vector_from(&input)?;
    /// let mut h_ciphertext_vector: LweCiphertextVector64 =
    ///     default_engine.encrypt_lwe_ciphertext_vector(&h_key, &h_plaintext_vector, noise)?;
    /// let lwe_ciphertext_count = h_ciphertext_vector.lwe_ciphertext_count();
    /// let lwe_size = h_ciphertext_vector.lwe_dimension().to_lwe_size();
    ///
    /// let mut h_raw_ciphertext_vector: Vec<u64> =
    ///     default_engine.consume_retrieve_lwe_ciphertext_vector(h_ciphertext_vector)?;
    /// let mut h_view_ciphertext_vector: LweCiphertextVectorMutView64 = default_engine
    ///     .create_lwe_ciphertext_vector_from(h_raw_ciphertext_vector.as_mut_slice(), lwe_size)?;
    ///
    /// let mut cuda_engine = CudaEngine::new(())?;
    /// let d_ciphertext_vector: CudaLweCiphertextVector64 =
    ///     cuda_engine.convert_lwe_ciphertext_vector(&h_view_ciphertext_vector)?;
    ///
    /// assert_eq!(d_ciphertext_vector.lwe_dimension(), lwe_dimension);
    /// assert_eq!(
    ///     d_ciphertext_vector.lwe_ciphertext_count(),
    ///     lwe_ciphertext_count
    /// );
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_lwe_ciphertext_vector(
        &mut self,
        input: &LweCiphertextVectorMutView64,
    ) -> Result<CudaLweCiphertextVector64, LweCiphertextVectorConversionError<CudaError>> {
        let number_of_gpus = number_of_active_gpus(
            self.get_number_of_gpus(),
            CiphertextCount(input.lwe_ciphertext_count().0),
        );
        for gpu_index in 0..number_of_gpus.0 {
            let stream = &self.streams[gpu_index];
            let samples = compute_number_of_samples_on_gpu(
                self.get_number_of_gpus(),
                CiphertextCount(input.lwe_ciphertext_count().0),
                GpuIndex(gpu_index),
            );
            let data_per_gpu = samples.0 * input.lwe_dimension().to_lwe_size().0;
            let size = data_per_gpu as u64 * std::mem::size_of::<u64>() as u64;
            stream.check_device_memory(size)?;
        }
        Ok(unsafe { self.convert_lwe_ciphertext_vector_unchecked(input) })
    }

    unsafe fn convert_lwe_ciphertext_vector_unchecked(
        &mut self,
        input: &LweCiphertextVectorMutView64,
    ) -> CudaLweCiphertextVector64 {
        let vecs = copy_lwe_ciphertext_vector_from_cpu_to_gpu::<u64, _>(
            self.get_cuda_streams(),
            &input.0,
            self.get_number_of_gpus(),
        );
        CudaLweCiphertextVector64(CudaLweList::<u64> {
            d_vecs: vecs,
            lwe_ciphertext_count: input.lwe_ciphertext_count(),
            lwe_dimension: input.lwe_dimension(),
        })
    }
}
