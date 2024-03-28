use crate::core_crypto::entities::LweCiphertextList;
use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::vec::CudaVec;
use crate::core_crypto::gpu::CudaStream;
use crate::core_crypto::prelude::{ContiguousEntityContainerMut, LweCiphertextCount};
use crate::integer::block_decomposition::{BlockDecomposer, DecomposableInto};
use crate::integer::gpu::ciphertext::info::{CudaBlockInfo, CudaRadixCiphertextInfo};
use crate::integer::gpu::ciphertext::{
    CudaIntegerRadixCiphertext, CudaRadixCiphertext, CudaUnsignedRadixCiphertext,
};
use crate::integer::gpu::server_key::CudaBootstrappingKey;
use crate::integer::gpu::CudaServerKey;
use crate::shortint::ciphertext::{Degree, NoiseLevel};
use crate::shortint::PBSOrder;

mod add;
mod bitwise_op;
mod cmux;
mod comparison;
mod mul;
mod neg;
mod scalar_add;
mod scalar_bitwise_op;
mod scalar_comparison;
mod scalar_mul;
mod scalar_shift;
mod scalar_sub;
mod shift;
mod sub;

mod scalar_rotate;

mod rotate;

#[cfg(test)]
mod tests_signed;
#[cfg(test)]
mod tests_unsigned;

impl CudaServerKey {
    /// Create a trivial ciphertext filled with zeros on the GPU.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::{CudaDevice, CudaStream};
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::integer::{gen_keys_radix, RadixCiphertext};
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let gpu_index = 0;
    /// let device = CudaDevice::new(gpu_index);
    /// let mut stream = CudaStream::new_unchecked(device);
    ///
    /// let num_blocks = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks, &mut stream);
    ///
    /// let d_ctxt: CudaUnsignedRadixCiphertext =
    ///     sks.create_trivial_zero_radix(num_blocks, &mut stream);
    /// let ctxt = d_ctxt.to_radix_ciphertext(&mut stream);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ctxt);
    /// assert_eq!(0, dec);
    /// ```
    pub fn create_trivial_zero_radix<T: CudaIntegerRadixCiphertext>(
        &self,
        num_blocks: usize,
        stream: &CudaStream,
    ) -> T {
        T::from(self.create_trivial_radix(0, num_blocks, stream).ciphertext)
    }

    /// Create a trivial ciphertext on the GPU
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::{CudaDevice, CudaStream};
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::integer::{gen_keys_radix, RadixCiphertext};
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let gpu_index = 0;
    /// let device = CudaDevice::new(gpu_index);
    /// let mut stream = CudaStream::new_unchecked(device);
    ///
    /// let num_blocks = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks, &mut stream);
    ///
    /// let d_ctxt = sks.create_trivial_radix(212u64, num_blocks, &mut stream);
    /// let ctxt = d_ctxt.to_radix_ciphertext(&mut stream);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ctxt);
    /// assert_eq!(212, dec);
    /// ```
    pub fn create_trivial_radix<Scalar>(
        &self,
        scalar: Scalar,
        num_blocks: usize,
        stream: &CudaStream,
    ) -> CudaUnsignedRadixCiphertext
    where
        Scalar: DecomposableInto<u64>,
    {
        let lwe_size = match self.pbs_order {
            PBSOrder::KeyswitchBootstrap => self.key_switching_key.input_key_lwe_size(),
            PBSOrder::BootstrapKeyswitch => self.key_switching_key.output_key_lwe_size(),
        };

        let delta = (1_u64 << 63) / (self.message_modulus.0 * self.carry_modulus.0) as u64;

        let decomposer = BlockDecomposer::new(scalar, self.message_modulus.0.ilog2())
            .iter_as::<u64>()
            .chain(std::iter::repeat(0))
            .take(num_blocks);
        let mut cpu_lwe_list = LweCiphertextList::new(
            0,
            lwe_size,
            LweCiphertextCount(num_blocks),
            self.ciphertext_modulus,
        );
        let mut info = Vec::with_capacity(num_blocks);
        for (block_value, mut lwe) in decomposer.zip(cpu_lwe_list.iter_mut()) {
            *lwe.get_mut_body().data = block_value * delta;
            info.push(CudaBlockInfo {
                degree: Degree::new(block_value as usize),
                message_modulus: self.message_modulus,
                carry_modulus: self.carry_modulus,
                pbs_order: self.pbs_order,
                noise_level: NoiseLevel::ZERO,
            });
        }

        let d_blocks = CudaLweCiphertextList::from_lwe_ciphertext_list(&cpu_lwe_list, stream);

        CudaUnsignedRadixCiphertext {
            ciphertext: CudaRadixCiphertext {
                d_blocks,
                info: CudaRadixCiphertextInfo { blocks: info },
            },
        }
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronized
    pub(crate) unsafe fn propagate_single_carry_assign_async<T>(
        &self,
        ct: &mut T,
        stream: &CudaStream,
    ) where
        T: CudaIntegerRadixCiphertext,
    {
        let ciphertext = ct.as_mut();
        let num_blocks = ciphertext.d_blocks.lwe_ciphertext_count().0 as u32;
        match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => {
                stream.propagate_single_carry_classic_assign_async(
                    &mut ciphertext.d_blocks.0.d_vec,
                    &d_bsk.d_vec,
                    &self.key_switching_key.d_vec,
                    d_bsk.input_lwe_dimension(),
                    d_bsk.glwe_dimension(),
                    d_bsk.polynomial_size(),
                    self.key_switching_key.decomposition_level_count(),
                    self.key_switching_key.decomposition_base_log(),
                    d_bsk.decomp_level_count(),
                    d_bsk.decomp_base_log(),
                    num_blocks,
                    ciphertext.info.blocks.first().unwrap().message_modulus,
                    ciphertext.info.blocks.first().unwrap().carry_modulus,
                );
            }
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                stream.propagate_single_carry_multibit_assign_async(
                    &mut ciphertext.d_blocks.0.d_vec,
                    &d_multibit_bsk.d_vec,
                    &self.key_switching_key.d_vec,
                    d_multibit_bsk.input_lwe_dimension(),
                    d_multibit_bsk.glwe_dimension(),
                    d_multibit_bsk.polynomial_size(),
                    self.key_switching_key.decomposition_level_count(),
                    self.key_switching_key.decomposition_base_log(),
                    d_multibit_bsk.decomp_level_count(),
                    d_multibit_bsk.decomp_base_log(),
                    d_multibit_bsk.grouping_factor,
                    num_blocks,
                    ciphertext.info.blocks.first().unwrap().message_modulus,
                    ciphertext.info.blocks.first().unwrap().carry_modulus,
                );
            }
        };
        ciphertext.info.blocks.iter_mut().for_each(|b| {
            b.degree = Degree::new(b.message_modulus.0 - 1);
            b.noise_level = NoiseLevel::NOMINAL;
        });
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronized
    pub(crate) unsafe fn full_propagate_assign_async<T: CudaIntegerRadixCiphertext>(
        &self,
        ct: &mut T,
        stream: &CudaStream,
    ) {
        let ciphertext = ct.as_mut();
        let num_blocks = ciphertext.d_blocks.lwe_ciphertext_count().0 as u32;
        match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => {
                stream.full_propagate_classic_assign_async(
                    &mut ciphertext.d_blocks.0.d_vec,
                    &d_bsk.d_vec,
                    &self.key_switching_key.d_vec,
                    d_bsk.input_lwe_dimension(),
                    d_bsk.glwe_dimension(),
                    d_bsk.polynomial_size(),
                    self.key_switching_key.decomposition_level_count(),
                    self.key_switching_key.decomposition_base_log(),
                    d_bsk.decomp_level_count(),
                    d_bsk.decomp_base_log(),
                    num_blocks,
                    ciphertext.info.blocks.first().unwrap().message_modulus,
                    ciphertext.info.blocks.first().unwrap().carry_modulus,
                );
            }
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                stream.full_propagate_multibit_assign_async(
                    &mut ciphertext.d_blocks.0.d_vec,
                    &d_multibit_bsk.d_vec,
                    &self.key_switching_key.d_vec,
                    d_multibit_bsk.input_lwe_dimension(),
                    d_multibit_bsk.glwe_dimension(),
                    d_multibit_bsk.polynomial_size(),
                    self.key_switching_key.decomposition_level_count(),
                    self.key_switching_key.decomposition_base_log(),
                    d_multibit_bsk.decomp_level_count(),
                    d_multibit_bsk.decomp_base_log(),
                    d_multibit_bsk.grouping_factor,
                    num_blocks,
                    ciphertext.info.blocks.first().unwrap().message_modulus,
                    ciphertext.info.blocks.first().unwrap().carry_modulus,
                );
            }
        };
        ciphertext
            .info
            .blocks
            .iter_mut()
            .for_each(|b| b.degree = Degree::new(b.message_modulus.0 - 1));
    }

    /// Prepend trivial zero LSB blocks to an existing [`CudaUnsignedRadixCiphertext`] or
    /// [`CudaSignedRadixCiphertext`](`crate::integer::gpu::ciphertext::CudaSignedRadixCiphertext`)
    /// and returns the result as a new ciphertext on GPU. This can be useful for casting
    /// operations.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::core_crypto::gpu::{CudaDevice, CudaStream};
    /// use tfhe::integer::gpu::ciphertext::CudaRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::integer::IntegerCiphertext;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let num_blocks = 4;
    ///
    /// let gpu_index = 0;
    /// let device = CudaDevice::new(gpu_index);
    /// let mut stream = CudaStream::new_unchecked(device);
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks, &mut stream);
    ///
    /// let mut d_ct1 = sks.create_trivial_radix(7u64, num_blocks, &mut stream);
    /// let ct1 = d_ct1.to_radix_ciphertext(&mut stream);
    /// assert_eq!(ct1.blocks().len(), 4);
    ///
    /// let added_blocks = 2;
    /// let d_ct_res = sks.extend_radix_with_trivial_zero_blocks_lsb(&d_ct1, added_blocks, &mut stream);
    /// let ct_res = d_ct_res.to_radix_ciphertext(&mut stream);
    /// assert_eq!(ct_res.blocks().len(), 6);
    ///
    /// // Decrypt
    /// let res: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(
    ///     7 * (PARAM_MESSAGE_2_CARRY_2_KS_PBS.message_modulus.0 as u64).pow(added_blocks as u32),
    ///     res
    /// );
    /// ```
    pub fn extend_radix_with_trivial_zero_blocks_lsb<T: CudaIntegerRadixCiphertext>(
        &self,
        ct: &T,
        num_blocks: usize,
        stream: &CudaStream,
    ) -> T {
        let new_num_blocks = ct.as_ref().d_blocks.lwe_ciphertext_count().0 + num_blocks;
        let ciphertext_modulus = ct.as_ref().d_blocks.ciphertext_modulus();
        let lwe_size = ct.as_ref().d_blocks.lwe_dimension().to_lwe_size();
        let shift = num_blocks * lwe_size.0;

        let mut extended_ct_vec =
            unsafe { CudaVec::new_async(new_num_blocks * lwe_size.0, stream) };
        unsafe {
            extended_ct_vec.memset_async(0u64, stream);
            extended_ct_vec.copy_self_range_gpu_to_gpu_async(
                shift..,
                &ct.as_ref().d_blocks.0.d_vec,
                stream,
            );
        }
        stream.synchronize();
        let extended_ct_list = CudaLweCiphertextList::from_cuda_vec(
            extended_ct_vec,
            LweCiphertextCount(new_num_blocks),
            ciphertext_modulus,
        );

        let extended_ct_info = ct
            .as_ref()
            .info
            .after_extend_radix_with_trivial_zero_blocks_lsb(num_blocks);
        T::from(CudaRadixCiphertext::new(extended_ct_list, extended_ct_info))
    }

    /// Append trivial zero MSB blocks to an existing [`CudaUnsignedRadixCiphertext`] or
    /// [`CudaSignedRadixCiphertext`](`crate::integer::gpu::ciphertext::CudaSignedRadixCiphertext`)
    /// and returns the result as a new ciphertext on GPU. This can be useful for casting
    /// operations.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::core_crypto::gpu::{CudaDevice, CudaStream};
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::integer::IntegerCiphertext;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let num_blocks = 4;
    ///
    /// let gpu_index = 0;
    /// let device = CudaDevice::new(gpu_index);
    /// let mut stream = CudaStream::new_unchecked(device);
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks, &mut stream);
    ///
    /// let mut d_ct1 = sks.create_trivial_radix(7u64, num_blocks, &mut stream);
    /// let ct1 = d_ct1.to_radix_ciphertext(&mut stream);
    /// assert_eq!(ct1.blocks().len(), 4);
    ///
    /// let d_ct_res = sks.extend_radix_with_trivial_zero_blocks_msb(&d_ct1, 2, &mut stream);
    /// let ct_res = d_ct_res.to_radix_ciphertext(&mut stream);
    /// assert_eq!(ct_res.blocks().len(), 6);
    ///
    /// // Decrypt
    /// let res: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(7, res);
    /// ```
    pub fn extend_radix_with_trivial_zero_blocks_msb<T: CudaIntegerRadixCiphertext>(
        &self,
        ct: &T,
        num_blocks: usize,
        stream: &CudaStream,
    ) -> T {
        let new_num_blocks = ct.as_ref().d_blocks.lwe_ciphertext_count().0 + num_blocks;
        let ciphertext_modulus = ct.as_ref().d_blocks.ciphertext_modulus();
        let lwe_size = ct.as_ref().d_blocks.lwe_dimension().to_lwe_size();

        let mut extended_ct_vec =
            unsafe { CudaVec::new_async(new_num_blocks * lwe_size.0, stream) };
        unsafe {
            extended_ct_vec.memset_async(0u64, stream);
            extended_ct_vec.copy_from_gpu_async(&ct.as_ref().d_blocks.0.d_vec, stream);
        }
        stream.synchronize();
        let extended_ct_list = CudaLweCiphertextList::from_cuda_vec(
            extended_ct_vec,
            LweCiphertextCount(new_num_blocks),
            ciphertext_modulus,
        );

        let extended_ct_info = ct
            .as_ref()
            .info
            .after_extend_radix_with_trivial_zero_blocks_msb(num_blocks);
        T::from(CudaRadixCiphertext::new(extended_ct_list, extended_ct_info))
    }

    /// Remove LSB blocks from an existing [`CudaUnsignedRadixCiphertext`] or
    /// [`CudaSignedRadixCiphertext`](`crate::integer::gpu::ciphertext::CudaSignedRadixCiphertext`)
    /// and returns the result as a new ciphertext on GPU. This can be useful for casting
    /// operations.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::core_crypto::gpu::{CudaDevice, CudaStream};
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::integer::IntegerCiphertext;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let num_blocks = 4;
    ///
    /// let gpu_index = 0;
    /// let device = CudaDevice::new(gpu_index);
    /// let mut stream = CudaStream::new_unchecked(device);
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks, &mut stream);
    ///
    /// let mut d_ct1 = sks.create_trivial_radix(119u64, num_blocks, &mut stream);
    /// let ct1 = d_ct1.to_radix_ciphertext(&mut stream);
    /// assert_eq!(ct1.blocks().len(), 4);
    ///
    /// let d_ct_res = sks.trim_radix_blocks_lsb(&d_ct1, 2, &mut stream);
    /// let ct_res = d_ct_res.to_radix_ciphertext(&mut stream);
    /// assert_eq!(ct_res.blocks().len(), 2);
    ///
    /// // Decrypt
    /// let res: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(7, res);
    /// ```
    pub fn trim_radix_blocks_lsb<T: CudaIntegerRadixCiphertext>(
        &self,
        ct: &T,
        num_blocks: usize,
        stream: &CudaStream,
    ) -> T {
        let new_num_blocks = ct.as_ref().d_blocks.lwe_ciphertext_count().0 - num_blocks;
        let ciphertext_modulus = ct.as_ref().d_blocks.ciphertext_modulus();
        let lwe_size = ct.as_ref().d_blocks.lwe_dimension().to_lwe_size();
        let shift = num_blocks * lwe_size.0;

        let mut trimmed_ct_vec = unsafe { CudaVec::new_async(new_num_blocks * lwe_size.0, stream) };
        unsafe {
            trimmed_ct_vec.copy_src_range_gpu_to_gpu_async(
                shift..,
                &ct.as_ref().d_blocks.0.d_vec,
                stream,
            );
        }
        stream.synchronize();
        let trimmed_ct_list = CudaLweCiphertextList::from_cuda_vec(
            trimmed_ct_vec,
            LweCiphertextCount(new_num_blocks),
            ciphertext_modulus,
        );

        let trimmed_ct_info = ct.as_ref().info.after_trim_radix_blocks_lsb(num_blocks);
        T::from(CudaRadixCiphertext::new(trimmed_ct_list, trimmed_ct_info))
    }

    /// Remove MSB blocks from an existing [`CudaUnsignedRadixCiphertext`] or
    /// [`CudaSignedRadixCiphertext`](`crate::integer::gpu::ciphertext::CudaSignedRadixCiphertext`)
    /// and returns the result as a new ciphertext on GPU. This can be useful for casting
    /// operations.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::core_crypto::gpu::{CudaDevice, CudaStream};
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::integer::IntegerCiphertext;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let num_blocks = 4;
    ///
    /// let gpu_index = 0;
    /// let device = CudaDevice::new(gpu_index);
    /// let mut stream = CudaStream::new_unchecked(device);
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks, &mut stream);
    ///
    /// let mut d_ct1 = sks.create_trivial_radix(119u64, num_blocks, &mut stream);
    /// let ct1 = d_ct1.to_radix_ciphertext(&mut stream);
    /// assert_eq!(ct1.blocks().len(), 4);
    ///
    /// let d_ct_res = sks.trim_radix_blocks_msb(&d_ct1, 2, &mut stream);
    /// let ct_res = d_ct_res.to_radix_ciphertext(&mut stream);
    /// assert_eq!(ct_res.blocks().len(), 2);
    ///
    /// // Decrypt
    /// let res: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(7, res);
    /// ```
    pub fn trim_radix_blocks_msb<T: CudaIntegerRadixCiphertext>(
        &self,
        ct: &T,
        num_blocks: usize,
        stream: &CudaStream,
    ) -> T {
        let new_num_blocks = ct.as_ref().d_blocks.lwe_ciphertext_count().0 - num_blocks;
        let ciphertext_modulus = ct.as_ref().d_blocks.ciphertext_modulus();
        let lwe_size = ct.as_ref().d_blocks.lwe_dimension().to_lwe_size();
        let shift = new_num_blocks * lwe_size.0;

        let mut trimmed_ct_vec = unsafe { CudaVec::new_async(new_num_blocks * lwe_size.0, stream) };
        unsafe {
            trimmed_ct_vec.copy_src_range_gpu_to_gpu_async(
                0..shift,
                &ct.as_ref().d_blocks.0.d_vec,
                stream,
            );
        }
        stream.synchronize();
        let trimmed_ct_list = CudaLweCiphertextList::from_cuda_vec(
            trimmed_ct_vec,
            LweCiphertextCount(new_num_blocks),
            ciphertext_modulus,
        );

        let trimmed_ct_info = ct.as_ref().info.after_trim_radix_blocks_msb(num_blocks);
        T::from(CudaRadixCiphertext::new(trimmed_ct_list, trimmed_ct_info))
    }

    /// Cast a [`CudaUnsignedRadixCiphertext`] to a [`CudaUnsignedRadixCiphertext`]
    /// with a possibly different number of blocks
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::core_crypto::gpu::{CudaDevice, CudaStream};
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::integer::IntegerCiphertext;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let num_blocks = 4;
    /// let gpu_index = 0;
    /// let device = CudaDevice::new(gpu_index);
    /// let mut stream = CudaStream::new_unchecked(device);
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks, &mut stream);
    ///
    /// let msg = 2u8;
    ///
    /// let mut d_ct1 = sks.create_trivial_radix(msg, num_blocks, &mut stream);
    /// let ct1 = d_ct1.to_radix_ciphertext(&mut stream);
    /// assert_eq!(ct1.blocks().len(), 4);
    ///
    /// let d_ct_res = sks.cast_to_unsigned(d_ct1, 8, &mut stream);
    /// let ct_res = d_ct_res.to_radix_ciphertext(&mut stream);
    /// assert_eq!(ct_res.blocks().len(), 8);
    ///
    /// // Decrypt
    /// let res: u16 = cks.decrypt(&ct_res);
    /// assert_eq!(msg as u16, res);
    /// ```
    pub fn cast_to_unsigned(
        &self,
        mut source: CudaUnsignedRadixCiphertext,
        target_num_blocks: usize,
        stream: &CudaStream,
    ) -> CudaUnsignedRadixCiphertext {
        if !source.block_carries_are_empty() {
            unsafe {
                self.full_propagate_assign_async(&mut source, stream);
            }
            stream.synchronize();
        }
        let current_num_blocks = source.ciphertext.info.blocks.len();
        // Casting from unsigned to unsigned, this is just about trimming/extending with zeros
        if target_num_blocks > current_num_blocks {
            let num_blocks_to_add = target_num_blocks - current_num_blocks;
            self.extend_radix_with_trivial_zero_blocks_msb(&source, num_blocks_to_add, stream)
        } else {
            let num_blocks_to_remove = current_num_blocks - target_num_blocks;
            self.trim_radix_blocks_msb(&source, num_blocks_to_remove, stream)
        }
    }
}
