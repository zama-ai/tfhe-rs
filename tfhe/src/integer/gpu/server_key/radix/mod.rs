use crate::core_crypto::entities::{GlweCiphertext, LweCiphertextList};
use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::vec::CudaVec;
use crate::core_crypto::gpu::{CudaLweList, CudaStreams};
use crate::core_crypto::prelude::{
    ContiguousEntityContainerMut, LweBskGroupingFactor, LweCiphertextCount,
};
use crate::integer::block_decomposition::{BlockDecomposer, DecomposableInto};
use crate::integer::gpu::ciphertext::info::{CudaBlockInfo, CudaRadixCiphertextInfo};
use crate::integer::gpu::ciphertext::{
    CudaIntegerRadixCiphertext, CudaRadixCiphertext, CudaSignedRadixCiphertext,
    CudaUnsignedRadixCiphertext,
};
use crate::integer::gpu::server_key::CudaBootstrappingKey;
use crate::integer::gpu::{
    apply_univariate_lut_kb_async, full_propagate_assign_async,
    propagate_single_carry_assign_async, CudaServerKey, PBSType,
};
use crate::shortint::ciphertext::{Degree, NoiseLevel};
use crate::shortint::engine::fill_accumulator;
use crate::shortint::server_key::LookupTableOwned;
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

mod div_mod;
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
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::integer::{gen_keys_radix, RadixCiphertext};
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let gpu_index = 0;
    /// let mut stream = CudaStreams::new_single_gpu(gpu_index);
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
        stream: &CudaStreams,
    ) -> T {
        self.create_trivial_radix(0, num_blocks, stream)
    }

    /// Create a trivial ciphertext on the GPU
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::integer::{gen_keys_radix, RadixCiphertext};
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let gpu_index = 0;
    /// let mut stream = CudaStreams::new_single_gpu(gpu_index);
    ///
    /// let num_blocks = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks, &mut stream);
    ///
    /// let d_ctxt: CudaUnsignedRadixCiphertext =
    ///     sks.create_trivial_radix(212u64, num_blocks, &mut stream);
    /// let ctxt = d_ctxt.to_radix_ciphertext(&mut stream);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ctxt);
    /// assert_eq!(212, dec);
    /// ```
    pub fn create_trivial_radix<Scalar, T>(
        &self,
        scalar: Scalar,
        num_blocks: usize,
        stream: &CudaStreams,
    ) -> T
    where
        T: CudaIntegerRadixCiphertext,
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

        T::from(CudaRadixCiphertext {
            d_blocks,
            info: CudaRadixCiphertextInfo { blocks: info },
        })
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronized
    pub(crate) unsafe fn propagate_single_carry_assign_async<T>(
        &self,
        ct: &mut T,
        streams: &CudaStreams,
    ) -> T
    where
        T: CudaIntegerRadixCiphertext,
    {
        let mut carry_out: T = self.create_trivial_zero_radix(1, streams);
        let ciphertext = ct.as_mut();
        let num_blocks = ciphertext.d_blocks.lwe_ciphertext_count().0 as u32;
        match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => {
                propagate_single_carry_assign_async(
                    streams,
                    &mut ciphertext.d_blocks.0.d_vec,
                    &mut carry_out.as_mut().d_blocks.0.d_vec,
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
                    PBSType::Classical,
                    LweBskGroupingFactor(0),
                );
            }
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                propagate_single_carry_assign_async(
                    streams,
                    &mut ciphertext.d_blocks.0.d_vec,
                    &mut carry_out.as_mut().d_blocks.0.d_vec,
                    &d_multibit_bsk.d_vec,
                    &self.key_switching_key.d_vec,
                    d_multibit_bsk.input_lwe_dimension(),
                    d_multibit_bsk.glwe_dimension(),
                    d_multibit_bsk.polynomial_size(),
                    self.key_switching_key.decomposition_level_count(),
                    self.key_switching_key.decomposition_base_log(),
                    d_multibit_bsk.decomp_level_count(),
                    d_multibit_bsk.decomp_base_log(),
                    num_blocks,
                    ciphertext.info.blocks.first().unwrap().message_modulus,
                    ciphertext.info.blocks.first().unwrap().carry_modulus,
                    PBSType::MultiBit,
                    d_multibit_bsk.grouping_factor,
                );
            }
        };
        ciphertext.info.blocks.iter_mut().for_each(|b| {
            b.degree = Degree::new(b.message_modulus.0 - 1);
            b.noise_level = NoiseLevel::NOMINAL;
        });
        carry_out.as_mut().info.blocks.iter_mut().for_each(|b| {
            b.degree = Degree::new(1);
            b.noise_level = NoiseLevel::NOMINAL;
        });
        carry_out
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronized
    pub(crate) unsafe fn full_propagate_assign_async<T: CudaIntegerRadixCiphertext>(
        &self,
        ct: &mut T,
        stream: &CudaStreams,
    ) {
        let ciphertext = ct.as_mut();
        let num_blocks = ciphertext.d_blocks.lwe_ciphertext_count().0 as u32;
        match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => {
                full_propagate_assign_async(
                    stream,
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
                    PBSType::Classical,
                    LweBskGroupingFactor(0),
                );
            }
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                full_propagate_assign_async(
                    stream,
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
                    num_blocks,
                    ciphertext.info.blocks.first().unwrap().message_modulus,
                    ciphertext.info.blocks.first().unwrap().carry_modulus,
                    PBSType::MultiBit,
                    d_multibit_bsk.grouping_factor,
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
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::integer::gpu::ciphertext::{CudaRadixCiphertext, CudaUnsignedRadixCiphertext};
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::integer::IntegerCiphertext;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let num_blocks = 4;
    ///
    /// let gpu_index = 0;
    /// let mut stream = CudaStreams::new_single_gpu(gpu_index);
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks, &mut stream);
    ///
    /// let mut d_ct1: CudaUnsignedRadixCiphertext =
    ///     sks.create_trivial_radix(7u64, num_blocks, &mut stream);
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
        stream: &CudaStreams,
    ) -> T {
        let new_num_blocks = ct.as_ref().d_blocks.lwe_ciphertext_count().0 + num_blocks;
        let ciphertext_modulus = ct.as_ref().d_blocks.ciphertext_modulus();
        let lwe_size = ct.as_ref().d_blocks.lwe_dimension().to_lwe_size();
        let shift = num_blocks * lwe_size.0;

        let mut extended_ct_vec =
            unsafe { CudaVec::new_async(new_num_blocks * lwe_size.0, stream, 0) };
        unsafe {
            extended_ct_vec.memset_async(0u64, stream, 0);
            extended_ct_vec.copy_self_range_gpu_to_gpu_async(
                shift..,
                &ct.as_ref().d_blocks.0.d_vec,
                stream,
                0,
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
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::integer::IntegerCiphertext;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let num_blocks = 4;
    ///
    /// let gpu_index = 0;
    /// let mut stream = CudaStreams::new_single_gpu(gpu_index);
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks, &mut stream);
    ///
    /// let mut d_ct1: CudaUnsignedRadixCiphertext =
    ///     sks.create_trivial_radix(7u64, num_blocks, &mut stream);
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
        stream: &CudaStreams,
    ) -> T {
        let new_num_blocks = ct.as_ref().d_blocks.lwe_ciphertext_count().0 + num_blocks;
        let ciphertext_modulus = ct.as_ref().d_blocks.ciphertext_modulus();
        let lwe_size = ct.as_ref().d_blocks.lwe_dimension().to_lwe_size();

        let mut extended_ct_vec =
            unsafe { CudaVec::new_async(new_num_blocks * lwe_size.0, stream, 0) };
        unsafe {
            extended_ct_vec.memset_async(0u64, stream, 0);
            extended_ct_vec.copy_from_gpu_async(&ct.as_ref().d_blocks.0.d_vec, stream, 0);
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
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::integer::IntegerCiphertext;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let num_blocks = 4;
    ///
    /// let gpu_index = 0;
    /// let mut stream = CudaStreams::new_single_gpu(gpu_index);
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks, &mut stream);
    ///
    /// let mut d_ct1: CudaUnsignedRadixCiphertext =
    ///     sks.create_trivial_radix(119u64, num_blocks, &mut stream);
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
        stream: &CudaStreams,
    ) -> T {
        let new_num_blocks = ct.as_ref().d_blocks.lwe_ciphertext_count().0 - num_blocks;
        let ciphertext_modulus = ct.as_ref().d_blocks.ciphertext_modulus();
        let lwe_size = ct.as_ref().d_blocks.lwe_dimension().to_lwe_size();
        let shift = num_blocks * lwe_size.0;

        let mut trimmed_ct_vec =
            unsafe { CudaVec::new_async(new_num_blocks * lwe_size.0, stream, 0) };
        unsafe {
            trimmed_ct_vec.copy_src_range_gpu_to_gpu_async(
                shift..,
                &ct.as_ref().d_blocks.0.d_vec,
                stream,
                0,
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
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::integer::IntegerCiphertext;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let num_blocks = 4;
    ///
    /// let gpu_index = 0;
    /// let mut stream = CudaStreams::new_single_gpu(gpu_index);
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks, &mut stream);
    ///
    /// let mut d_ct1: CudaUnsignedRadixCiphertext =
    ///     sks.create_trivial_radix(119u64, num_blocks, &mut stream);
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
        stream: &CudaStreams,
    ) -> T {
        let new_num_blocks = ct.as_ref().d_blocks.lwe_ciphertext_count().0 - num_blocks;
        let ciphertext_modulus = ct.as_ref().d_blocks.ciphertext_modulus();
        let lwe_size = ct.as_ref().d_blocks.lwe_dimension().to_lwe_size();
        let shift = new_num_blocks * lwe_size.0;

        let mut trimmed_ct_vec =
            unsafe { CudaVec::new_async(new_num_blocks * lwe_size.0, stream, 0) };
        unsafe {
            trimmed_ct_vec.copy_src_range_gpu_to_gpu_async(
                0..shift,
                &ct.as_ref().d_blocks.0.d_vec,
                stream,
                0,
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

    pub(crate) fn generate_lookup_table<F>(&self, f: F) -> LookupTableOwned
    where
        F: Fn(u64) -> u64,
    {
        let (glwe_size, polynomial_size) = match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => {
                (d_bsk.glwe_dimension.to_glwe_size(), d_bsk.polynomial_size)
            }
            CudaBootstrappingKey::MultiBit(d_bsk) => {
                (d_bsk.glwe_dimension.to_glwe_size(), d_bsk.polynomial_size)
            }
        };
        let mut acc = GlweCiphertext::new(0, glwe_size, polynomial_size, self.ciphertext_modulus);
        let max_value = fill_accumulator(
            &mut acc,
            polynomial_size,
            glwe_size,
            self.message_modulus,
            self.carry_modulus,
            f,
        );

        LookupTableOwned {
            acc,
            degree: Degree::new(max_value as usize),
        }
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronized
    pub(crate) fn extend_radix_with_sign_msb<T: CudaIntegerRadixCiphertext>(
        &self,
        ct: &T,
        num_blocks: usize,
        stream: &CudaStreams,
    ) -> T {
        let message_modulus = self.message_modulus.0 as u64;
        let num_bits_in_block = message_modulus.ilog2();
        let padding_block_creator_lut = self.generate_lookup_table(|x| {
            let x = x % message_modulus;
            let x_sign_bit = x >> (num_bits_in_block - 1) & 1;
            // padding is a message full of 1 if sign bit is one
            // else padding is a zero message
            (message_modulus - 1) * x_sign_bit
        });
        let num_ct_blocks = ct.as_ref().d_blocks.lwe_ciphertext_count().0;
        let new_num_ct_blocks = num_ct_blocks + num_blocks;

        assert_ne!(num_ct_blocks, 0, "Cannot sign extend an empty ciphertext");
        let lwe_size = ct.as_ref().d_blocks.0.lwe_dimension.to_lwe_size().0;

        // Allocate the necessary amount of memory
        let mut output_radix = CudaVec::new(new_num_ct_blocks * lwe_size, stream, 0);
        unsafe {
            output_radix.copy_from_gpu_async(&ct.as_ref().d_blocks.0.d_vec, stream, 0);
            // Get the last ct block
            let last_block = ct
                .as_ref()
                .d_blocks
                .0
                .d_vec
                .as_slice(lwe_size * (num_ct_blocks - 1).., 0)
                .unwrap();
            let mut output_slice = output_radix
                .as_mut_slice(lwe_size * num_ct_blocks..lwe_size * new_num_ct_blocks, 0)
                .unwrap();
            let (padding_block, new_blocks) = output_slice.split_at_mut(lwe_size, 0);
            let mut padding_block = padding_block.unwrap();
            let mut new_blocks = new_blocks.unwrap();

            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    apply_univariate_lut_kb_async(
                        stream,
                        &mut padding_block,
                        &last_block,
                        padding_block_creator_lut.acc.as_ref(),
                        &d_bsk.d_vec,
                        &self.key_switching_key.d_vec,
                        self.key_switching_key
                            .output_key_lwe_size()
                            .to_lwe_dimension(),
                        d_bsk.glwe_dimension,
                        d_bsk.polynomial_size,
                        self.key_switching_key.decomposition_level_count(),
                        self.key_switching_key.decomposition_base_log(),
                        d_bsk.decomp_level_count,
                        d_bsk.decomp_base_log,
                        1u32,
                        self.message_modulus,
                        self.carry_modulus,
                        PBSType::Classical,
                        LweBskGroupingFactor(0),
                    );
                }
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                    apply_univariate_lut_kb_async(
                        stream,
                        &mut padding_block,
                        &last_block,
                        padding_block_creator_lut.acc.as_ref(),
                        &d_multibit_bsk.d_vec,
                        &self.key_switching_key.d_vec,
                        self.key_switching_key
                            .output_key_lwe_size()
                            .to_lwe_dimension(),
                        d_multibit_bsk.glwe_dimension,
                        d_multibit_bsk.polynomial_size,
                        self.key_switching_key.decomposition_level_count(),
                        self.key_switching_key.decomposition_base_log(),
                        d_multibit_bsk.decomp_level_count,
                        d_multibit_bsk.decomp_base_log,
                        1u32,
                        self.message_modulus,
                        self.carry_modulus,
                        PBSType::MultiBit,
                        d_multibit_bsk.grouping_factor,
                    );
                }
            }
            for i in 0..num_blocks - 1 {
                let mut output_block = new_blocks
                    .get_mut(lwe_size * i..lwe_size * (i + 1), 0)
                    .unwrap();
                output_block.copy_from_gpu_async(&padding_block, stream, 0);
            }
        }
        stream.synchronize();
        let output_lwe_list = CudaLweCiphertextList(CudaLweList {
            d_vec: output_radix,
            lwe_ciphertext_count: LweCiphertextCount(new_num_ct_blocks),
            lwe_dimension: ct.as_ref().d_blocks.0.lwe_dimension,
            ciphertext_modulus: self.ciphertext_modulus,
        });
        let mut info = ct.as_ref().info.clone();
        let last_block_info = ct.as_ref().info.blocks.last().unwrap();
        for _ in num_ct_blocks..new_num_ct_blocks {
            info.blocks.push(*last_block_info);
        }

        T::from(CudaRadixCiphertext::new(output_lwe_list, info))
    }
    /// Cast a [`CudaUnsignedRadixCiphertext`] or a [`CudaSignedRadixCiphertext`]
    /// to a [`CudaUnsignedRadixCiphertext`] with a possibly different number of blocks
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::integer::gpu::ciphertext::CudaSignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::integer::IntegerCiphertext;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let num_blocks = 4;
    /// let gpu_index = 0;
    /// let mut stream = CudaStreams::new_single_gpu(gpu_index);
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks, &mut stream);
    ///
    /// let msg = -2i8;
    ///
    /// let mut ct1 = cks.encrypt_signed(msg);
    /// assert_eq!(ct1.blocks().len(), 4);
    /// let d_ct1 = CudaSignedRadixCiphertext::from_signed_radix_ciphertext(&ct1, &stream);
    ///
    /// let d_ct_res = sks.cast_to_unsigned(d_ct1, 8, &mut stream);
    /// let ct_res = d_ct_res.to_radix_ciphertext(&mut stream);
    /// assert_eq!(ct_res.blocks().len(), 8);
    ///
    /// // Decrypt
    /// let res: u16 = cks.decrypt(&ct_res);
    /// assert_eq!(msg as u16, res);
    /// ```
    pub fn cast_to_unsigned<T>(
        &self,
        mut source: T,
        target_num_blocks: usize,
        stream: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext
    where
        T: CudaIntegerRadixCiphertext,
    {
        if !source.block_carries_are_empty() {
            unsafe {
                self.full_propagate_assign_async(&mut source, stream);
            }
            stream.synchronize();
        }
        let current_num_blocks = source.as_ref().info.blocks.len();
        if T::IS_SIGNED {
            // Casting from signed to unsigned
            // We have to trim or sign extend first
            if target_num_blocks > current_num_blocks {
                let num_blocks_to_add = target_num_blocks - current_num_blocks;
                let signed_res: T =
                    self.extend_radix_with_sign_msb(&source, num_blocks_to_add, stream);
                <CudaUnsignedRadixCiphertext as CudaIntegerRadixCiphertext>::from(
                    signed_res.into_inner(),
                )
            } else {
                let num_blocks_to_remove = current_num_blocks - target_num_blocks;
                let signed_res = self.trim_radix_blocks_msb(&source, num_blocks_to_remove, stream);
                <CudaUnsignedRadixCiphertext as CudaIntegerRadixCiphertext>::from(
                    signed_res.into_inner(),
                )
            }
        } else {
            // Casting from unsigned to unsigned, this is just about trimming/extending with zeros
            if target_num_blocks > current_num_blocks {
                let num_blocks_to_add = target_num_blocks - current_num_blocks;
                let unsigned_res = self.extend_radix_with_trivial_zero_blocks_msb(
                    &source,
                    num_blocks_to_add,
                    stream,
                );
                <CudaUnsignedRadixCiphertext as CudaIntegerRadixCiphertext>::from(
                    unsigned_res.into_inner(),
                )
            } else {
                let num_blocks_to_remove = current_num_blocks - target_num_blocks;
                let unsigned_res =
                    self.trim_radix_blocks_msb(&source, num_blocks_to_remove, stream);
                <CudaUnsignedRadixCiphertext as CudaIntegerRadixCiphertext>::from(
                    unsigned_res.into_inner(),
                )
            }
        }
    }

    /// Cast a `CudaUnsignedRadixCiphertext` or `CudaSignedRadixCiphertext` to a
    /// `CudaSignedRadixCiphertext` with a possibly different number of blocks
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::integer::{gen_keys_radix, IntegerCiphertext};
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let num_blocks = 8;
    /// let gpu_index = 0;
    /// let mut stream = CudaStreams::new_single_gpu(gpu_index);
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks, &mut stream);
    ///
    /// let msg = u16::MAX;
    ///
    /// let mut ct1 = cks.encrypt(msg);
    /// assert_eq!(ct1.blocks().len(), num_blocks);
    /// let d_ct1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct1, &stream);
    ///
    /// let d_ct_res = sks.cast_to_signed(d_ct1, 4, &mut stream);
    /// let ct_res = d_ct_res.to_signed_radix_ciphertext(&mut stream);
    /// assert_eq!(ct_res.blocks().len(), 4);
    ///
    /// // Decrypt
    /// let res: i8 = cks.decrypt_signed(&ct_res);
    /// assert_eq!(msg as i8, res);
    /// ```
    pub fn cast_to_signed<T>(
        &self,
        mut source: T,
        target_num_blocks: usize,
        stream: &CudaStreams,
    ) -> CudaSignedRadixCiphertext
    where
        T: CudaIntegerRadixCiphertext,
    {
        if !source.block_carries_are_empty() {
            unsafe {
                self.full_propagate_assign_async(&mut source, stream);
            }
            stream.synchronize();
        }

        let current_num_blocks = source.as_ref().info.blocks.len();

        if T::IS_SIGNED {
            // Casting from signed to signed
            if target_num_blocks > current_num_blocks {
                let num_blocks_to_add = target_num_blocks - current_num_blocks;
                let unsigned_res: T =
                    self.extend_radix_with_sign_msb(&source, num_blocks_to_add, stream);
                <CudaSignedRadixCiphertext as CudaIntegerRadixCiphertext>::from(
                    unsigned_res.into_inner(),
                )
            } else {
                let num_blocks_to_remove = current_num_blocks - target_num_blocks;
                let unsigned_res =
                    self.trim_radix_blocks_msb(&source, num_blocks_to_remove, stream);
                <CudaSignedRadixCiphertext as CudaIntegerRadixCiphertext>::from(
                    unsigned_res.into_inner(),
                )
            }
        } else {
            // casting from unsigned to signed
            if target_num_blocks > current_num_blocks {
                let num_blocks_to_add = target_num_blocks - current_num_blocks;
                let signed_res = self.extend_radix_with_trivial_zero_blocks_msb(
                    &source,
                    num_blocks_to_add,
                    stream,
                );
                <CudaSignedRadixCiphertext as CudaIntegerRadixCiphertext>::from(
                    signed_res.into_inner(),
                )
            } else {
                let num_blocks_to_remove = current_num_blocks - target_num_blocks;
                let signed_res = self.trim_radix_blocks_msb(&source, num_blocks_to_remove, stream);
                <CudaSignedRadixCiphertext as CudaIntegerRadixCiphertext>::from(
                    signed_res.into_inner(),
                )
            }
        }
    }
}
