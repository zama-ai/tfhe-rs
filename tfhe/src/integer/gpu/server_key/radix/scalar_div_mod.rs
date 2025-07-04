use crate::core_crypto::gpu::vec::CudaVec;
use crate::core_crypto::gpu::CudaStreams;
use crate::core_crypto::prelude::{LweBskGroupingFactor, Numeric};
use crate::integer::block_decomposition::{BlockDecomposer, DecomposableInto};
use crate::integer::gpu::ciphertext::{
    CudaIntegerRadixCiphertext, CudaSignedRadixCiphertext, CudaUnsignedRadixCiphertext,
};
use crate::integer::gpu::server_key::CudaBootstrappingKey;
use crate::integer::gpu::{
    get_full_propagate_assign_size_on_gpu, get_scalar_div_integer_radix_kb_size_on_gpu,
    get_scalar_div_rem_integer_radix_kb_size_on_gpu,
    get_signed_scalar_div_integer_radix_kb_size_on_gpu, get_signed_scalar_div_rem_size_on_gpu,
    prepare_default_scalar_divisor, unchecked_signed_scalar_div_integer_radix_kb_assign_async,
    unchecked_signed_scalar_div_rem_integer_radix_kb_assign_async,
    unchecked_unsigned_scalar_div_integer_radix_kb_assign_async,
    unchecked_unsigned_scalar_div_rem_integer_radix_kb_assign_async, CudaServerKey, PBSType,
};
use crate::integer::server_key::radix_parallel::scalar_div_mod::{
    choose_multiplier, SignedReciprocable,
};
use crate::integer::server_key::radix_parallel::OutputFlag;
use crate::integer::server_key::{MiniUnsignedInteger, Reciprocable, ScalarMultiplier};
use crate::prelude::{CastFrom, CastInto};
use itertools::Itertools;

impl CudaServerKey {
    /// Computes homomorphically a division between a ciphertext and a scalar.
    ///
    /// This function computes the operation without checking if it exceeds the capacity of the
    /// ciphertext.
    ///
    /// The result is returned as a new ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(
    ///     PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    ///     size,
    ///     &streams,
    /// );
    ///
    /// let msg = 30;
    /// let scalar = 3;
    ///
    /// let ct = cks.encrypt(msg);
    /// let d_ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, &streams);
    ///
    /// // Compute homomorphically a scalar division:
    /// let d_ct_res = sks.unchecked_scalar_div(&d_ct, scalar, &streams);
    /// let ct_res = d_ct_res.to_radix_ciphertext(&streams);
    ///
    /// let clear: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg / scalar, clear);
    /// ```
    pub fn unchecked_scalar_div<Scalar>(
        &self,
        numerator: &CudaUnsignedRadixCiphertext,
        divisor: Scalar,
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext
    where
        Scalar: Reciprocable,
    {
        let res = unsafe { self.unchecked_scalar_div_async(numerator, divisor, streams) };
        streams.synchronize();
        res
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronized
    pub unsafe fn unchecked_scalar_div_async<Scalar>(
        &self,
        numerator: &CudaUnsignedRadixCiphertext,
        divisor: Scalar,
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext
    where
        Scalar: Reciprocable,
    {
        assert_ne!(divisor, Scalar::ZERO, "attempt to divide by 0");

        let numerator_bits = numerator
            .as_ref()
            .info
            .blocks
            .first()
            .unwrap()
            .message_modulus
            .0
            .ilog2()
            * numerator.as_ref().d_blocks.lwe_ciphertext_count().0 as u32;

        let msg_bits = self.message_modulus.0.ilog2() as usize;
        let num_blocks = numerator.as_ref().d_blocks.lwe_ciphertext_count().0 as u32;
        let lwe_dimension = self
            .key_switching_key
            .output_key_lwe_size()
            .to_lwe_dimension();
        let mut quotient = unsafe { numerator.duplicate_async(streams) };

        assert!(
            Scalar::BITS >= numerator_bits as usize,
            "The scalar divisor type must have a number of bits that is \
    >= to the number of bits encrypted in the ciphertext: \n\
    encrypted bits: {numerator_bits}, scalar bits: {}
    ",
            Scalar::BITS
        );

        let mut scalar_properties = prepare_default_scalar_divisor();

        let is_divisor_power_of_two = MiniUnsignedInteger::is_power_of_two(divisor);
        scalar_properties.is_divisor_pow2 = is_divisor_power_of_two;
        scalar_properties.is_abs_divisor_one = divisor == Scalar::ONE;
        scalar_properties.ilog2_divisor = MiniUnsignedInteger::ilog2(divisor);
        scalar_properties.is_divisor_wider_than_numerator =
            MiniUnsignedInteger::ceil_ilog2(divisor) > numerator_bits;

        let mut chosen_multiplier = choose_multiplier(divisor, numerator_bits, numerator_bits);

        let shift_pre = if chosen_multiplier.multiplier
            >= (Scalar::DoublePrecision::ONE << numerator_bits as usize)
            && crate::integer::server_key::radix_parallel::scalar_div_mod::is_even(divisor)
            && !is_divisor_power_of_two
            && !scalar_properties.is_divisor_wider_than_numerator
        {
            let divisor_dp = Scalar::DoublePrecision::cast_from(divisor);
            let two_pow_e = divisor_dp
                & ((Scalar::DoublePrecision::ONE << numerator_bits as usize) - divisor_dp);
            let e = MiniUnsignedInteger::ilog2(two_pow_e);
            let divisor_odd_dp = divisor_dp / two_pow_e;

            assert!(numerator_bits > e && e <= Scalar::BITS as u32);
            let divisor_odd: Scalar = divisor_odd_dp.cast_into();
            chosen_multiplier = choose_multiplier(divisor_odd, numerator_bits - e, numerator_bits);
            e as u64
        } else {
            0
        };

        scalar_properties.shift_pre = shift_pre;
        scalar_properties.shift_post = chosen_multiplier.shift_post;
        scalar_properties.is_multiplier_geq_numerator_magnitude = chosen_multiplier.multiplier
            >= (Scalar::DoublePrecision::ONE << numerator_bits as usize);
        scalar_properties.multiplier_length = chosen_multiplier.l;

        let rhs = if scalar_properties.is_multiplier_geq_numerator_magnitude {
            chosen_multiplier.multiplier - (Scalar::DoublePrecision::ONE << numerator_bits as usize)
        } else {
            chosen_multiplier.multiplier
        };

        let decomposed_multiplier = BlockDecomposer::with_early_stop_at_zero(rhs, 1)
            .iter_as::<u64>()
            .collect::<Vec<_>>();

        scalar_properties.decomposed_multiplier = decomposed_multiplier.as_ptr();
        scalar_properties.num_scalars_multiplier = decomposed_multiplier.len() as u32;

        let decomposer = BlockDecomposer::with_early_stop_at_zero(rhs, 1).iter_as::<u8>();

        let mut multiplier_has_at_least_one_set = vec![0u64; msg_bits];
        for (i, bit) in decomposer.collect_vec().iter().copied().enumerate() {
            if bit == 1 {
                multiplier_has_at_least_one_set[i % msg_bits] = 1;
            }
        }
        scalar_properties.multiplier_has_at_least_one_set =
            multiplier_has_at_least_one_set.as_ptr();

        let num_ciphertext_bits = 2 * msg_bits * num_blocks as usize;
        scalar_properties.active_bits_multiplier = decomposed_multiplier
            .iter()
            .take(num_ciphertext_bits)
            .filter(|&&rhs_bit| rhs_bit == 1u64)
            .count() as u32;

        scalar_properties.is_multiplier_pow2 = MiniUnsignedInteger::is_power_of_two(rhs);
        scalar_properties.is_abs_multiplier_one = rhs == Scalar::DoublePrecision::ONE;
        scalar_properties.is_multiplier_zero = rhs == Scalar::DoublePrecision::ZERO;

        scalar_properties.ilog2_multiplier =
            if scalar_properties.is_multiplier_pow2 && !scalar_properties.is_abs_multiplier_one {
                MiniUnsignedInteger::ilog2(rhs)
            } else {
                0u32
            };

        match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => {
                unchecked_unsigned_scalar_div_integer_radix_kb_assign_async(
                    streams,
                    quotient.as_mut(),
                    &scalar_properties,
                    &self.key_switching_key.d_vec,
                    &d_bsk.d_vec,
                    self.message_modulus,
                    self.carry_modulus,
                    d_bsk.glwe_dimension,
                    d_bsk.polynomial_size,
                    lwe_dimension,
                    self.key_switching_key.decomposition_level_count(),
                    self.key_switching_key.decomposition_base_log(),
                    d_bsk.decomp_level_count,
                    d_bsk.decomp_base_log,
                    LweBskGroupingFactor(0),
                    num_blocks,
                    PBSType::Classical,
                    d_bsk.d_ms_noise_reduction_key.as_ref(),
                );
            }
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                unchecked_unsigned_scalar_div_integer_radix_kb_assign_async(
                    streams,
                    quotient.as_mut(),
                    &scalar_properties,
                    &self.key_switching_key.d_vec,
                    &d_multibit_bsk.d_vec,
                    self.message_modulus,
                    self.carry_modulus,
                    d_multibit_bsk.glwe_dimension,
                    d_multibit_bsk.polynomial_size,
                    lwe_dimension,
                    self.key_switching_key.decomposition_level_count(),
                    self.key_switching_key.decomposition_base_log(),
                    d_multibit_bsk.decomp_level_count,
                    d_multibit_bsk.decomp_base_log,
                    d_multibit_bsk.grouping_factor,
                    num_blocks,
                    PBSType::MultiBit,
                    None,
                );
            }
        }

        quotient
    }

    /// Computes homomorphically a division between a ciphertext and a scalar.
    ///
    /// This function computes the operation without checking if it exceeds the capacity of the
    /// ciphertext.
    ///
    /// The result is returned as a new ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, size, &streams);
    ///
    /// let msg = 30;
    /// let scalar = 3;
    ///
    /// let ct = cks.encrypt(msg);
    /// let d_ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, &streams);
    ///
    /// // Compute homomorphically a scalar multiplication:
    /// let d_ct_res = sks.scalar_div(&d_ct, scalar, &streams);
    /// let ct_res = d_ct_res.to_radix_ciphertext(&streams);
    ///
    /// let clear: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg / scalar, clear);
    /// ```
    pub fn scalar_div<Scalar>(
        &self,
        numerator: &CudaUnsignedRadixCiphertext,
        divisor: Scalar,
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext
    where
        Scalar: Reciprocable,
    {
        let res = unsafe { self.unchecked_scalar_div_async(numerator, divisor, streams) };
        streams.synchronize();
        res
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronized
    pub unsafe fn scalar_div_async<Scalar>(
        &self,
        numerator: &CudaUnsignedRadixCiphertext,
        divisor: Scalar,
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext
    where
        Scalar: Reciprocable,
    {
        let mut tmp_numerator;
        let numerator = if numerator.block_carries_are_empty() {
            numerator
        } else {
            tmp_numerator = numerator.duplicate_async(streams);
            self.full_propagate_assign_async(&mut tmp_numerator, streams);
            &tmp_numerator
        };

        self.unchecked_scalar_div_async(numerator, divisor, streams)
    }

    pub fn unchecked_scalar_div_rem<Scalar>(
        &self,
        numerator: &CudaUnsignedRadixCiphertext,
        divisor: Scalar,
        streams: &CudaStreams,
    ) -> (CudaUnsignedRadixCiphertext, CudaUnsignedRadixCiphertext)
    where
        Scalar: Reciprocable + ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
    {
        let (quotient, remainder) =
            unsafe { self.unchecked_scalar_div_rem_async(numerator, divisor, streams) };

        streams.synchronize();

        (quotient, remainder)
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronized
    pub unsafe fn unchecked_scalar_div_rem_async<Scalar>(
        &self,
        numerator: &CudaUnsignedRadixCiphertext,
        divisor: Scalar,
        streams: &CudaStreams,
    ) -> (CudaUnsignedRadixCiphertext, CudaUnsignedRadixCiphertext)
    where
        Scalar: Reciprocable + ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
    {
        assert_ne!(divisor, Scalar::ZERO, "attempt to divide by 0");

        let num_blocks = numerator.as_ref().d_blocks.lwe_ciphertext_count().0 as u32;
        let msg_bits = self.message_modulus.0.ilog2() as usize;

        let mut quotient: CudaUnsignedRadixCiphertext =
            unsafe { numerator.duplicate_async(streams) };
        let mut remainder: CudaUnsignedRadixCiphertext =
            unsafe { self.create_trivial_zero_radix_async(num_blocks as usize, streams) };

        let numerator_bits = numerator
            .as_ref()
            .info
            .blocks
            .first()
            .unwrap()
            .message_modulus
            .0
            .ilog2()
            * num_blocks;

        assert!(
            Scalar::BITS >= numerator_bits as usize,
            "The scalar divisor type must have a number of bits that is \
        >= to the number of bits encrypted in the ciphertext: \n\
        encrypted bits: {numerator_bits}, scalar bits: {}",
            Scalar::BITS
        );

        let mut scalar_properties = prepare_default_scalar_divisor();

        let is_divisor_power_of_two = MiniUnsignedInteger::is_power_of_two(divisor);
        let log2_divisor_exceeds_threshold =
            MiniUnsignedInteger::ceil_ilog2(divisor) > numerator_bits;
        let mut chosen_multiplier = choose_multiplier(divisor, numerator_bits, numerator_bits);

        let shift_pre = if chosen_multiplier.multiplier
            >= (Scalar::DoublePrecision::ONE << numerator_bits as usize)
            && crate::integer::server_key::radix_parallel::scalar_div_mod::is_even(divisor)
            && !is_divisor_power_of_two
            && !log2_divisor_exceeds_threshold
        {
            let divisor_dp = Scalar::DoublePrecision::cast_from(divisor);
            let two_pow_e = divisor_dp
                & ((Scalar::DoublePrecision::ONE << numerator_bits as usize) - divisor_dp);
            let e = MiniUnsignedInteger::ilog2(two_pow_e);
            let divisor_odd_dp = divisor_dp / two_pow_e;

            assert!(numerator_bits > e && e <= Scalar::BITS as u32);
            let divisor_odd: Scalar = divisor_odd_dp.cast_into();
            chosen_multiplier = choose_multiplier(divisor_odd, numerator_bits - e, numerator_bits);
            e as u64
        } else {
            0
        };

        scalar_properties.shift_pre = shift_pre;
        scalar_properties.shift_post = chosen_multiplier.shift_post;
        scalar_properties.is_multiplier_geq_numerator_magnitude = chosen_multiplier.multiplier
            >= (Scalar::DoublePrecision::ONE << numerator_bits as usize);
        scalar_properties.multiplier_length = chosen_multiplier.l;

        let rhs = if scalar_properties.is_multiplier_geq_numerator_magnitude {
            chosen_multiplier.multiplier - (Scalar::DoublePrecision::ONE << numerator_bits as usize)
        } else {
            chosen_multiplier.multiplier
        };

        let decomposed_multiplier = BlockDecomposer::with_early_stop_at_zero(rhs, 1)
            .iter_as::<u64>()
            .collect::<Vec<_>>();
        let decomposer_rhs = BlockDecomposer::with_early_stop_at_zero(rhs, 1).iter_as::<u8>();
        let mut multiplier_has_at_least_one_set = vec![0u64; msg_bits];
        for (i, bit) in decomposer_rhs.collect_vec().iter().copied().enumerate() {
            if bit == 1 {
                multiplier_has_at_least_one_set[i % msg_bits] = 1;
            }
        }

        scalar_properties.decomposed_multiplier = decomposed_multiplier.as_ptr();
        scalar_properties.multiplier_has_at_least_one_set =
            multiplier_has_at_least_one_set.as_ptr();
        scalar_properties.num_scalars_multiplier = decomposed_multiplier.len() as u32;
        scalar_properties.active_bits_multiplier = decomposed_multiplier
            .iter()
            .take(2 * msg_bits * num_blocks as usize)
            .filter(|&&bit| bit == 1u64)
            .count() as u32;
        scalar_properties.is_multiplier_pow2 = MiniUnsignedInteger::is_power_of_two(rhs);
        scalar_properties.is_abs_multiplier_one = rhs == Scalar::DoublePrecision::ONE;
        scalar_properties.is_multiplier_zero = rhs == Scalar::DoublePrecision::ZERO;
        scalar_properties.ilog2_multiplier = if scalar_properties.is_multiplier_pow2 {
            MiniUnsignedInteger::ilog2(rhs)
        } else {
            0
        };

        let decomposed_divisor = BlockDecomposer::with_early_stop_at_zero(divisor, 1)
            .iter_as::<u64>()
            .collect::<Vec<_>>();
        let decomposer_divisor =
            BlockDecomposer::with_early_stop_at_zero(divisor, 1).iter_as::<u8>();
        let mut divisor_has_at_least_one_set = vec![0u64; msg_bits];
        for (i, bit) in decomposer_divisor.collect_vec().iter().copied().enumerate() {
            if bit == 1 {
                divisor_has_at_least_one_set[i % msg_bits] = 1;
            }
        }

        scalar_properties.decomposed_divisor = decomposed_divisor.as_ptr();
        scalar_properties.divisor_has_at_least_one_set = divisor_has_at_least_one_set.as_ptr();
        scalar_properties.num_scalars_divisor = decomposed_divisor.len() as u32;
        scalar_properties.active_bits_divisor = decomposed_divisor
            .iter()
            .take(msg_bits * num_blocks as usize)
            .filter(|&&bit| bit == 1u64)
            .count() as u32;
        scalar_properties.is_divisor_pow2 = is_divisor_power_of_two;
        scalar_properties.is_abs_divisor_one = divisor == Scalar::ONE;
        scalar_properties.ilog2_divisor = MiniUnsignedInteger::ilog2(divisor);
        scalar_properties.is_divisor_wider_than_numerator = log2_divisor_exceeds_threshold;

        let h_clear_blocks = BlockDecomposer::with_early_stop_at_zero(
            divisor - Scalar::ONE,
            self.message_modulus.0.ilog2(),
        )
        .iter_as::<u8>()
        .map(|x| x as u64)
        .collect::<Vec<_>>();
        let clear_blocks = CudaVec::from_cpu_async(&h_clear_blocks, streams, 0);

        unsafe {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    unchecked_unsigned_scalar_div_rem_integer_radix_kb_assign_async(
                        streams,
                        quotient.as_mut(),
                        remainder.as_mut(),
                        &scalar_properties,
                        &self.key_switching_key.d_vec,
                        &d_bsk.d_vec,
                        self.message_modulus,
                        self.carry_modulus,
                        d_bsk.glwe_dimension,
                        d_bsk.polynomial_size,
                        d_bsk.input_lwe_dimension,
                        self.key_switching_key.decomposition_level_count(),
                        self.key_switching_key.decomposition_base_log(),
                        d_bsk.decomp_level_count,
                        d_bsk.decomp_base_log,
                        LweBskGroupingFactor(0),
                        num_blocks,
                        &h_clear_blocks,
                        &clear_blocks,
                        PBSType::Classical,
                        d_bsk.d_ms_noise_reduction_key.as_ref(),
                    );
                }
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                    unchecked_unsigned_scalar_div_rem_integer_radix_kb_assign_async(
                        streams,
                        quotient.as_mut(),
                        remainder.as_mut(),
                        &scalar_properties,
                        &self.key_switching_key.d_vec,
                        &d_multibit_bsk.d_vec,
                        self.message_modulus,
                        self.carry_modulus,
                        d_multibit_bsk.glwe_dimension,
                        d_multibit_bsk.polynomial_size,
                        d_multibit_bsk.input_lwe_dimension,
                        self.key_switching_key.decomposition_level_count(),
                        self.key_switching_key.decomposition_base_log(),
                        d_multibit_bsk.decomp_level_count,
                        d_multibit_bsk.decomp_base_log,
                        d_multibit_bsk.grouping_factor,
                        num_blocks,
                        &h_clear_blocks,
                        &clear_blocks,
                        PBSType::MultiBit,
                        None,
                    );
                }
            }
        }

        (quotient, remainder)
    }

    /// Computes homomorphically a division between a ciphertext and a scalar and returns the
    /// encrypted quotient and remainder.
    ///
    /// This function computes the operation without checking if it exceeds the capacity of the
    /// ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, size, &streams);
    ///
    /// let msg = 30;
    /// let scalar = 3;
    ///
    /// let ct = cks.encrypt(msg);
    /// let d_ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, &streams);
    ///
    /// // Compute homomorphically a scalar multiplication:
    /// let (d_ct_q, d_ct_r) = sks.scalar_div_rem(&d_ct, scalar, &streams);
    /// let ct_q = d_ct_q.to_radix_ciphertext(&streams);
    /// let ct_r = d_ct_r.to_radix_ciphertext(&streams);
    ///
    /// let quotient: u64 = cks.decrypt(&ct_q);
    /// let remainder: u64 = cks.decrypt(&ct_r);
    /// assert_eq!(msg / scalar, quotient);
    /// assert_eq!(msg % scalar, remainder);
    /// ```
    pub fn scalar_div_rem<Scalar>(
        &self,
        numerator: &CudaUnsignedRadixCiphertext,
        divisor: Scalar,
        streams: &CudaStreams,
    ) -> (CudaUnsignedRadixCiphertext, CudaUnsignedRadixCiphertext)
    where
        Scalar: Reciprocable + ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
    {
        let res = unsafe { self.unchecked_scalar_div_rem_async(numerator, divisor, streams) };
        streams.synchronize();
        res
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronized
    pub unsafe fn scalar_div_rem_async<Scalar>(
        &self,
        numerator: &CudaUnsignedRadixCiphertext,
        divisor: Scalar,
        streams: &CudaStreams,
    ) -> (CudaUnsignedRadixCiphertext, CudaUnsignedRadixCiphertext)
    where
        Scalar: Reciprocable + ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
    {
        let mut tmp_numerator;
        let numerator = if numerator.block_carries_are_empty() {
            numerator
        } else {
            tmp_numerator = numerator.duplicate_async(streams);
            self.full_propagate_assign_async(&mut tmp_numerator, streams);
            &tmp_numerator
        };

        self.unchecked_scalar_div_rem_async(numerator, divisor, streams)
    }

    pub fn unchecked_scalar_rem<Scalar>(
        &self,
        numerator: &CudaUnsignedRadixCiphertext,
        divisor: Scalar,
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext
    where
        Scalar: Reciprocable + ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
    {
        let res = unsafe { self.unchecked_scalar_rem_async(numerator, divisor, streams) };
        streams.synchronize();
        res
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronized
    pub unsafe fn unchecked_scalar_rem_async<Scalar>(
        &self,
        numerator: &CudaUnsignedRadixCiphertext,
        divisor: Scalar,
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext
    where
        Scalar: Reciprocable + ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
    {
        self.unchecked_scalar_div_rem_async(numerator, divisor, streams)
            .1
    }

    /// Computes homomorphically a division between a ciphertext and a scalar.
    ///
    /// The result is returned as a new ciphertext that encrypts the remainder.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, size, &streams);
    ///
    /// let msg = 30;
    /// let scalar = 3;
    ///
    /// let ct = cks.encrypt(msg);
    /// let d_ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, &streams);
    ///
    /// // Compute homomorphically a scalar multiplication:
    /// let d_ct_res = sks.scalar_rem(&d_ct, scalar, &streams);
    /// let ct_res = d_ct_res.to_radix_ciphertext(&streams);
    ///
    /// let clear: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg % scalar, clear);
    /// ```
    pub fn scalar_rem<Scalar>(
        &self,
        numerator: &CudaUnsignedRadixCiphertext,
        divisor: Scalar,
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext
    where
        Scalar: Reciprocable + ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
    {
        let res = unsafe { self.unchecked_scalar_rem_async(numerator, divisor, streams) };
        streams.synchronize();
        res
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronized
    pub unsafe fn scalar_rem_async<Scalar>(
        &self,
        numerator: &CudaUnsignedRadixCiphertext,
        divisor: Scalar,
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext
    where
        Scalar: Reciprocable + ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
    {
        let mut tmp_numerator;
        let numerator = if numerator.block_carries_are_empty() {
            numerator
        } else {
            tmp_numerator = numerator.duplicate_async(streams);
            self.full_propagate_assign_async(&mut tmp_numerator, streams);
            &tmp_numerator
        };

        self.unchecked_scalar_rem_async(numerator, divisor, streams)
    }

    pub fn unchecked_signed_scalar_div<Scalar>(
        &self,
        numerator: &CudaSignedRadixCiphertext,
        divisor: Scalar,
        streams: &CudaStreams,
    ) -> CudaSignedRadixCiphertext
    where
        Scalar: SignedReciprocable + ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
        <<Scalar as SignedReciprocable>::Unsigned as Reciprocable>::DoublePrecision: Send,
    {
        let res = unsafe { self.unchecked_signed_scalar_div_async(numerator, divisor, streams) };
        streams.synchronize();
        res
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronized
    pub unsafe fn unchecked_signed_scalar_div_async<Scalar>(
        &self,
        numerator: &CudaSignedRadixCiphertext,
        divisor: Scalar,
        streams: &CudaStreams,
    ) -> CudaSignedRadixCiphertext
    where
        Scalar: SignedReciprocable + ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
        <<Scalar as SignedReciprocable>::Unsigned as Reciprocable>::DoublePrecision: Send,
    {
        assert_ne!(divisor, Scalar::ZERO, "attempt to divide by 0");

        let numerator_bits = self.message_modulus.0.ilog2()
            * numerator.ciphertext.d_blocks.lwe_ciphertext_count().0 as u32;
        assert!(
            Scalar::BITS >= numerator_bits as usize,
            "The scalar divisor type must have a number of bits that is\
        >= to the number of bits encrypted in the ciphertext"
        );

        let mut quotient: CudaSignedRadixCiphertext = numerator.duplicate_async(streams);
        let num_blocks = numerator.as_ref().d_blocks.lwe_ciphertext_count().0 as u32;
        let msg_bits = self.message_modulus.0.ilog2() as usize;
        let lwe_dimension = self
            .key_switching_key
            .output_key_lwe_size()
            .to_lwe_dimension();

        let mut scalar_properties = prepare_default_scalar_divisor();

        let absolute_divisor = Scalar::Unsigned::cast_from(divisor.wrapping_abs());
        let chosen_multiplier =
            choose_multiplier(absolute_divisor, numerator_bits - 1, numerator_bits);

        scalar_properties.is_abs_divisor_one = absolute_divisor == Scalar::Unsigned::ONE;
        scalar_properties.is_divisor_negative = divisor < Scalar::ZERO;
        scalar_properties.is_divisor_pow2 = absolute_divisor.is_power_of_two();

        scalar_properties.is_multiplier_geq_numerator_magnitude = chosen_multiplier.multiplier
            >= (<Scalar::Unsigned as Reciprocable>::DoublePrecision::ONE << (numerator_bits - 1));
        scalar_properties.shift_post = chosen_multiplier.shift_post;
        scalar_properties.multiplier_length = chosen_multiplier.l;
        scalar_properties.is_multiplier_wider_than_numerator =
            chosen_multiplier.l >= numerator_bits;

        let rhs = if scalar_properties.is_multiplier_geq_numerator_magnitude {
            let cst = chosen_multiplier.multiplier
                - (<Scalar::Unsigned as Reciprocable>::DoublePrecision::ONE << numerator_bits);
            Scalar::DoublePrecision::cast_from(cst)
        } else {
            Scalar::DoublePrecision::cast_from(chosen_multiplier.multiplier)
        };

        let decomposed_multiplier = BlockDecomposer::with_early_stop_at_zero(rhs, 1)
            .iter_as::<u64>()
            .collect::<Vec<_>>();
        scalar_properties.decomposed_multiplier = decomposed_multiplier.as_ptr();

        let decomposer = BlockDecomposer::with_early_stop_at_zero(rhs, 1).iter_as::<u8>();
        let mut multiplier_has_at_least_one_set = vec![0u64; msg_bits];
        for (i, bit) in decomposer.collect_vec().iter().copied().enumerate() {
            if bit == 1 {
                multiplier_has_at_least_one_set[i % msg_bits] = 1;
            }
        }
        scalar_properties.multiplier_has_at_least_one_set =
            multiplier_has_at_least_one_set.as_ptr();

        let num_ciphertext_bits = msg_bits * 2 * num_blocks as usize;
        scalar_properties.active_bits_multiplier = decomposed_multiplier
            .iter()
            .take(num_ciphertext_bits)
            .filter(|&&bit| bit == 1u64)
            .count() as u32;

        scalar_properties.is_multiplier_pow2 = rhs.is_power_of_two();
        scalar_properties.is_abs_multiplier_one = rhs == Scalar::DoublePrecision::ONE;
        scalar_properties.is_multiplier_zero = rhs == Scalar::DoublePrecision::ZERO;
        scalar_properties.ilog2_multiplier = if scalar_properties.is_multiplier_pow2 {
            rhs.ilog2()
        } else {
            0u32
        };

        match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => {
                unchecked_signed_scalar_div_integer_radix_kb_assign_async(
                    streams,
                    quotient.as_mut(),
                    &scalar_properties,
                    &self.key_switching_key.d_vec,
                    &d_bsk.d_vec,
                    self.message_modulus,
                    self.carry_modulus,
                    d_bsk.glwe_dimension,
                    d_bsk.polynomial_size,
                    lwe_dimension,
                    self.key_switching_key.decomposition_level_count(),
                    self.key_switching_key.decomposition_base_log(),
                    d_bsk.decomp_level_count,
                    d_bsk.decomp_base_log,
                    LweBskGroupingFactor(0),
                    num_blocks,
                    PBSType::Classical,
                    d_bsk.d_ms_noise_reduction_key.as_ref(),
                    numerator_bits,
                );
            }
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                unchecked_signed_scalar_div_integer_radix_kb_assign_async(
                    streams,
                    quotient.as_mut(),
                    &scalar_properties,
                    &self.key_switching_key.d_vec,
                    &d_multibit_bsk.d_vec,
                    self.message_modulus,
                    self.carry_modulus,
                    d_multibit_bsk.glwe_dimension,
                    d_multibit_bsk.polynomial_size,
                    lwe_dimension,
                    self.key_switching_key.decomposition_level_count(),
                    self.key_switching_key.decomposition_base_log(),
                    d_multibit_bsk.decomp_level_count,
                    d_multibit_bsk.decomp_base_log,
                    d_multibit_bsk.grouping_factor,
                    num_blocks,
                    PBSType::MultiBit,
                    None,
                    numerator_bits,
                );
            }
        }

        let _carry = self.propagate_single_carry_assign_async(
            &mut quotient,
            streams,
            None,
            OutputFlag::None,
        );

        quotient
    }

    /// Computes homomorphically a division between a signed ciphertext and a scalar.
    ///
    /// The result is returned as a new ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::integer::gpu::ciphertext::CudaSignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, size, &streams);
    ///
    /// let msg = 30;
    /// let scalar = -3;
    ///
    /// let ct = cks.encrypt_signed(msg);
    /// let d_ct = CudaSignedRadixCiphertext::from_signed_radix_ciphertext(&ct, &streams);
    ///
    /// // Compute homomorphically a scalar division:
    /// let d_ct_res = sks.signed_scalar_div(&d_ct, scalar, &streams);
    /// let ct_res = d_ct_res.to_signed_radix_ciphertext(&streams);
    ///
    /// let clear: i64 = cks.decrypt_signed(&ct_res);
    /// assert_eq!(msg / scalar, clear);
    /// ```
    pub fn signed_scalar_div<Scalar>(
        &self,
        numerator: &CudaSignedRadixCiphertext,
        divisor: Scalar,
        streams: &CudaStreams,
    ) -> CudaSignedRadixCiphertext
    where
        Scalar: SignedReciprocable + ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
        <<Scalar as SignedReciprocable>::Unsigned as Reciprocable>::DoublePrecision: Send,
    {
        let res = unsafe { self.signed_scalar_div_async(numerator, divisor, streams) };
        streams.synchronize();
        res
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronized
    pub unsafe fn signed_scalar_div_async<Scalar>(
        &self,
        numerator: &CudaSignedRadixCiphertext,
        divisor: Scalar,
        streams: &CudaStreams,
    ) -> CudaSignedRadixCiphertext
    where
        Scalar: SignedReciprocable + ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
        <<Scalar as SignedReciprocable>::Unsigned as Reciprocable>::DoublePrecision: Send,
    {
        let mut tmp_numerator;
        let numerator = if numerator.block_carries_are_empty() {
            numerator
        } else {
            tmp_numerator = numerator.duplicate_async(streams);
            self.full_propagate_assign_async(&mut tmp_numerator, streams);
            &tmp_numerator
        };

        self.unchecked_signed_scalar_div_async(numerator, divisor, streams)
    }

    pub fn unchecked_signed_scalar_div_rem<Scalar>(
        &self,
        numerator: &CudaSignedRadixCiphertext,
        divisor: Scalar,
        streams: &CudaStreams,
    ) -> (CudaSignedRadixCiphertext, CudaSignedRadixCiphertext)
    where
        Scalar: SignedReciprocable + ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
        <<Scalar as SignedReciprocable>::Unsigned as Reciprocable>::DoublePrecision: Send,
    {
        let res =
            unsafe { self.unchecked_signed_scalar_div_rem_async(numerator, divisor, streams) };
        streams.synchronize();
        res
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronized
    pub unsafe fn unchecked_signed_scalar_div_rem_async<Scalar>(
        &self,
        numerator: &CudaSignedRadixCiphertext,
        divisor: Scalar,
        streams: &CudaStreams,
    ) -> (CudaSignedRadixCiphertext, CudaSignedRadixCiphertext)
    where
        Scalar: SignedReciprocable + ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
        <<Scalar as SignedReciprocable>::Unsigned as Reciprocable>::DoublePrecision: Send,
    {
        let num_blocks = numerator.as_ref().d_blocks.lwe_ciphertext_count().0 as u32;

        let mut quotient: CudaSignedRadixCiphertext = numerator.duplicate_async(streams);
        let mut remainder: CudaSignedRadixCiphertext =
            self.create_trivial_zero_radix_async(num_blocks as usize, streams);

        assert_ne!(divisor, Scalar::ZERO, "attempt to divide by 0");

        let numerator_bits = self.message_modulus.0.ilog2()
            * numerator.ciphertext.d_blocks.lwe_ciphertext_count().0 as u32;

        assert!(
            Scalar::BITS >= numerator_bits as usize,
            "The scalar divisor type must have a number of bits that is\
    >= to the number of bits encrypted in the ciphertext"
        );

        let msg_bits = self.message_modulus.0.ilog2() as usize;
        let lwe_dimension = self
            .key_switching_key
            .output_key_lwe_size()
            .to_lwe_dimension();

        let mut scalar_properties = prepare_default_scalar_divisor();

        let absolute_divisor = Scalar::Unsigned::cast_from(divisor.wrapping_abs());
        let chosen_multiplier =
            choose_multiplier(absolute_divisor, numerator_bits - 1, numerator_bits);

        let is_abs_divisor_pow2 = absolute_divisor.is_power_of_two();
        scalar_properties.is_divisor_pow2 = is_abs_divisor_pow2;
        scalar_properties.is_abs_divisor_one = absolute_divisor == Scalar::Unsigned::ONE;
        scalar_properties.is_divisor_negative = divisor < Scalar::ZERO;
        scalar_properties.is_divisor_zero = divisor == Scalar::ZERO;
        if is_abs_divisor_pow2 && !scalar_properties.is_divisor_negative {
            scalar_properties.ilog2_divisor = divisor.ilog2();
        }

        let decomposed_divisor = BlockDecomposer::with_early_stop_at_zero(divisor, 1)
            .iter_as::<u64>()
            .collect::<Vec<_>>();
        let decomposer_divisor =
            BlockDecomposer::with_early_stop_at_zero(divisor, 1).iter_as::<u8>();
        let mut divisor_has_at_least_one_set = vec![0u64; msg_bits];
        for (i, bit) in decomposer_divisor.collect_vec().iter().copied().enumerate() {
            if bit == 1 {
                divisor_has_at_least_one_set[i % msg_bits] = 1;
            }
        }
        scalar_properties.decomposed_divisor = decomposed_divisor.as_ptr();
        scalar_properties.divisor_has_at_least_one_set = divisor_has_at_least_one_set.as_ptr();
        scalar_properties.num_scalars_divisor = decomposed_divisor.len() as u32;
        scalar_properties.active_bits_divisor = decomposed_divisor
            .iter()
            .take(msg_bits * num_blocks as usize)
            .filter(|&&bit| bit == 1u64)
            .count() as u32;

        scalar_properties.is_multiplier_geq_numerator_magnitude = chosen_multiplier.multiplier
            >= (<Scalar::Unsigned as Reciprocable>::DoublePrecision::ONE << (numerator_bits - 1));
        scalar_properties.multiplier_length = chosen_multiplier.l;
        scalar_properties.shift_post = chosen_multiplier.shift_post;
        scalar_properties.is_multiplier_wider_than_numerator =
            chosen_multiplier.l >= numerator_bits;

        let rhs = if scalar_properties.is_multiplier_geq_numerator_magnitude {
            let cst = chosen_multiplier.multiplier
                - (<Scalar::Unsigned as Reciprocable>::DoublePrecision::ONE << numerator_bits);
            Scalar::DoublePrecision::cast_from(cst)
        } else {
            Scalar::DoublePrecision::cast_from(chosen_multiplier.multiplier)
        };

        let decomposed_multiplier = BlockDecomposer::with_early_stop_at_zero(rhs, 1)
            .iter_as::<u64>()
            .collect::<Vec<_>>();
        scalar_properties.decomposed_multiplier = decomposed_multiplier.as_ptr();

        let decomposer_rhs = BlockDecomposer::with_early_stop_at_zero(rhs, 1).iter_as::<u8>();
        let mut multiplier_has_at_least_one_set = vec![0u64; msg_bits];
        for (i, bit) in decomposer_rhs.collect_vec().iter().copied().enumerate() {
            if bit == 1 {
                multiplier_has_at_least_one_set[i % msg_bits] = 1;
            }
        }
        scalar_properties.multiplier_has_at_least_one_set =
            multiplier_has_at_least_one_set.as_ptr();
        scalar_properties.num_scalars_multiplier = decomposed_multiplier.len() as u32;
        scalar_properties.active_bits_multiplier = decomposed_multiplier
            .iter()
            .take(2 * msg_bits * num_blocks as usize)
            .filter(|&&bit| bit == 1u64)
            .count() as u32;

        scalar_properties.is_multiplier_pow2 = rhs.is_power_of_two();
        scalar_properties.is_abs_multiplier_one = rhs == Scalar::DoublePrecision::ONE;
        scalar_properties.is_multiplier_zero = rhs == Scalar::DoublePrecision::ZERO;
        scalar_properties.ilog2_multiplier =
            if scalar_properties.is_multiplier_pow2 && !scalar_properties.is_abs_multiplier_one {
                rhs.ilog2()
            } else {
                0u32
            };

        match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => {
                unchecked_signed_scalar_div_rem_integer_radix_kb_assign_async(
                    streams,
                    quotient.as_mut(),
                    remainder.as_mut(),
                    &scalar_properties,
                    &self.key_switching_key.d_vec,
                    &d_bsk.d_vec,
                    self.message_modulus,
                    self.carry_modulus,
                    d_bsk.glwe_dimension,
                    d_bsk.polynomial_size,
                    lwe_dimension,
                    self.key_switching_key.decomposition_level_count(),
                    self.key_switching_key.decomposition_base_log(),
                    d_bsk.decomp_level_count,
                    d_bsk.decomp_base_log,
                    LweBskGroupingFactor(0),
                    num_blocks,
                    PBSType::Classical,
                    numerator_bits,
                    d_bsk.d_ms_noise_reduction_key.as_ref(),
                );
            }
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                unchecked_signed_scalar_div_rem_integer_radix_kb_assign_async(
                    streams,
                    quotient.as_mut(),
                    remainder.as_mut(),
                    &scalar_properties,
                    &self.key_switching_key.d_vec,
                    &d_multibit_bsk.d_vec,
                    self.message_modulus,
                    self.carry_modulus,
                    d_multibit_bsk.glwe_dimension,
                    d_multibit_bsk.polynomial_size,
                    lwe_dimension,
                    self.key_switching_key.decomposition_level_count(),
                    self.key_switching_key.decomposition_base_log(),
                    d_multibit_bsk.decomp_level_count,
                    d_multibit_bsk.decomp_base_log,
                    d_multibit_bsk.grouping_factor,
                    num_blocks,
                    PBSType::MultiBit,
                    numerator_bits,
                    None,
                );
            }
        }

        (quotient, remainder)
    }

    /// Computes homomorphically a division between a signed ciphertext and a scalar.
    ///
    /// The result is returned as a two new ciphertexts for the quotient and remainder.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::integer::gpu::ciphertext::CudaSignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, size, &streams);
    ///
    /// let msg = 30;
    /// let scalar = -3;
    ///
    /// let ct = cks.encrypt_signed(msg);
    /// let d_ct = CudaSignedRadixCiphertext::from_signed_radix_ciphertext(&ct, &streams);
    ///
    /// // Compute homomorphically a scalar division:
    /// let (d_ct_q, d_ct_r) = sks.signed_scalar_div_rem(&d_ct, scalar, &streams);
    /// let ct_q = d_ct_q.to_signed_radix_ciphertext(&streams);
    /// let ct_r = d_ct_r.to_signed_radix_ciphertext(&streams);
    ///
    /// let quotient: i64 = cks.decrypt_signed(&ct_q);
    /// let remainder: i64 = cks.decrypt_signed(&ct_r);
    /// assert_eq!(msg / scalar, quotient);
    /// assert_eq!(msg % scalar, remainder);
    /// ```
    pub fn signed_scalar_div_rem<Scalar>(
        &self,
        numerator: &CudaSignedRadixCiphertext,
        divisor: Scalar,
        streams: &CudaStreams,
    ) -> (CudaSignedRadixCiphertext, CudaSignedRadixCiphertext)
    where
        Scalar: SignedReciprocable + ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
        <<Scalar as SignedReciprocable>::Unsigned as Reciprocable>::DoublePrecision: Send,
    {
        let res = unsafe { self.signed_scalar_div_rem_async(numerator, divisor, streams) };
        streams.synchronize();
        res
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronized
    pub unsafe fn signed_scalar_div_rem_async<Scalar>(
        &self,
        numerator: &CudaSignedRadixCiphertext,
        divisor: Scalar,
        streams: &CudaStreams,
    ) -> (CudaSignedRadixCiphertext, CudaSignedRadixCiphertext)
    where
        Scalar: SignedReciprocable + ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
        <<Scalar as SignedReciprocable>::Unsigned as Reciprocable>::DoublePrecision: Send,
    {
        let mut tmp_numerator;
        let numerator = if numerator.block_carries_are_empty() {
            numerator
        } else {
            tmp_numerator = numerator.duplicate_async(streams);
            self.full_propagate_assign_async(&mut tmp_numerator, streams);
            &tmp_numerator
        };

        self.unchecked_signed_scalar_div_rem_async(numerator, divisor, streams)
    }

    pub fn unchecked_signed_scalar_rem<Scalar>(
        &self,
        numerator: &CudaSignedRadixCiphertext,
        divisor: Scalar,
        streams: &CudaStreams,
    ) -> CudaSignedRadixCiphertext
    where
        Scalar: SignedReciprocable + ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
        <<Scalar as SignedReciprocable>::Unsigned as Reciprocable>::DoublePrecision: Send,
    {
        let remainder =
            unsafe { self.unchecked_signed_scalar_rem_async(numerator, divisor, streams) };
        streams.synchronize();

        remainder
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronized
    pub unsafe fn unchecked_signed_scalar_rem_async<Scalar>(
        &self,
        numerator: &CudaSignedRadixCiphertext,
        divisor: Scalar,
        streams: &CudaStreams,
    ) -> CudaSignedRadixCiphertext
    where
        Scalar: SignedReciprocable + ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
        <<Scalar as SignedReciprocable>::Unsigned as Reciprocable>::DoublePrecision: Send,
    {
        let (_, remainder) =
            self.unchecked_signed_scalar_div_rem_async(numerator, divisor, streams);

        remainder
    }

    /// Computes homomorphically a division between a ciphertext and a scalar.
    ///
    /// The result is returned as a new ciphertext that encrypts the remainder of the division.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::integer::gpu::ciphertext::CudaSignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, size, &streams);
    ///
    /// let msg = 30;
    /// let scalar = -3;
    ///
    /// let ct = cks.encrypt_signed(msg);
    /// let d_ct = CudaSignedRadixCiphertext::from_signed_radix_ciphertext(&ct, &streams);
    ///
    /// // Compute homomorphically a scalar multiplication:
    /// let d_ct_res = sks.signed_scalar_rem(&d_ct, scalar, &streams);
    /// let ct_res = d_ct_res.to_signed_radix_ciphertext(&streams);
    ///
    /// let clear: i64 = cks.decrypt_signed(&ct_res);
    /// assert_eq!(msg % scalar, clear);
    /// ```
    pub fn signed_scalar_rem<Scalar>(
        &self,
        numerator: &CudaSignedRadixCiphertext,
        divisor: Scalar,
        streams: &CudaStreams,
    ) -> CudaSignedRadixCiphertext
    where
        Scalar: SignedReciprocable + ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
        <<Scalar as SignedReciprocable>::Unsigned as Reciprocable>::DoublePrecision: Send,
    {
        let res = unsafe { self.signed_scalar_rem_async(numerator, divisor, streams) };
        streams.synchronize();
        res
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronized
    pub unsafe fn signed_scalar_rem_async<Scalar>(
        &self,
        numerator: &CudaSignedRadixCiphertext,
        divisor: Scalar,
        streams: &CudaStreams,
    ) -> CudaSignedRadixCiphertext
    where
        Scalar: SignedReciprocable + ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
        <<Scalar as SignedReciprocable>::Unsigned as Reciprocable>::DoublePrecision: Send,
    {
        let mut tmp_numerator;
        let numerator = if numerator.block_carries_are_empty() {
            numerator
        } else {
            tmp_numerator = numerator.duplicate_async(streams);
            self.full_propagate_assign_async(&mut tmp_numerator, streams);
            &tmp_numerator
        };

        self.unchecked_signed_scalar_rem_async(numerator, divisor, streams)
    }

    pub fn get_scalar_div_size_on_gpu<Scalar>(
        &self,
        numerator: &CudaUnsignedRadixCiphertext,
        divisor: Scalar,
        streams: &CudaStreams,
    ) -> u64
    where
        Scalar: Reciprocable + ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
    {
        let num_blocks = numerator.as_ref().d_blocks.lwe_ciphertext_count().0 as u32;

        let numerator_bits = numerator
            .as_ref()
            .info
            .blocks
            .first()
            .unwrap()
            .message_modulus
            .0
            .ilog2()
            * num_blocks;

        assert_ne!(divisor, Scalar::ZERO, "attempt to divide by 0");

        assert!(
            Scalar::BITS >= numerator_bits as usize,
            "The scalar divisor type must have a number of bits that is \
    >= to the number of bits encrypted in the ciphertext: \n\
    encrypted bits: {numerator_bits}, scalar bits: {}
    ",
            Scalar::BITS
        );

        let mut scalar_properties = prepare_default_scalar_divisor();

        let is_divisor_power_of_two = MiniUnsignedInteger::is_power_of_two(divisor);
        scalar_properties.is_divisor_pow2 = is_divisor_power_of_two;
        scalar_properties.is_abs_divisor_one = divisor == Scalar::ONE;
        scalar_properties.is_divisor_wider_than_numerator =
            MiniUnsignedInteger::ceil_ilog2(divisor) > numerator_bits;

        let mut chosen_multiplier = choose_multiplier(divisor, numerator_bits, numerator_bits);

        if chosen_multiplier.multiplier >= (Scalar::DoublePrecision::ONE << numerator_bits as usize)
            && crate::integer::server_key::radix_parallel::scalar_div_mod::is_even(divisor)
            && !scalar_properties.is_divisor_pow2
            && !scalar_properties.is_divisor_wider_than_numerator
        {
            let divisor_dp = Scalar::DoublePrecision::cast_from(divisor);
            let two_pow_e = divisor_dp
                & ((Scalar::DoublePrecision::ONE << numerator_bits as usize) - divisor_dp);
            let e = MiniUnsignedInteger::ilog2(two_pow_e);
            let divisor_odd_dp = divisor_dp / two_pow_e;

            assert!(numerator_bits > e && e <= Scalar::BITS as u32);
            let divisor_odd: Scalar = divisor_odd_dp.cast_into();
            chosen_multiplier = choose_multiplier(divisor_odd, numerator_bits - e, numerator_bits);
        }

        scalar_properties.is_multiplier_geq_numerator_magnitude = chosen_multiplier.multiplier
            >= (Scalar::DoublePrecision::ONE << numerator_bits as usize);

        let rhs = if scalar_properties.is_multiplier_geq_numerator_magnitude {
            chosen_multiplier.multiplier - (Scalar::DoublePrecision::ONE << numerator_bits as usize)
        } else {
            chosen_multiplier.multiplier
        };

        let msg_bits = self.message_modulus.0.ilog2() as usize;

        let decomposed_rhs = BlockDecomposer::with_early_stop_at_zero(rhs, 1)
            .iter_as::<u64>()
            .collect::<Vec<_>>();

        scalar_properties.active_bits_multiplier = decomposed_rhs
            .iter()
            .take(2 * msg_bits * num_blocks as usize)
            .filter(|&&rhs_bit| rhs_bit == 1u64)
            .count() as u32;

        let full_prop_mem = if numerator.block_carries_are_empty() {
            0
        } else {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => get_full_propagate_assign_size_on_gpu(
                    streams,
                    d_bsk.input_lwe_dimension(),
                    d_bsk.glwe_dimension(),
                    d_bsk.polynomial_size(),
                    self.key_switching_key.decomposition_level_count(),
                    self.key_switching_key.decomposition_base_log(),
                    d_bsk.decomp_level_count(),
                    d_bsk.decomp_base_log(),
                    self.message_modulus,
                    self.carry_modulus,
                    PBSType::Classical,
                    LweBskGroupingFactor(0),
                    d_bsk.d_ms_noise_reduction_key.as_ref(),
                ),
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                    get_full_propagate_assign_size_on_gpu(
                        streams,
                        d_multibit_bsk.input_lwe_dimension(),
                        d_multibit_bsk.glwe_dimension(),
                        d_multibit_bsk.polynomial_size(),
                        self.key_switching_key.decomposition_level_count(),
                        self.key_switching_key.decomposition_base_log(),
                        d_multibit_bsk.decomp_level_count(),
                        d_multibit_bsk.decomp_base_log(),
                        self.message_modulus,
                        self.carry_modulus,
                        PBSType::MultiBit,
                        d_multibit_bsk.grouping_factor,
                        None,
                    )
                }
            }
        };

        let scalar_div_mem = match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => get_scalar_div_integer_radix_kb_size_on_gpu(
                streams,
                &scalar_properties,
                self.message_modulus,
                self.carry_modulus,
                d_bsk.glwe_dimension,
                d_bsk.polynomial_size,
                d_bsk.input_lwe_dimension,
                self.key_switching_key.decomposition_level_count(),
                self.key_switching_key.decomposition_base_log(),
                d_bsk.decomp_level_count,
                d_bsk.decomp_base_log,
                LweBskGroupingFactor(0),
                num_blocks,
                PBSType::Classical,
                d_bsk.d_ms_noise_reduction_key.as_ref(),
            ),
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                get_scalar_div_integer_radix_kb_size_on_gpu(
                    streams,
                    &scalar_properties,
                    self.message_modulus,
                    self.carry_modulus,
                    d_multibit_bsk.glwe_dimension,
                    d_multibit_bsk.polynomial_size,
                    d_multibit_bsk.input_lwe_dimension,
                    self.key_switching_key.decomposition_level_count(),
                    self.key_switching_key.decomposition_base_log(),
                    d_multibit_bsk.decomp_level_count,
                    d_multibit_bsk.decomp_base_log,
                    d_multibit_bsk.grouping_factor,
                    num_blocks,
                    PBSType::MultiBit,
                    None,
                )
            }
        };

        full_prop_mem.max(scalar_div_mem)
    }

    pub fn get_scalar_div_rem_size_on_gpu<Scalar>(
        &self,
        numerator: &CudaUnsignedRadixCiphertext,
        divisor: Scalar,
        streams: &CudaStreams,
    ) -> u64
    where
        Scalar: Reciprocable + ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
    {
        let num_blocks = numerator.as_ref().d_blocks.lwe_ciphertext_count().0 as u32;

        let numerator_bits = numerator
            .as_ref()
            .info
            .blocks
            .first()
            .unwrap()
            .message_modulus
            .0
            .ilog2()
            * num_blocks;

        assert_ne!(divisor, Scalar::ZERO, "attempt to divide by 0");

        assert!(
            Scalar::BITS >= numerator_bits as usize,
            "The scalar divisor type must have a number of bits that is \
    >= to the number of bits encrypted in the ciphertext: \n\
    encrypted bits: {numerator_bits}, scalar bits: {}
    ",
            Scalar::BITS
        );
        let mut scalar_properties = prepare_default_scalar_divisor();
        let msg_bits = self.message_modulus.0.ilog2() as usize;

        let is_divisor_power_of_two = MiniUnsignedInteger::is_power_of_two(divisor);
        scalar_properties.is_divisor_pow2 = is_divisor_power_of_two;
        scalar_properties.is_abs_divisor_one = divisor == Scalar::ONE;
        scalar_properties.is_divisor_wider_than_numerator =
            MiniUnsignedInteger::ceil_ilog2(divisor) > numerator_bits;

        let decomposed_divisor = BlockDecomposer::with_early_stop_at_zero(divisor, 1)
            .iter_as::<u64>()
            .collect::<Vec<_>>();
        scalar_properties.active_bits_divisor = decomposed_divisor
            .iter()
            .take(msg_bits * num_blocks as usize)
            .filter(|&&bit| bit == 1u64)
            .count() as u32;

        let mut chosen_multiplier = choose_multiplier(divisor, numerator_bits, numerator_bits);

        if chosen_multiplier.multiplier >= (Scalar::DoublePrecision::ONE << numerator_bits as usize)
            && crate::integer::server_key::radix_parallel::scalar_div_mod::is_even(divisor)
            && !scalar_properties.is_divisor_pow2
            && !scalar_properties.is_divisor_wider_than_numerator
        {
            let divisor_dp = Scalar::DoublePrecision::cast_from(divisor);
            let two_pow_e = divisor_dp
                & ((Scalar::DoublePrecision::ONE << numerator_bits as usize) - divisor_dp);
            let e = MiniUnsignedInteger::ilog2(two_pow_e);
            let divisor_odd_dp = divisor_dp / two_pow_e;

            assert!(numerator_bits > e && e <= Scalar::BITS as u32);
            let divisor_odd: Scalar = divisor_odd_dp.cast_into();
            chosen_multiplier = choose_multiplier(divisor_odd, numerator_bits - e, numerator_bits);
        }

        scalar_properties.is_multiplier_geq_numerator_magnitude = chosen_multiplier.multiplier
            >= (Scalar::DoublePrecision::ONE << numerator_bits as usize);

        let rhs = if scalar_properties.is_multiplier_geq_numerator_magnitude {
            chosen_multiplier.multiplier - (Scalar::DoublePrecision::ONE << numerator_bits as usize)
        } else {
            chosen_multiplier.multiplier
        };

        let decomposed_rhs = BlockDecomposer::with_early_stop_at_zero(rhs, 1)
            .iter_as::<u64>()
            .collect::<Vec<_>>();
        scalar_properties.active_bits_multiplier = decomposed_rhs
            .iter()
            .take(2 * msg_bits * num_blocks as usize)
            .filter(|&&rhs_bit| rhs_bit == 1u64)
            .count() as u32;

        unsafe {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    get_scalar_div_rem_integer_radix_kb_size_on_gpu(
                        streams,
                        &scalar_properties,
                        self.message_modulus,
                        self.carry_modulus,
                        d_bsk.glwe_dimension,
                        d_bsk.polynomial_size,
                        d_bsk.input_lwe_dimension,
                        self.key_switching_key.decomposition_level_count(),
                        self.key_switching_key.decomposition_base_log(),
                        d_bsk.decomp_level_count,
                        d_bsk.decomp_base_log,
                        LweBskGroupingFactor(0),
                        num_blocks,
                        PBSType::Classical,
                        d_bsk.d_ms_noise_reduction_key.as_ref(),
                    )
                }
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                    get_scalar_div_rem_integer_radix_kb_size_on_gpu(
                        streams,
                        &scalar_properties,
                        self.message_modulus,
                        self.carry_modulus,
                        d_multibit_bsk.glwe_dimension,
                        d_multibit_bsk.polynomial_size,
                        d_multibit_bsk.input_lwe_dimension,
                        self.key_switching_key.decomposition_level_count(),
                        self.key_switching_key.decomposition_base_log(),
                        d_multibit_bsk.decomp_level_count,
                        d_multibit_bsk.decomp_base_log,
                        d_multibit_bsk.grouping_factor,
                        num_blocks,
                        PBSType::MultiBit,
                        None,
                    )
                }
            }
        }
    }

    pub fn get_scalar_rem_size_on_gpu<Scalar>(
        &self,
        numerator: &CudaUnsignedRadixCiphertext,
        divisor: Scalar,
        streams: &CudaStreams,
    ) -> u64
    where
        Scalar: Reciprocable + ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
    {
        if MiniUnsignedInteger::is_power_of_two(divisor) {
            return self.get_scalar_bitand_size_on_gpu(numerator, streams);
        }

        self.get_scalar_div_rem_size_on_gpu(numerator, divisor, streams)
    }

    pub fn get_signed_scalar_div_size_on_gpu<Scalar>(
        &self,
        numerator: &CudaSignedRadixCiphertext,
        divisor: Scalar,
        streams: &CudaStreams,
    ) -> u64
    where
        Scalar: SignedReciprocable,
        <<Scalar as SignedReciprocable>::Unsigned as Reciprocable>::DoublePrecision: Send,
    {
        assert_ne!(divisor, Scalar::ZERO, "attempt to divide by 0");

        let num_blocks = numerator.as_ref().d_blocks.lwe_ciphertext_count().0 as u32;
        let numerator_bits = self.message_modulus.0.ilog2()
            * numerator.ciphertext.d_blocks.lwe_ciphertext_count().0 as u32;

        assert!(
            Scalar::BITS >= numerator_bits as usize,
            "The scalar divisor type must have a number of bits that is\
    >= to the number of bits encrypted in the ciphertext"
        );

        let mut scalar_properties = prepare_default_scalar_divisor();

        let absolute_divisor = Scalar::Unsigned::cast_from(divisor.wrapping_abs());
        let chosen_multiplier =
            choose_multiplier(absolute_divisor, numerator_bits - 1, numerator_bits);

        scalar_properties.is_abs_divisor_one = absolute_divisor == Scalar::Unsigned::ONE;
        scalar_properties.is_divisor_negative = divisor < Scalar::ZERO;
        scalar_properties.is_divisor_pow2 = absolute_divisor.is_power_of_two();

        scalar_properties.is_multiplier_geq_numerator_magnitude = chosen_multiplier.multiplier
            >= (<Scalar::Unsigned as Reciprocable>::DoublePrecision::ONE << (numerator_bits - 1));
        scalar_properties.is_multiplier_wider_than_numerator =
            chosen_multiplier.l >= numerator_bits;

        let rhs = if scalar_properties.is_multiplier_geq_numerator_magnitude {
            let cst = chosen_multiplier.multiplier
                - (<Scalar::Unsigned as Reciprocable>::DoublePrecision::ONE << numerator_bits);
            Scalar::DoublePrecision::cast_from(cst)
        } else {
            Scalar::DoublePrecision::cast_from(chosen_multiplier.multiplier)
        };

        let decomposed_rhs = BlockDecomposer::with_early_stop_at_zero(rhs, 1)
            .iter_as::<u64>()
            .collect::<Vec<_>>();

        let msg_bits = self.message_modulus.0.ilog2() as usize;
        let num_ciphertext_bits = 2 * msg_bits * num_blocks as usize;
        scalar_properties.active_bits_multiplier = decomposed_rhs
            .iter()
            .take(num_ciphertext_bits)
            .filter(|&&bit| bit == 1u64)
            .count() as u32;

        let lwe_dimension = self
            .key_switching_key
            .output_key_lwe_size()
            .to_lwe_dimension();

        match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => {
                get_signed_scalar_div_integer_radix_kb_size_on_gpu(
                    streams,
                    self.message_modulus,
                    self.carry_modulus,
                    d_bsk.glwe_dimension,
                    d_bsk.polynomial_size,
                    lwe_dimension,
                    d_bsk.decomp_base_log,
                    d_bsk.decomp_level_count,
                    self.key_switching_key.decomposition_base_log(),
                    self.key_switching_key.decomposition_level_count(),
                    LweBskGroupingFactor(0),
                    num_blocks,
                    PBSType::Classical,
                    &scalar_properties,
                    d_bsk.d_ms_noise_reduction_key.as_ref(),
                )
            }
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                get_signed_scalar_div_integer_radix_kb_size_on_gpu(
                    streams,
                    self.message_modulus,
                    self.carry_modulus,
                    d_multibit_bsk.glwe_dimension,
                    d_multibit_bsk.polynomial_size,
                    lwe_dimension,
                    d_multibit_bsk.decomp_base_log,
                    d_multibit_bsk.decomp_level_count,
                    self.key_switching_key.decomposition_base_log(),
                    self.key_switching_key.decomposition_level_count(),
                    d_multibit_bsk.grouping_factor,
                    num_blocks,
                    PBSType::MultiBit,
                    &scalar_properties,
                    None,
                )
            }
        }
    }

    pub fn get_signed_scalar_div_rem_size_on_gpu<Scalar>(
        &self,
        numerator: &CudaSignedRadixCiphertext,
        divisor: Scalar,
        streams: &CudaStreams,
    ) -> u64
    where
        Scalar: SignedReciprocable + ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
        <<Scalar as SignedReciprocable>::Unsigned as Reciprocable>::DoublePrecision: Send,
    {
        assert_ne!(divisor, Scalar::ZERO, "attempt to divide by 0");

        let num_blocks = numerator.as_ref().d_blocks.lwe_ciphertext_count().0 as u32;
        let numerator_bits = self.message_modulus.0.ilog2()
            * numerator.ciphertext.d_blocks.lwe_ciphertext_count().0 as u32;
        let msg_bits = self.message_modulus.0.ilog2() as usize;

        assert!(
            Scalar::BITS >= numerator_bits as usize,
            "The scalar divisor type must have a number of bits that is\
    >= to the number of bits encrypted in the ciphertext"
        );

        let mut scalar_properties = prepare_default_scalar_divisor();

        let absolute_divisor = Scalar::Unsigned::cast_from(divisor.wrapping_abs());
        scalar_properties.is_divisor_pow2 = absolute_divisor.is_power_of_two();
        scalar_properties.is_abs_divisor_one = absolute_divisor == Scalar::Unsigned::ONE;
        scalar_properties.is_divisor_negative = divisor < Scalar::ZERO;
        scalar_properties.is_divisor_zero = divisor == Scalar::ZERO;

        let decomposed_divisor = BlockDecomposer::with_early_stop_at_zero(divisor, 1)
            .iter_as::<u64>()
            .collect::<Vec<_>>();
        scalar_properties.active_bits_divisor = decomposed_divisor
            .iter()
            .take(msg_bits * num_blocks as usize)
            .filter(|&&bit| bit == 1u64)
            .count() as u32;

        let chosen_multiplier =
            choose_multiplier(absolute_divisor, numerator_bits - 1, numerator_bits);
        scalar_properties.is_multiplier_geq_numerator_magnitude = chosen_multiplier.multiplier
            >= (<Scalar::Unsigned as Reciprocable>::DoublePrecision::ONE << (numerator_bits - 1));
        scalar_properties.is_multiplier_wider_than_numerator =
            chosen_multiplier.l >= numerator_bits;

        let rhs = if scalar_properties.is_multiplier_geq_numerator_magnitude {
            let cst = chosen_multiplier.multiplier
                - (<Scalar::Unsigned as Reciprocable>::DoublePrecision::ONE << numerator_bits);
            Scalar::DoublePrecision::cast_from(cst)
        } else {
            Scalar::DoublePrecision::cast_from(chosen_multiplier.multiplier)
        };
        let decomposed_rhs = BlockDecomposer::with_early_stop_at_zero(rhs, 1)
            .iter_as::<u64>()
            .collect::<Vec<_>>();
        scalar_properties.active_bits_multiplier = decomposed_rhs
            .iter()
            .take(2 * msg_bits * num_blocks as usize)
            .filter(|&&bit| bit == 1u64)
            .count() as u32;

        let lwe_dimension = self
            .key_switching_key
            .output_key_lwe_size()
            .to_lwe_dimension();

        unsafe {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => get_signed_scalar_div_rem_size_on_gpu(
                    streams,
                    self.message_modulus,
                    self.carry_modulus,
                    d_bsk.glwe_dimension,
                    d_bsk.polynomial_size,
                    lwe_dimension,
                    self.key_switching_key.decomposition_level_count(),
                    self.key_switching_key.decomposition_base_log(),
                    d_bsk.decomp_level_count,
                    d_bsk.decomp_base_log,
                    LweBskGroupingFactor(0),
                    num_blocks,
                    PBSType::Classical,
                    &scalar_properties,
                    d_bsk.d_ms_noise_reduction_key.as_ref(),
                ),
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                    get_signed_scalar_div_rem_size_on_gpu(
                        streams,
                        self.message_modulus,
                        self.carry_modulus,
                        d_multibit_bsk.glwe_dimension,
                        d_multibit_bsk.polynomial_size,
                        lwe_dimension,
                        self.key_switching_key.decomposition_level_count(),
                        self.key_switching_key.decomposition_base_log(),
                        d_multibit_bsk.decomp_level_count,
                        d_multibit_bsk.decomp_base_log,
                        d_multibit_bsk.grouping_factor,
                        num_blocks,
                        PBSType::MultiBit,
                        &scalar_properties,
                        None,
                    )
                }
            }
        }
    }

    pub fn get_signed_scalar_rem_size_on_gpu<Scalar>(
        &self,
        numerator: &CudaSignedRadixCiphertext,
        divisor: Scalar,
        streams: &CudaStreams,
    ) -> u64
    where
        Scalar: SignedReciprocable + ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
        <<Scalar as SignedReciprocable>::Unsigned as Reciprocable>::DoublePrecision: Send,
    {
        self.get_signed_scalar_div_rem_size_on_gpu(numerator, divisor, streams)
            + 2 * self.get_ciphertext_size_on_gpu(numerator)
    }
}
