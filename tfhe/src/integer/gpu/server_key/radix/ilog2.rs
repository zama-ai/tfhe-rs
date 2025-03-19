use crate::core_crypto::gpu::CudaStreams;
use crate::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock;
use crate::integer::gpu::ciphertext::{
    CudaIntegerRadixCiphertext, CudaSignedRadixCiphertext, CudaUnsignedRadixCiphertext,
};
use crate::integer::gpu::reverse_blocks_inplace_async;
use crate::integer::gpu::server_key::CudaServerKey;
use crate::integer::server_key::radix_parallel::ilog2::{BitValue, Direction};
use crate::shortint::ciphertext::Degree;
use crate::shortint::parameters::NoiseLevel;

impl CudaServerKey {
    /// This function takes a ciphertext in radix representation
    /// and returns a vec of blocks, where each blocks holds the number of leading_zeros/ones
    ///
    /// This contains the logic of making a block have 0 leading_ones/zeros if its preceding
    /// block was not full of ones/zeros
    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronised
    pub(crate) unsafe fn prepare_count_of_consecutive_bits_async<T: CudaIntegerRadixCiphertext>(
        &self,
        ct: &T,
        direction: Direction,
        bit_value: BitValue,
        streams: &CudaStreams,
    ) -> T {
        assert!(
            self.carry_modulus.0 >= self.message_modulus.0,
            "A carry modulus as least as big as the message modulus is required"
        );

        let num_ct_blocks = ct.as_ref().d_blocks.lwe_ciphertext_count().0;

        // Allocate the necessary amount of memory
        let mut tmp_radix = ct.duplicate_async(streams);

        let lut = match direction {
            Direction::Trailing => self.generate_lookup_table(|x| {
                let x = x % self.message_modulus.0;

                let mut count = 0;
                for i in 0..self.message_modulus.0.ilog2() {
                    if (x >> i) & 1 == bit_value.opposite() as u64 {
                        break;
                    }
                    count += 1;
                }
                count
            }),
            Direction::Leading => self.generate_lookup_table(|x| {
                let x = x % self.message_modulus.0;

                let mut count = 0;
                for i in (0..self.message_modulus.0.ilog2()).rev() {
                    if (x >> i) & 1 == bit_value.opposite() as u64 {
                        break;
                    }
                    count += 1;
                }
                count
            }),
        };

        self.apply_lookup_table_async(
            tmp_radix.as_mut(),
            ct.as_ref(),
            &lut,
            0..num_ct_blocks,
            streams,
        );

        if direction == Direction::Leading {
            // Our blocks are from lsb to msb
            // `leading` means starting from the msb, so we reverse block
            // for the cum sum process done later
            reverse_blocks_inplace_async(streams, tmp_radix.as_mut());
        }

        // Use hillis-steele cumulative-sum algorithm
        // Here, each block either keeps his value (the number of leading zeros)
        // or becomes 0 if the preceding block
        // had a bit set to one in it (leading_zeros != num bits in message)
        let num_bits_in_message = self.message_modulus.0.ilog2() as u64;
        let sum_lut = self.generate_lookup_table_bivariate(
            |block_num_bit_count, more_significant_block_bit_count| {
                if more_significant_block_bit_count == num_bits_in_message {
                    block_num_bit_count
                } else {
                    0
                }
            },
        );

        let mut output_cts: T =
            self.create_trivial_zero_radix_async(num_ct_blocks * num_ct_blocks, streams);

        self.compute_prefix_sum_hillis_steele_async(
            output_cts.as_mut(),
            tmp_radix.as_mut(),
            &sum_lut,
            0..num_ct_blocks,
            streams,
        );
        output_cts
    }

    /// Counts how many consecutive bits there are
    ///
    /// The returned Ciphertexts has a variable size
    /// i.e. It contains just the minimum number of block
    /// needed to represent the maximum possible number of bits.
    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronised
    pub(crate) unsafe fn count_consecutive_bits_async<T: CudaIntegerRadixCiphertext>(
        &self,
        ct: &T,
        direction: Direction,
        bit_value: BitValue,
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext {
        if ct.as_ref().d_blocks.0.d_vec.is_empty() {
            return self.create_trivial_zero_radix_async(0, streams);
        }

        let num_bits_in_message = self.message_modulus.0.ilog2();
        let original_num_blocks = ct.as_ref().d_blocks.lwe_ciphertext_count().0;

        let num_bits_in_ciphertext = num_bits_in_message
            .checked_mul(original_num_blocks as u32)
            .expect("Number of bits encrypted exceeds u32::MAX");

        let mut leading_count_per_blocks =
            self.prepare_count_of_consecutive_bits_async(ct, direction, bit_value, streams);

        // `num_bits_in_ciphertext` is the max value we want to represent
        // its ilog2 + 1 gives use how many bits we need to be able to represent it.
        let counter_num_blocks =
            (num_bits_in_ciphertext.ilog2() + 1).div_ceil(self.message_modulus.0.ilog2()) as usize;

        let lwe_dimension = ct.as_ref().d_blocks.lwe_dimension();

        let lwe_size = lwe_dimension.to_lwe_size().0;
        let mut cts = Vec::<CudaUnsignedRadixCiphertext>::with_capacity(
            ct.as_ref().d_blocks.lwe_ciphertext_count().0,
        );
        for i in 0..ct.as_ref().d_blocks.lwe_ciphertext_count().0 {
            let mut new_item: CudaUnsignedRadixCiphertext =
                self.create_trivial_zero_radix_async(counter_num_blocks, streams);
            let mut dest_slice = new_item
                .as_mut()
                .d_blocks
                .0
                .d_vec
                .as_mut_slice(0..lwe_size, 0)
                .unwrap();

            let src_slice = leading_count_per_blocks
                .as_mut()
                .d_blocks
                .0
                .d_vec
                .as_mut_slice((i * lwe_size)..((i + 1) * lwe_size), 0)
                .unwrap();
            dest_slice.copy_from_gpu_async(&src_slice, streams, 0);
            let b = new_item.ciphertext.info.blocks.first_mut().unwrap();
            b.degree = leading_count_per_blocks
                .as_ref()
                .info
                .blocks
                .get(i)
                .unwrap()
                .degree;
            b.noise_level = leading_count_per_blocks
                .as_ref()
                .info
                .blocks
                .get(i)
                .unwrap()
                .noise_level;
            cts.push(new_item);
        }

        self.unchecked_sum_ciphertexts_async(&cts, streams)
    }

    //==============================================================================================
    //  Unchecked
    //==============================================================================================

    /// See [Self::trailing_zeros]
    ///
    /// Expects ct to have clean carries
    pub fn unchecked_trailing_zeros<T>(
        &self,
        ct: &T,
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext
    where
        T: CudaIntegerRadixCiphertext,
    {
        let res = unsafe { self.unchecked_trailing_zeros_async(ct, streams) };
        streams.synchronize();
        res
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronised
    pub unsafe fn unchecked_trailing_zeros_async<T>(
        &self,
        ct: &T,
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext
    where
        T: CudaIntegerRadixCiphertext,
    {
        self.count_consecutive_bits_async(ct, Direction::Trailing, BitValue::Zero, streams)
    }

    /// See [Self::trailing_ones]
    ///
    /// Expects ct to have clean carries
    pub fn unchecked_trailing_ones<T>(
        &self,
        ct: &T,
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext
    where
        T: CudaIntegerRadixCiphertext,
    {
        let res = unsafe { self.unchecked_trailing_ones_async(ct, streams) };
        streams.synchronize();
        res
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronised
    pub unsafe fn unchecked_trailing_ones_async<T>(
        &self,
        ct: &T,
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext
    where
        T: CudaIntegerRadixCiphertext,
    {
        self.count_consecutive_bits_async(ct, Direction::Trailing, BitValue::One, streams)
    }

    /// See [Self::leading_zeros]
    ///
    /// Expects ct to have clean carries
    pub fn unchecked_leading_zeros<T>(
        &self,
        ct: &T,
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext
    where
        T: CudaIntegerRadixCiphertext,
    {
        let res = unsafe { self.unchecked_leading_zeros_async(ct, streams) };
        streams.synchronize();
        res
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronised
    pub unsafe fn unchecked_leading_zeros_async<T>(
        &self,
        ct: &T,
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext
    where
        T: CudaIntegerRadixCiphertext,
    {
        self.count_consecutive_bits_async(ct, Direction::Leading, BitValue::Zero, streams)
    }

    /// See [Self::leading_ones]
    ///
    /// Expects ct to have clean carries
    pub fn unchecked_leading_ones<T>(
        &self,
        ct: &T,
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext
    where
        T: CudaIntegerRadixCiphertext,
    {
        let res = unsafe { self.unchecked_leading_ones_async(ct, streams) };
        streams.synchronize();
        res
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronised
    pub unsafe fn unchecked_leading_ones_async<T>(
        &self,
        ct: &T,
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext
    where
        T: CudaIntegerRadixCiphertext,
    {
        self.count_consecutive_bits_async(ct, Direction::Leading, BitValue::One, streams)
    }

    /// Returns the base 2 logarithm of the number, rounded down.
    ///
    /// See [Self::ilog2] for an example
    ///
    /// Expects ct to have clean carries
    pub fn unchecked_ilog2<T>(&self, ct: &T, streams: &CudaStreams) -> CudaUnsignedRadixCiphertext
    where
        T: CudaIntegerRadixCiphertext,
    {
        let res = unsafe { self.unchecked_ilog2_async(ct, streams) };
        streams.synchronize();
        res
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronised
    pub unsafe fn unchecked_ilog2_async<T>(
        &self,
        ct: &T,
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext
    where
        T: CudaIntegerRadixCiphertext,
    {
        if ct.as_ref().d_blocks.0.d_vec.is_empty() {
            return self.create_trivial_zero_radix_async(
                ct.as_ref().d_blocks.lwe_ciphertext_count().0,
                streams,
            );
        }

        let num_bits_in_message = self.message_modulus.0.ilog2();
        let original_num_blocks = ct.as_ref().d_blocks.lwe_ciphertext_count().0;

        let num_bits_in_ciphertext = num_bits_in_message
            .checked_mul(original_num_blocks as u32)
            .expect("Number of bits encrypted exceeds u32::MAX");

        // `num_bits_in_ciphertext-1` is the max value we want to represent
        // its ilog2 + 1 gives use how many bits we need to be able to represent it.
        // We add `1` to this number as we are going to use signed numbers later
        //
        // The ilog2 of a number that is on n bits, is in range 1..=n-1
        let counter_num_blocks = ((num_bits_in_ciphertext - 1).ilog2() + 1 + 1)
            .div_ceil(self.message_modulus.0.ilog2()) as usize;

        // 11111000
        // x.ilog2() = (x.num_bit() - 1) - x.leading_zeros()
        // - (x.num_bit() - 1) is trivially known
        // - we can get leading zeros via a sum
        //
        // However, the sum include a full propagation, thus the subtraction
        // will add another full propagation which is costly.
        //
        // However, we can do better:
        // let N = (x.num_bit() - 1)
        // let L0 = x.leading_zeros()
        // ```
        // x.ilog2() = N - L0
        // x.ilog2() = -(-(N - L0))
        // x.ilog2() = -(-N + L0)
        // ```
        // Since N is a clear number, getting -N is free,
        // meaning -N + L0 where L0 is actually `sum(L0[b0], .., L0[num_blocks-1])`
        // can be done with `sum(-N, L0[b0], .., L0[num_blocks-1]), by switching to signed
        // numbers.
        //
        // Also, to do -(-N + L0) aka -sum(-N, L0[b0], .., L0[num_blocks-1])
        // we can make the sum not return a fully propagated result,
        // and extract message/carry blocks while negating them at the same time
        // using the fact that in twos complement -X = bitnot(X) + 1
        // so given a non propagated `C`, we can compute the fully propagated `PC`
        // PC = bitnot(message(C)) + bitnot(blockshift(carry(C), 1)) + 2

        let mut leading_zeros_per_blocks = self.prepare_count_of_consecutive_bits_async(
            ct,
            Direction::Leading,
            BitValue::Zero,
            streams,
        );
        let lwe_dimension = ct.as_ref().d_blocks.lwe_dimension();

        let lwe_size = lwe_dimension.to_lwe_size().0;
        let capacity = leading_zeros_per_blocks
            .as_ref()
            .d_blocks
            .lwe_ciphertext_count()
            .0
            + 1;
        let mut cts = Vec::<CudaSignedRadixCiphertext>::with_capacity(capacity);

        for i in 0..(capacity - 1) {
            let mut new_item: CudaSignedRadixCiphertext =
                self.create_trivial_zero_radix_async(counter_num_blocks, streams);

            let mut dest_slice = new_item
                .as_mut()
                .d_blocks
                .0
                .d_vec
                .as_mut_slice(0..lwe_size, 0)
                .unwrap();

            let src_slice = leading_zeros_per_blocks
                .as_mut()
                .d_blocks
                .0
                .d_vec
                .as_mut_slice((i * lwe_size)..((i + 1) * lwe_size), 0)
                .unwrap();
            dest_slice.copy_from_gpu_async(&src_slice, streams, 0);
            let b = new_item.ciphertext.info.blocks.first_mut().unwrap();
            b.degree = leading_zeros_per_blocks
                .as_ref()
                .info
                .blocks
                .get(i)
                .unwrap()
                .degree;
            b.noise_level = leading_zeros_per_blocks
                .as_ref()
                .info
                .blocks
                .get(i)
                .unwrap()
                .noise_level;
            cts.push(new_item);
        }

        let new_trivial: CudaSignedRadixCiphertext = self.create_trivial_radix_async(
            -(num_bits_in_ciphertext as i32 - 1i32),
            counter_num_blocks,
            streams,
        );

        cts.push(new_trivial);

        let result = self
            .unchecked_partial_sum_ciphertexts_async(&cts, streams)
            .expect("internal error, empty ciphertext count");

        // This is the part where we extract message and carry blocks
        // while inverting their bits
        let lut_a = self.generate_lookup_table(|x| {
            // extract message
            let x = x % self.message_modulus.0;
            // bitnot the message
            (!x) % self.message_modulus.0
        });

        let mut message_blocks: CudaSignedRadixCiphertext =
            self.create_trivial_zero_radix(counter_num_blocks, streams);
        self.apply_lookup_table_async(
            message_blocks.as_mut(),
            result.as_ref(),
            &lut_a,
            0..counter_num_blocks,
            streams,
        );

        let lut_b = self.generate_lookup_table(|x| {
            // extract carry
            let x = x / self.message_modulus.0;
            // bitnot the carry
            (!x) % self.message_modulus.0
        });

        let mut carry_blocks: CudaSignedRadixCiphertext =
            self.create_trivial_zero_radix(counter_num_blocks, streams);

        let mut trivial_last_block: CudaSignedRadixCiphertext =
            self.create_trivial_radix_async(self.message_modulus.0 - 1, 1, streams);
        let trivial_last_block_slice = trivial_last_block
            .as_mut()
            .d_blocks
            .0
            .d_vec
            .as_mut_slice(0..lwe_size, 0)
            .unwrap();

        let mut carry_blocks_last = carry_blocks
            .as_mut()
            .d_blocks
            .0
            .d_vec
            .as_mut_slice(
                lwe_size * (counter_num_blocks - 1)..lwe_size * counter_num_blocks,
                0,
            )
            .unwrap();

        carry_blocks_last.copy_from_gpu_async(&trivial_last_block_slice, streams, 0);
        carry_blocks.as_mut().info.blocks.last_mut().unwrap().degree =
            Degree(self.message_modulus.0 - 1);
        carry_blocks
            .as_mut()
            .info
            .blocks
            .last_mut()
            .unwrap()
            .noise_level = NoiseLevel::ZERO;

        self.apply_lookup_table_async(
            carry_blocks.as_mut(),
            result.as_ref(),
            &lut_b,
            0..counter_num_blocks - 1,
            streams,
        );

        let mut ciphertexts = Vec::<CudaSignedRadixCiphertext>::with_capacity(3);

        ciphertexts.push(message_blocks);
        ciphertexts.push(carry_blocks);

        let trivial_ct: CudaSignedRadixCiphertext =
            self.create_trivial_radix_async(2u32, counter_num_blocks, streams);
        ciphertexts.push(trivial_ct);

        let result = self.sum_ciphertexts_async(ciphertexts, streams).unwrap();

        self.cast_to_unsigned_async(result, counter_num_blocks, streams)
    }

    /// Returns the number of trailing zeros in the binary representation of `ct`
    ///
    /// The returned Ciphertexts has a variable size
    /// i.e. It contains just the minimum number of block
    /// needed to represent the maximum possible number of bits.
    ///
    /// This is a default function, it will internally clone the ciphertext if it has
    /// non propagated carries, and it will output a ciphertext without any carries.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gpu::ciphertext::CudaSignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_gpu;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    /// let number_of_blocks = 4;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, &streams);
    ///
    /// let msg = -4i8;
    ///
    /// // Encrypt two messages
    /// let ctxt = cks.encrypt_signed_radix(msg, number_of_blocks);
    ///
    /// let d_ctxt = CudaSignedRadixCiphertext::from_signed_radix_ciphertext(&ctxt, &streams);
    ///
    /// // Compute homomorphically trailing zeros
    /// let d_ct_res = sks.trailing_zeros(&d_ctxt, &streams);
    ///
    /// // Decrypt
    /// let ct_res = d_ct_res.to_radix_ciphertext(&streams);
    /// let res: u32 = cks.decrypt_radix(&ct_res);
    /// assert_eq!(res, msg.trailing_zeros());
    /// ```
    pub fn trailing_zeros<T>(&self, ct: &T, streams: &CudaStreams) -> CudaUnsignedRadixCiphertext
    where
        T: CudaIntegerRadixCiphertext,
    {
        let res = unsafe { self.trailing_zeros_async(ct, streams) };
        streams.synchronize();
        res
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronised
    pub unsafe fn trailing_zeros_async<T>(
        &self,
        ct: &T,
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext
    where
        T: CudaIntegerRadixCiphertext,
    {
        let mut tmp;
        let ct = if ct.block_carries_are_empty() {
            ct
        } else {
            tmp = ct.duplicate_async(streams);
            self.full_propagate_assign_async(&mut tmp, streams);
            &tmp
        };
        self.unchecked_trailing_zeros_async(ct, streams)
    }

    /// Returns the number of trailing ones in the binary representation of `ct`
    ///
    /// The returned Ciphertexts has a variable size
    /// i.e. It contains just the minimum number of block
    /// needed to represent the maximum possible number of bits.
    ///
    /// This is a default function, it will internally clone the ciphertext if it has
    /// non propagated carries, and it will output a ciphertext without any carries.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gpu::ciphertext::CudaSignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_gpu;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    /// let number_of_blocks = 4;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, &streams);
    ///
    /// let msg = -4i8;
    ///
    /// // Encrypt two messages
    /// let ctxt = cks.encrypt_signed_radix(msg, number_of_blocks);
    ///
    /// let d_ctxt = CudaSignedRadixCiphertext::from_signed_radix_ciphertext(&ctxt, &streams);
    ///
    /// // Compute homomorphically trailing ones
    /// let d_ct_res = sks.trailing_ones(&d_ctxt, &streams);
    ///
    /// // Decrypt
    /// let ct_res = d_ct_res.to_radix_ciphertext(&streams);
    /// let res: u32 = cks.decrypt_radix(&ct_res);
    /// assert_eq!(res, msg.trailing_ones());
    /// ```
    pub fn trailing_ones<T>(&self, ct: &T, streams: &CudaStreams) -> CudaUnsignedRadixCiphertext
    where
        T: CudaIntegerRadixCiphertext,
    {
        let res = unsafe { self.trailing_ones_async(ct, streams) };
        streams.synchronize();
        res
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronised
    pub unsafe fn trailing_ones_async<T>(
        &self,
        ct: &T,
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext
    where
        T: CudaIntegerRadixCiphertext,
    {
        let mut tmp;
        let ct = if ct.block_carries_are_empty() {
            ct
        } else {
            tmp = ct.duplicate_async(streams);
            self.full_propagate_assign_async(&mut tmp, streams);
            &tmp
        };
        self.unchecked_trailing_ones_async(ct, streams)
    }

    /// Returns the number of leading zeros in the binary representation of `ct`
    ///
    /// The returned Ciphertexts has a variable size
    /// i.e. It contains just the minimum number of block
    /// needed to represent the maximum possible number of bits.
    ///
    /// This is a default function, it will internally clone the ciphertext if it has
    /// non propagated carries, and it will output a ciphertext without any carries.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gpu::ciphertext::CudaSignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_gpu;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    /// let number_of_blocks = 4;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, &streams);
    ///
    /// let msg = -4i8;
    ///
    /// // Encrypt two messages
    /// let ctxt = cks.encrypt_signed_radix(msg, number_of_blocks);
    ///
    /// let d_ctxt = CudaSignedRadixCiphertext::from_signed_radix_ciphertext(&ctxt, &streams);
    ///
    /// // Compute homomorphically leading zeros
    /// let d_ct_res = sks.leading_zeros(&d_ctxt, &streams);
    ///
    /// // Decrypt
    /// let ct_res = d_ct_res.to_radix_ciphertext(&streams);
    /// let res: u32 = cks.decrypt_radix(&ct_res);
    /// assert_eq!(res, msg.leading_zeros());
    /// ```
    pub fn leading_zeros<T>(&self, ct: &T, streams: &CudaStreams) -> CudaUnsignedRadixCiphertext
    where
        T: CudaIntegerRadixCiphertext,
    {
        let res = unsafe { self.leading_zeros_async(ct, streams) };
        streams.synchronize();
        res
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronised
    pub unsafe fn leading_zeros_async<T>(
        &self,
        ct: &T,
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext
    where
        T: CudaIntegerRadixCiphertext,
    {
        let mut tmp;
        let ct = if ct.block_carries_are_empty() {
            ct
        } else {
            tmp = ct.duplicate_async(streams);
            self.full_propagate_assign_async(&mut tmp, streams);
            &tmp
        };
        self.unchecked_leading_zeros_async(ct, streams)
    }

    /// Returns the number of leading ones in the binary representation of `ct`
    ///
    /// The returned Ciphertexts has a variable size
    /// i.e. It contains just the minimum number of block
    /// needed to represent the maximum possible number of bits.
    ///
    /// This is a default function, it will internally clone the ciphertext if it has
    /// non propagated carries, and it will output a ciphertext without any carries.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gpu::ciphertext::CudaSignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_gpu;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    /// let number_of_blocks = 4;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, &streams);
    ///
    /// let msg = -4i8;
    ///
    /// // Encrypt two messages
    /// let ctxt = cks.encrypt_signed_radix(msg, number_of_blocks);
    ///
    /// let d_ctxt = CudaSignedRadixCiphertext::from_signed_radix_ciphertext(&ctxt, &streams);
    ///
    /// // Compute homomorphically leading ones
    /// let d_ct_res = sks.leading_ones(&d_ctxt, &streams);
    ///
    /// // Decrypt
    /// let ct_res = d_ct_res.to_radix_ciphertext(&streams);
    /// let res: u32 = cks.decrypt_radix(&ct_res);
    /// assert_eq!(res, msg.leading_ones());
    /// ```
    pub fn leading_ones<T>(&self, ct: &T, streams: &CudaStreams) -> CudaUnsignedRadixCiphertext
    where
        T: CudaIntegerRadixCiphertext,
    {
        let res = unsafe { self.leading_ones_async(ct, streams) };
        streams.synchronize();
        res
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronised
    pub unsafe fn leading_ones_async<T>(
        &self,
        ct: &T,
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext
    where
        T: CudaIntegerRadixCiphertext,
    {
        let mut tmp;
        let ct = if ct.block_carries_are_empty() {
            ct
        } else {
            tmp = ct.duplicate_async(streams);
            self.full_propagate_assign_async(&mut tmp, streams);
            &tmp
        };
        self.unchecked_leading_ones_async(ct, streams)
    }

    /// Returns the base 2 logarithm of the number, rounded down.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gpu::ciphertext::CudaSignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_gpu;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    /// let number_of_blocks = 4;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, &streams);
    ///
    /// let msg = 5i8;
    ///
    /// // Encrypt two messages
    /// let ctxt = cks.encrypt_signed_radix(msg, number_of_blocks);
    ///
    /// let d_ctxt = CudaSignedRadixCiphertext::from_signed_radix_ciphertext(&ctxt, &streams);
    ///
    /// // Compute homomorphically a log2
    /// let d_ct_res = sks.ilog2(&d_ctxt, &streams);
    ///
    /// // Decrypt
    /// let ct_res = d_ct_res.to_radix_ciphertext(&streams);
    /// let res: u32 = cks.decrypt_radix(&ct_res);
    /// assert_eq!(res, msg.ilog2());
    /// ```
    pub fn ilog2<T>(&self, ct: &T, streams: &CudaStreams) -> CudaUnsignedRadixCiphertext
    where
        T: CudaIntegerRadixCiphertext,
    {
        let res = unsafe { self.ilog2_async(ct, streams) };
        streams.synchronize();
        res
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronised
    pub unsafe fn ilog2_async<T>(
        &self,
        ct: &T,
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext
    where
        T: CudaIntegerRadixCiphertext,
    {
        let mut tmp;
        let ct = if ct.block_carries_are_empty() {
            ct
        } else {
            tmp = ct.duplicate_async(streams);
            self.full_propagate_assign_async(&mut tmp, streams);
            &tmp
        };

        self.unchecked_ilog2_async(ct, streams)
    }

    /// Returns the base 2 logarithm of the number, rounded down.
    ///
    /// Also returns a BooleanBlock, encrypting true (1) if the result is
    /// valid (input is > 0), otherwise 0.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gpu::ciphertext::CudaSignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_gpu;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    /// let number_of_blocks = 4;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, &streams);
    ///
    /// let msg = 5i8;
    ///
    /// // Encrypt two messages
    /// let ctxt = cks.encrypt_signed_radix(msg, number_of_blocks);
    ///
    /// let d_ctxt = CudaSignedRadixCiphertext::from_signed_radix_ciphertext(&ctxt, &streams);
    /// // Compute homomorphically a log2 and a check if input is valid
    /// let (d_ct_res, d_is_oks) = sks.checked_ilog2(&d_ctxt, &streams);
    ///
    /// // Decrypt
    /// let ct_res = d_ct_res.to_radix_ciphertext(&streams);
    /// let res: u32 = cks.decrypt_radix(&ct_res);
    /// assert_eq!(res, msg.ilog2());
    /// let is_oks = d_is_oks.to_boolean_block(&streams);
    /// let is_ok = cks.decrypt_bool(&is_oks);
    /// assert!(is_ok);
    pub fn checked_ilog2<T>(
        &self,
        ct: &T,
        streams: &CudaStreams,
    ) -> (CudaUnsignedRadixCiphertext, CudaBooleanBlock)
    where
        T: CudaIntegerRadixCiphertext,
    {
        let res = unsafe { self.checked_ilog2_async(ct, streams) };
        streams.synchronize();
        res
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronised
    pub unsafe fn checked_ilog2_async<T>(
        &self,
        ct: &T,
        streams: &CudaStreams,
    ) -> (CudaUnsignedRadixCiphertext, CudaBooleanBlock)
    where
        T: CudaIntegerRadixCiphertext,
    {
        let mut tmp;
        let ct = if ct.block_carries_are_empty() {
            ct
        } else {
            tmp = ct.duplicate_async(streams);
            self.full_propagate_assign_async(&mut tmp, streams);
            &tmp
        };

        (
            self.ilog2_async(ct, streams),
            self.scalar_gt_async(ct, 0, streams),
        )
    }
}
