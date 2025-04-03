use crate::core_crypto::commons::numeric::UnsignedInteger;
use crate::integer::ciphertext::IntegerRadixCiphertext;
use crate::integer::{BooleanBlock, RadixCiphertext, ServerKey, SignedRadixCiphertext};
use crate::shortint::ciphertext::Degree;
use crate::shortint::Ciphertext;
use rayon::prelude::*;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(crate) enum CarryPropagationAlgorithm {
    Sequential,
    Parallel,
    Automatic,
}
/// Possible output flag that the advanced_add_assign_with_carry family of
/// functions can compute.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(crate) enum OutputFlag {
    /// Request no flag at all
    None,
    /// The overflow flag is the flag that tells whether the input carry bit onto the last bit
    /// is different from the output bit.
    ///
    /// This is useful to know if a signed addition overflowed (in 2's complement)
    Overflow,
    /// The carry flag is simply the carry bit that the output from the last pair of blocks
    /// in an addition.
    ///
    /// This is useful to know if an unsigned addition overflowed.
    Carry,
}

impl OutputFlag {
    /// Returns which flag shall be computed in order to get the flag
    /// telling the overflow status
    pub(crate) const fn from_signedness(is_signed: bool) -> Self {
        if is_signed {
            Self::Overflow
        } else {
            Self::Carry
        }
    }
}

fn should_parallel_propagation_be_faster(
    full_modulus: u64,
    num_blocks: usize,
    num_threads: usize,
) -> bool {
    const PARALLEL_LATENCY_PENALTY: usize = 1;
    // However that penalty only kicks in when certain level of
    // parallelism is used
    let penalty_threshold = num_threads / 2;

    // The unit of latency is a PBS
    let compute_latency_of_one_layer = |num_blocks: usize, num_threads: usize| -> usize {
        let latency = num_blocks.div_ceil(num_threads);
        if num_blocks >= penalty_threshold {
            latency * PARALLEL_LATENCY_PENALTY
        } else {
            latency
        }
    };

    // Estimate the latency of the parallelized algorithm
    // One pre-processing layer, one layer to compute what happens in each grouping,
    // one final post processing layer
    let mut parallel_expected_latency = 3 * compute_latency_of_one_layer(num_blocks, num_threads);

    let grouping_size = full_modulus.ilog2();
    let num_groups = num_blocks.div_ceil(grouping_size as usize);

    let num_carry_to_resolve = num_groups.saturating_sub(1);

    let sequential_depth = (num_carry_to_resolve.saturating_sub(1) as u32) / (grouping_size - 1);
    let hillis_steel_depth = if num_carry_to_resolve == 0 {
        0
    } else {
        num_carry_to_resolve.ceil_ilog2()
    };

    let parallel_algo_uses_sequential_to_resolve_grouping_carries =
        sequential_depth <= hillis_steel_depth;

    if parallel_algo_uses_sequential_to_resolve_grouping_carries {
        parallel_expected_latency += sequential_depth as usize
            * compute_latency_of_one_layer(grouping_size as usize, num_threads);
    } else {
        let max_depth = num_blocks.ceil_ilog2();
        let mut space = 1;
        for _ in 0..max_depth {
            let num_block_at_iter = num_blocks - space;
            let iter_latency = compute_latency_of_one_layer(num_block_at_iter, num_threads);
            parallel_expected_latency += iter_latency;
            space *= 2;
        }
    }

    // the other algorithm has num_blocks latency
    parallel_expected_latency < num_blocks
}

impl ServerKey {
    pub fn unchecked_add_parallelized<T>(&self, lhs: &T, rhs: &T) -> T
    where
        T: IntegerRadixCiphertext,
    {
        let mut result = lhs.clone();
        self.unchecked_add_assign_parallelized(&mut result, rhs);
        result
    }

    pub fn unchecked_add_assign_parallelized<T>(&self, lhs: &mut T, rhs: &T)
    where
        T: IntegerRadixCiphertext,
    {
        lhs.blocks_mut()
            .par_iter_mut()
            .zip(rhs.blocks().par_iter())
            .for_each(|(ct_left_i, ct_right_i)| {
                self.key.unchecked_add_assign(ct_left_i, ct_right_i);
            });
    }

    /// Computes homomorphically an addition between two ciphertexts encrypting integer values.
    ///
    /// # Warning
    ///
    /// - Multithreaded
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    ///
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, num_blocks);
    ///
    /// let msg1 = 14;
    /// let msg2 = 97;
    ///
    /// let mut ct1 = cks.encrypt(msg1);
    /// let mut ct2 = cks.encrypt(msg2);
    ///
    /// // Compute homomorphically an addition:
    /// let ct_res = sks.smart_add_parallelized(&mut ct1, &mut ct2);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, msg1 + msg2);
    /// ```
    pub fn smart_add_parallelized<T>(&self, ct_left: &mut T, ct_right: &mut T) -> T
    where
        T: IntegerRadixCiphertext,
    {
        if self.is_add_possible(ct_left, ct_right).is_err() {
            rayon::join(
                || self.full_propagate_parallelized(ct_left),
                || self.full_propagate_parallelized(ct_right),
            );
        }

        self.is_add_possible(ct_left, ct_right).unwrap();
        self.unchecked_add(ct_left, ct_right)
    }

    pub fn smart_add_assign_parallelized<T>(&self, ct_left: &mut T, ct_right: &mut T)
    where
        T: IntegerRadixCiphertext,
    {
        if self.is_add_possible(ct_left, ct_right).is_err() {
            rayon::join(
                || self.full_propagate_parallelized(ct_left),
                || self.full_propagate_parallelized(ct_right),
            );
        }

        self.is_add_possible(ct_left, ct_right).unwrap();
        self.unchecked_add_assign(ct_left, ct_right);
    }

    /// Computes homomorphically an addition between two ciphertexts encrypting integer values.
    ///
    /// This function, like all "default" operations (i.e. not smart, checked or unchecked), will
    /// check that the input ciphertexts block carries are empty and clears them if it's not the
    /// case and the operation requires it. It outputs a ciphertext whose block carries are always
    /// empty.
    ///
    /// This means that when using only "default" operations, a given operation (like add for
    /// example) has always the same performance characteristics from one call to another and
    /// guarantees correctness by pre-emptively clearing carries of output ciphertexts.
    ///
    /// # Warning
    ///
    /// - Multithreaded
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    ///
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, num_blocks);
    ///
    /// let msg1 = 14;
    /// let msg2 = 97;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Compute homomorphically an addition:
    /// let ct_res = sks.add_parallelized(&ct1, &ct2);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, msg1 + msg2);
    /// ```
    pub fn add_parallelized<T>(&self, ct_left: &T, ct_right: &T) -> T
    where
        T: IntegerRadixCiphertext,
    {
        let mut ct_res = ct_left.clone();
        self.add_assign_parallelized(&mut ct_res, ct_right);
        ct_res
    }

    pub fn add_assign_parallelized<T>(&self, ct_left: &mut T, ct_right: &T)
    where
        T: IntegerRadixCiphertext,
    {
        let mut tmp_rhs: T;

        let (lhs, rhs) = match (
            ct_left.block_carries_are_empty(),
            ct_right.block_carries_are_empty(),
        ) {
            (true, true) => (ct_left, ct_right),
            (true, false) => {
                tmp_rhs = ct_right.clone();
                self.full_propagate_parallelized(&mut tmp_rhs);
                (ct_left, &tmp_rhs)
            }
            (false, true) => {
                self.full_propagate_parallelized(ct_left);
                (ct_left, ct_right)
            }
            (false, false) => {
                tmp_rhs = ct_right.clone();
                rayon::join(
                    || self.full_propagate_parallelized(ct_left),
                    || self.full_propagate_parallelized(&mut tmp_rhs),
                );
                (ct_left, &tmp_rhs)
            }
        };

        self.add_assign_with_carry_parallelized(lhs, rhs, None);
    }

    /// Computes the addition of two ciphertexts and returns the overflow flag
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    ///
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, num_blocks);
    ///
    /// let msg1 = u8::MAX;
    /// let msg2 = 1;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// let (ct_res, overflowed) = sks.unsigned_overflowing_add_parallelized(&ct1, &ct2);
    ///
    /// // Decrypt:
    /// let dec_result: u8 = cks.decrypt(&ct_res);
    /// let dec_overflowed = cks.decrypt_bool(&overflowed);
    /// let (expected_result, expected_overflow) = msg1.overflowing_add(msg2);
    /// assert_eq!(dec_result, expected_result);
    /// assert_eq!(dec_overflowed, expected_overflow);
    /// ```
    pub fn overflowing_add_parallelized<T>(&self, ct_left: &T, ct_right: &T) -> (T, BooleanBlock)
    where
        T: IntegerRadixCiphertext,
    {
        let mut ct_res = ct_left.clone();
        let overflowed = self.overflowing_add_assign_parallelized(&mut ct_res, ct_right);
        (ct_res, overflowed)
    }

    pub fn overflowing_add_assign_parallelized<T>(
        &self,
        ct_left: &mut T,
        ct_right: &T,
    ) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
    {
        let mut tmp_rhs: T;
        if ct_left.blocks().is_empty() || ct_right.blocks().is_empty() {
            return self.create_trivial_boolean_block(false);
        }

        let (lhs, rhs) = match (
            ct_left.block_carries_are_empty(),
            ct_right.block_carries_are_empty(),
        ) {
            (true, true) => (ct_left, ct_right),
            (true, false) => {
                tmp_rhs = ct_right.clone();
                self.full_propagate_parallelized(&mut tmp_rhs);
                (ct_left, &tmp_rhs)
            }
            (false, true) => {
                self.full_propagate_parallelized(ct_left);
                (ct_left, ct_right)
            }
            (false, false) => {
                tmp_rhs = ct_right.clone();
                rayon::join(
                    || self.full_propagate_parallelized(ct_left),
                    || self.full_propagate_parallelized(&mut tmp_rhs),
                );
                (ct_left, &tmp_rhs)
            }
        };

        self.overflowing_add_assign_with_carry(lhs, rhs, None)
    }

    /// Computes the addition of two unsigned ciphertexts and returns the overflow flag
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    ///
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, num_blocks);
    ///
    /// let msg1 = u8::MAX;
    /// let msg2 = 1;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// let (ct_res, overflowed) = sks.unsigned_overflowing_add_parallelized(&ct1, &ct2);
    ///
    /// // Decrypt:
    /// let dec_result: u8 = cks.decrypt(&ct_res);
    /// let dec_overflowed = cks.decrypt_bool(&overflowed);
    /// let (expected_result, expected_overflow) = msg1.overflowing_add(msg2);
    /// assert_eq!(dec_result, expected_result);
    /// assert_eq!(dec_overflowed, expected_overflow);
    /// ```
    pub fn unsigned_overflowing_add_parallelized(
        &self,
        ct_left: &RadixCiphertext,
        ct_right: &RadixCiphertext,
    ) -> (RadixCiphertext, BooleanBlock) {
        self.overflowing_add_parallelized(ct_left, ct_right)
    }

    pub fn unsigned_overflowing_add_assign_parallelized(
        &self,
        ct_left: &mut RadixCiphertext,
        ct_right: &RadixCiphertext,
    ) -> BooleanBlock {
        self.overflowing_add_assign_parallelized(ct_left, ct_right)
    }

    pub fn signed_overflowing_add_parallelized(
        &self,
        ct_left: &SignedRadixCiphertext,
        ct_right: &SignedRadixCiphertext,
    ) -> (SignedRadixCiphertext, BooleanBlock) {
        self.overflowing_add_parallelized(ct_left, ct_right)
    }

    pub fn unchecked_signed_overflowing_add_parallelized(
        &self,
        ct_left: &SignedRadixCiphertext,
        ct_right: &SignedRadixCiphertext,
    ) -> (SignedRadixCiphertext, BooleanBlock) {
        assert_eq!(
            ct_left.blocks.len(),
            ct_right.blocks.len(),
            "lhs and rhs must have the name number of blocks ({} vs {})",
            ct_left.blocks.len(),
            ct_right.blocks.len()
        );
        assert!(!ct_left.blocks.is_empty(), "inputs cannot be empty");

        let mut result = ct_left.clone();
        let overflowed = self.overflowing_add_assign_with_carry(&mut result, ct_right, None);
        (result, overflowed)
    }

    pub(crate) fn is_eligible_for_parallel_single_carry_propagation(
        &self,
        num_blocks: usize,
    ) -> bool {
        // having 4-bits is a hard requirement
        // as the parallel implementation uses a bivariate BPS where individual values need
        // 2 bits
        let total_modulus = self.key.message_modulus.0 * self.key.carry_modulus.0;
        let has_enough_bits_per_block = total_modulus >= (1 << 4);
        if !has_enough_bits_per_block {
            return false;
        }

        should_parallel_propagation_be_faster(
            self.message_modulus().0 * self.carry_modulus().0,
            num_blocks,
            rayon::current_num_threads(),
        )
    }

    /// Does lhs += (rhs + carry)
    pub fn add_assign_with_carry_parallelized<T>(
        &self,
        lhs: &mut T,
        rhs: &T,
        input_carry: Option<&BooleanBlock>,
    ) where
        T: IntegerRadixCiphertext,
    {
        if !lhs.block_carries_are_empty() {
            self.full_propagate_parallelized(lhs);
        }

        let mut cloned_rhs;

        let rhs = if rhs.block_carries_are_empty() {
            rhs
        } else {
            cloned_rhs = rhs.clone();
            self.full_propagate_parallelized(&mut cloned_rhs);
            &cloned_rhs
        };

        self.advanced_add_assign_with_carry_parallelized(
            lhs.blocks_mut(),
            rhs.blocks(),
            input_carry,
            OutputFlag::None,
            CarryPropagationAlgorithm::Automatic,
        );
    }

    /// Does lhs += (rhs + carry)
    ///
    /// Returns a boolean block that encrypts `true` if overflow happened
    pub fn overflowing_add_assign_with_carry<T>(
        &self,
        lhs: &mut T,
        rhs: &T,
        input_carry: Option<&BooleanBlock>,
    ) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
    {
        self.advanced_add_assign_with_carry_parallelized(
            lhs.blocks_mut(),
            rhs.blocks(),
            input_carry,
            OutputFlag::from_signedness(T::IS_SIGNED),
            CarryPropagationAlgorithm::Automatic,
        )
        .expect("internal error, overflow computation was not returned as was requested")
    }

    pub(crate) fn propagate_single_carry_parallelized(&self, radix: &mut [Ciphertext]) {
        self.advanced_add_assign_with_carry_at_least_4_bits(radix, &[], None, OutputFlag::None);
    }

    /// Computes the result of `lhs += rhs + input_carry`
    ///
    /// This will select what seems to be the best algorithm to propagate carries
    /// (fully parallel vs sequential) by looking at the number of blocks and
    /// number of threads.
    ///
    /// - `lhs` and `rhs` must have the same `len()`, empty is allowed
    /// - `blocks of lhs` and `rhs` must all be without carry
    /// - blocks must have at least one bit of message and one bit of carry
    ///
    /// Returns `Some(...)` if requested_flag != ComputationFlags::None
    pub(crate) fn advanced_add_assign_with_carry_parallelized(
        &self,
        lhs: &mut [Ciphertext],
        rhs: &[Ciphertext],
        input_carry: Option<&BooleanBlock>,
        requested_flag: OutputFlag,
        mut algorithm: CarryPropagationAlgorithm,
    ) -> Option<BooleanBlock> {
        // having 4-bits is a hard requirement
        // So to protect against bad carry prop choice we do this check
        let total_modulus = self.key.message_modulus.0 * self.key.carry_modulus.0;
        let has_enough_bits_per_block = total_modulus >= (1 << 4);
        if !has_enough_bits_per_block {
            algorithm = CarryPropagationAlgorithm::Sequential;
        }

        if algorithm == CarryPropagationAlgorithm::Automatic {
            if should_parallel_propagation_be_faster(
                self.message_modulus().0 * self.carry_modulus().0,
                lhs.len(),
                rayon::current_num_threads(),
            ) {
                algorithm = CarryPropagationAlgorithm::Parallel;
            } else {
                algorithm = CarryPropagationAlgorithm::Sequential
            }
        }
        match algorithm {
            CarryPropagationAlgorithm::Parallel => self
                .advanced_add_assign_with_carry_at_least_4_bits(
                    lhs,
                    rhs,
                    input_carry,
                    requested_flag,
                ),
            CarryPropagationAlgorithm::Sequential => self
                .advanced_add_assign_with_carry_sequential_parallelized(
                    lhs,
                    rhs,
                    input_carry,
                    requested_flag,
                ),
            CarryPropagationAlgorithm::Automatic => unreachable!(),
        }
    }

    /// Computes the result of `lhs += rhs + input_carry`
    ///
    /// This uses the sequential algorithm to propagate the carries
    ///
    /// - `lhs` and `rhs` must have the same `len()`, empty is allowed
    /// - `blocks of lhs` and `rhs` must all be without carry
    /// - blocks must have at least one bit of message and one bit of carry
    ///
    /// Returns `Some(...)` if requested_flag != ComputationFlags::None
    pub(crate) fn advanced_add_assign_with_carry_sequential_parallelized(
        &self,
        lhs: &mut [Ciphertext],
        rhs: &[Ciphertext],
        input_carry: Option<&BooleanBlock>,
        requested_flag: OutputFlag,
    ) -> Option<BooleanBlock> {
        assert_eq!(
            lhs.len(),
            rhs.len(),
            "Both operands must have the same number of blocks"
        );

        if lhs.is_empty() {
            return if requested_flag == OutputFlag::None {
                None
            } else {
                Some(self.create_trivial_boolean_block(false))
            };
        }

        let carry =
            input_carry.map_or_else(|| self.create_trivial_boolean_block(false), Clone::clone);

        // 2_2, 3_3, 4_4
        // If we have at least 2 bits and at least as much carries
        //
        // The num blocks == 1 + requested_flag == OverflowFlag will actually result in one more
        // PBS of latency than num_blocks == 1 && requested_flag != OverflowFlag
        //
        // It happens because the computation of the overflow flag requires 2 steps,
        // and we insert these two steps in parallel to normal carry propagation.
        // The first step is done when processing the first block,
        // the second step is done when processing the last block.
        // So if the number of block is smaller than 2 then,
        // the overflow computation adds additional layer of PBS.
        if self.key.message_modulus.0 >= 4 && self.key.carry_modulus.0 >= self.key.message_modulus.0
        {
            self.advanced_add_assign_sequential_at_least_4_bits(
                requested_flag,
                lhs,
                rhs,
                carry,
                input_carry,
            )
        } else if self.key.message_modulus.0 == 2
            && self.key.carry_modulus.0 >= self.key.message_modulus.0
        {
            self.advanced_add_assign_sequential_at_least_2_bits(lhs, rhs, carry, requested_flag)
        } else {
            panic!(
                "Invalid combo of message modulus ({}) and carry modulus ({}) \n\
                This function requires the message modulus >= 2 and carry modulus >= message_modulus \n\
                I.e. PARAM_MESSAGE_X_CARRY_Y where X >= 1 and Y >= X.",
                self.key.message_modulus.0, self.key.carry_modulus.0
            );
        }
    }

    /// Computes lhs += (rhs + carry) using the sequential propagation of carries
    ///
    /// parameters of blocks must have 4 bits, parameters in the form X_Y where X >= 2 && Y >= X
    fn advanced_add_assign_sequential_at_least_4_bits(
        &self,
        requested_flag: OutputFlag,
        lhs: &mut [Ciphertext],
        rhs: &[Ciphertext],
        carry: BooleanBlock,
        input_carry: Option<&BooleanBlock>,
    ) -> Option<BooleanBlock> {
        let mut carry = carry.0;

        let mut overflow_flag = if requested_flag == OutputFlag::Overflow {
            let mut block = self
                .key
                .unchecked_scalar_mul(lhs.last().as_ref().unwrap(), self.message_modulus().0 as u8);
            self.key
                .unchecked_add_assign(&mut block, rhs.last().as_ref().unwrap());
            Some(block)
        } else {
            None
        };

        // Handle the first block
        self.key.unchecked_add_assign(&mut lhs[0], &rhs[0]);
        self.key.unchecked_add_assign(&mut lhs[0], &carry);

        // To be able to use carry_extract_assign in it
        carry.clone_from(&lhs[0]);
        rayon::scope(|s| {
            s.spawn(|_| {
                self.key.message_extract_assign(&mut lhs[0]);
            });

            s.spawn(|_| {
                self.key.carry_extract_assign(&mut carry);
            });

            if requested_flag == OutputFlag::Overflow {
                s.spawn(|_| {
                    // Computing the overflow flag requires an extra step for the first block

                    let overflow_flag = overflow_flag.as_mut().unwrap();
                    let num_bits_in_message = self.message_modulus().0.ilog2() as u64;
                    let lut = self.key.generate_lookup_table(|lhs_rhs| {
                        let lhs = lhs_rhs / self.message_modulus().0;
                        let rhs = lhs_rhs % self.message_modulus().0;
                        overflow_flag_preparation_lut(lhs, rhs, num_bits_in_message)
                    });
                    self.key.apply_lookup_table_assign(overflow_flag, &lut);
                });
            }
        });

        let num_blocks = lhs.len();

        // We did the first block before, the last block is done after this if,
        // so we need 3 blocks at least to enter this
        if num_blocks >= 3 {
            for (lhs_b, rhs_b) in lhs[1..num_blocks - 1]
                .iter_mut()
                .zip(rhs[1..num_blocks - 1].iter())
            {
                self.key.unchecked_add_assign(lhs_b, rhs_b);
                self.key.unchecked_add_assign(lhs_b, &carry);

                carry.clone_from(lhs_b);
                rayon::join(
                    || self.key.message_extract_assign(lhs_b),
                    || self.key.carry_extract_assign(&mut carry),
                );
            }
        }

        if num_blocks >= 2 {
            // Handle the last block
            self.key
                .unchecked_add_assign(&mut lhs[num_blocks - 1], &rhs[num_blocks - 1]);
            self.key
                .unchecked_add_assign(&mut lhs[num_blocks - 1], &carry);
        }

        if let Some(block) = overflow_flag.as_mut() {
            if num_blocks == 1 && input_carry.is_some() {
                self.key
                    .unchecked_add_assign(block, input_carry.map(|b| &b.0).unwrap());
            } else if num_blocks > 1 {
                self.key.unchecked_add_assign(block, &carry);
            }
        }

        // Note that here when num_blocks == 1 && requested_flag != Overflow nothing
        // will actually be spawned.
        rayon::scope(|s| {
            if num_blocks >= 2 {
                // To be able to use carry_extract_assign in it
                carry.clone_from(&lhs[num_blocks - 1]);

                // These would already have been done when the first block was processed
                s.spawn(|_| {
                    self.key.message_extract_assign(&mut lhs[num_blocks - 1]);
                });

                s.spawn(|_| {
                    self.key.carry_extract_assign(&mut carry);
                });
            }

            if requested_flag == OutputFlag::Overflow {
                s.spawn(|_| {
                    let overflow_flag_block = overflow_flag.as_mut().unwrap();
                    // Computing the overflow flag requires and extra step for the first block
                    let overflow_flag_lut = self.key.generate_lookup_table(|block| {
                        let input_carry = block & 1;
                        let does_overflow_if_carry_is_1 = (block >> 3) & 1;
                        let does_overflow_if_carry_is_0 = (block >> 2) & 1;
                        if input_carry == 1 {
                            does_overflow_if_carry_is_1
                        } else {
                            does_overflow_if_carry_is_0
                        }
                    });

                    self.key
                        .apply_lookup_table_assign(overflow_flag_block, &overflow_flag_lut);
                });
            }
        });

        match requested_flag {
            OutputFlag::None => None,
            OutputFlag::Overflow => {
                assert!(
                    overflow_flag.is_some(),
                    "internal error, overflow_flag should exist"
                );
                overflow_flag.map(BooleanBlock::new_unchecked)
            }
            OutputFlag::Carry => {
                carry.degree = Degree::new(1);
                Some(BooleanBlock::new_unchecked(carry))
            }
        }
    }

    /// Computes lhs += (rhs + carry) using the sequential propagation of carries
    ///
    /// parameters of blocks must have 2 bits, parameters in the form X_Y where X >= 1 && Y >= X
    // so 1_X parameters
    //
    // Same idea as other algorithms, however since we have 1 bit per block
    // we do not have to resolve any inner propagation but it adds one more
    // sequential PBS when we are interested in the OverflowFlag
    fn advanced_add_assign_sequential_at_least_2_bits(
        &self,
        lhs: &mut [Ciphertext],
        rhs: &[Ciphertext],
        carry: BooleanBlock,
        requested_flag: OutputFlag,
    ) -> Option<BooleanBlock> {
        let mut carry = carry.0;

        fn block_add_assign_returning_carry(
            sks: &ServerKey,
            lhs: &mut Ciphertext,
            rhs: &Ciphertext,
            carry: &Ciphertext,
        ) -> Ciphertext {
            sks.key.unchecked_add_assign(lhs, rhs);
            sks.key.unchecked_add_assign(lhs, carry);
            let (carry, message) = rayon::join(
                || sks.key.carry_extract(lhs),
                || sks.key.message_extract(lhs),
            );

            *lhs = message;

            carry
        }
        let num_blocks = lhs.len();
        for (lhs_b, rhs_b) in lhs[..num_blocks - 1]
            .iter_mut()
            .zip(rhs[..num_blocks - 1].iter())
        {
            carry = block_add_assign_returning_carry(self, lhs_b, rhs_b, &carry);
        }

        let mut output_carry = block_add_assign_returning_carry(
            self,
            &mut lhs[num_blocks - 1],
            &rhs[num_blocks - 1],
            &carry,
        );

        match requested_flag {
            OutputFlag::None => None,
            OutputFlag::Overflow => {
                let overflowed = self.key.not_equal(&output_carry, &carry);
                Some(BooleanBlock::new_unchecked(overflowed))
            }
            OutputFlag::Carry => {
                output_carry.degree = Degree::new(1);
                Some(BooleanBlock::new_unchecked(output_carry))
            }
        }
    }

    /// Does lhs += (rhs + carry)
    ///
    /// acts like the ADC assembly op, except, the flags have to be explicitly requested
    /// as they incur additional PBSes
    ///
    /// - Parameters must have at least 2 bits of message, 2 bits of carry
    /// - blocks of lhs and rhs must be clean (no carries)
    /// - lhs and rhs must have the same length
    pub(crate) fn advanced_add_assign_with_carry_at_least_4_bits(
        &self,
        lhs: &mut [Ciphertext],
        rhs: &[Ciphertext],
        input_carry: Option<&BooleanBlock>,
        requested_flag: OutputFlag,
    ) -> Option<BooleanBlock> {
        // Empty rhs is a specially allowed 'weird' case to
        // act like a 'propagate single carry' function.
        // This is not made explicit in the docs as we have a
        // `propagate_single_carry_parallelized` function which wraps this special case
        if rhs.is_empty() {
            // Technically, CarryFlag is computable, but OverflowFlag is not
            assert_eq!(
                requested_flag,
                OutputFlag::None,
                "Cannot compute flags when called in propagation mode"
            );
        } else {
            assert_eq!(
                lhs.len(),
                rhs.len(),
                "Both operands must have the same number of blocks"
            );
        }

        if lhs.is_empty() {
            // Then both are empty
            if requested_flag == OutputFlag::None {
                return None;
            }
            return Some(self.create_trivial_boolean_block(false));
        }

        let saved_last_blocks = if requested_flag == OutputFlag::Overflow {
            Some((lhs.last().cloned().unwrap(), rhs.last().cloned().unwrap()))
        } else {
            None
        };

        // Perform the block additions
        for (lhs_b, rhs_b) in lhs.iter_mut().zip(rhs.iter()) {
            self.key.unchecked_add_assign(lhs_b, rhs_b);
        }
        if let Some(carry) = input_carry {
            self.key.unchecked_add_assign(&mut lhs[0], &carry.0);
        }

        let blocks = lhs;
        let num_blocks = blocks.len();

        let message_modulus = self.message_modulus().0;
        let num_bits_in_message = message_modulus.ilog2() as u64;

        let block_modulus = self.message_modulus().0 * self.carry_modulus().0;
        let num_bits_in_block = block_modulus.ilog2();

        // Just in case we compare with max noise level, but it should always be num_bits_in_blocks
        // with the parameters we provide
        let grouping_size =
            (num_bits_in_block as usize).min(self.key.max_noise_level.get() as usize);

        let mut output_flag = None;

        // First step
        let (shifted_blocks, block_states) = match requested_flag {
            OutputFlag::None => {
                let (shifted_blocks, mut block_states) =
                    self.compute_shifted_blocks_and_block_states(blocks);
                let _ = block_states.pop().unwrap();
                (shifted_blocks, block_states)
            }
            OutputFlag::Overflow => {
                let (block, (shifted_blocks, block_states)) = rayon::join(
                    || {
                        // When used on the last block of `lhs` and `rhs`, this will create a
                        // block that encodes the 2 values needed to later know if overflow did
                        // happen depending on the input carry of the last block.
                        let lut = self.key.generate_lookup_table_bivariate(|lhs, rhs| {
                            overflow_flag_preparation_lut(lhs, rhs, num_bits_in_message)
                        });
                        let (last_lhs_block, last_rhs_block) = saved_last_blocks.as_ref().unwrap();
                        self.key.unchecked_apply_lookup_table_bivariate(
                            last_lhs_block,
                            last_rhs_block,
                            &lut,
                        )
                    },
                    || {
                        let (shifted_blocks, mut block_states) =
                            self.compute_shifted_blocks_and_block_states(blocks);
                        let _ = block_states.pop().unwrap();
                        (shifted_blocks, block_states)
                    },
                );

                output_flag = Some(block);
                (shifted_blocks, block_states)
            }
            OutputFlag::Carry => {
                let (shifted_blocks, mut block_states) =
                    self.compute_shifted_blocks_and_block_states(blocks);
                let last_block_state = block_states.pop().unwrap();
                output_flag = Some(last_block_state);
                (shifted_blocks, block_states)
            }
        };

        // Second step
        let (mut prepared_blocks, resolved_carries) = {
            let (propagation_simulators, resolved_carries) = self
                .compute_propagation_simulators_and_groups_carries(grouping_size, &block_states);

            let mut prepared_blocks = shifted_blocks;
            prepared_blocks
                .iter_mut()
                .zip(propagation_simulators.iter())
                .for_each(|(block, simulator)| {
                    self.key.unchecked_add_assign(block, simulator);
                });

            match requested_flag {
                OutputFlag::None => {}
                OutputFlag::Overflow => {
                    let block = output_flag.as_mut().unwrap();
                    self.key
                        .unchecked_add_assign(block, &propagation_simulators[num_blocks - 1]);
                }
                OutputFlag::Carry => {
                    let block = output_flag.as_mut().unwrap();
                    self.key
                        .unchecked_add_assign(block, &propagation_simulators[num_blocks - 1]);
                }
            }

            (prepared_blocks, resolved_carries)
        };

        // Final step: adding resolved carries and cleaning result
        let mut add_carries_and_cleanup = || {
            let message_extract_lut = self
                .key
                .generate_lookup_table(|block| (block >> 1) % message_modulus);

            prepared_blocks
                .par_iter_mut()
                .enumerate()
                .for_each(|(i, block)| {
                    let grouping_index = i / grouping_size;
                    let carry = &resolved_carries[grouping_index];
                    self.key.unchecked_add_assign(block, carry);

                    self.key
                        .apply_lookup_table_assign(block, &message_extract_lut)
                });
        };

        match requested_flag {
            OutputFlag::None => {
                add_carries_and_cleanup();
            }
            OutputFlag::Overflow => {
                let overflow_flag_lut = self.key.generate_lookup_table(|block| {
                    let input_carry = (block >> 1) & 1;
                    let does_overflow_if_carry_is_1 = (block >> 3) & 1;
                    let does_overflow_if_carry_is_0 = (block >> 2) & 1;
                    if input_carry == 1 {
                        does_overflow_if_carry_is_1
                    } else {
                        does_overflow_if_carry_is_0
                    }
                });
                rayon::join(
                    || {
                        let block = output_flag.as_mut().unwrap();
                        // When num block is 1, we have to use the input carry
                        // given by the caller
                        let carry_into_last_block = input_carry
                            .as_ref()
                            .filter(|_| num_blocks == 1)
                            .map_or_else(
                                || &resolved_carries[resolved_carries.len() - 1],
                                |input_carry| &input_carry.0,
                            );
                        self.key.unchecked_add_assign(block, carry_into_last_block);
                        self.key
                            .apply_lookup_table_assign(block, &overflow_flag_lut);
                    },
                    add_carries_and_cleanup,
                );
            }
            OutputFlag::Carry => {
                let carry_flag_lut = self.key.generate_lookup_table(|block| (block >> 2) & 1);

                rayon::join(
                    || {
                        let block = output_flag.as_mut().unwrap();
                        self.key.unchecked_add_assign(
                            block,
                            &resolved_carries[resolved_carries.len() - 1],
                        );
                        self.key.apply_lookup_table_assign(block, &carry_flag_lut);
                    },
                    add_carries_and_cleanup,
                );
            }
        }

        blocks.clone_from_slice(&prepared_blocks);

        match requested_flag {
            OutputFlag::None => None,
            OutputFlag::Overflow | OutputFlag::Carry => {
                output_flag.map(BooleanBlock::new_unchecked)
            }
        }
    }

    pub(crate) fn compute_propagation_simulators_and_groups_carries(
        &self,
        grouping_size: usize,
        block_states: &[Ciphertext],
    ) -> (Vec<Ciphertext>, Vec<Ciphertext>) {
        if block_states.is_empty() {
            return (
                vec![self.key.create_trivial(1)],
                vec![self.key.create_trivial(0)],
            );
        }
        let message_modulus = self.key.message_modulus.0;
        let block_modulus = message_modulus * self.carry_modulus().0;
        let num_bits_in_block = block_modulus.ilog2();
        let num_blocks = block_states.len();

        // This stores the LUTs that given a cum sum block in the first grouping
        // tells if a carry is generated or not
        let first_grouping_inner_propagation_luts = (0..grouping_size - 1)
            .map(|index| {
                self.key.generate_lookup_table(|propa_cum_sum_block| {
                    let carry = (propa_cum_sum_block >> index) & 1;
                    if carry != 0 {
                        2 // Generates
                    } else {
                        0 // Nothing
                    }
                })
            })
            .collect::<Vec<_>>();

        // This stores the LUTs that given a cum sum in non first grouping
        // tells if a carry is generated or propagated or neither of these
        let other_groupings_inner_propagation_luts = (0..grouping_size)
            .map(|index| {
                self.key.generate_lookup_table(|propa_cum_sum_block| {
                    let mask = (2 << index) - 1;
                    if propa_cum_sum_block >= (2 << index) {
                        2 // Generates
                    } else if (propa_cum_sum_block & mask) == mask {
                        1 // Propagate
                    } else {
                        0
                    }
                })
            })
            .collect::<Vec<_>>();

        // This stores the LUT that outputs the propagation result of the first grouping
        let first_grouping_outer_propagation_lut = self.key.generate_lookup_table(|block| {
            // Check if the last bit of the block is set
            (block >> (num_bits_in_block - 1)) & 1
        });

        let num_groupings = num_blocks.div_ceil(grouping_size);
        let num_carry_to_resolve = num_groupings - 1;

        let sequential_depth =
            (num_carry_to_resolve.saturating_sub(1) as u32) / (grouping_size as u32 - 1);
        let hillis_steel_depth = if num_carry_to_resolve == 0 {
            0
        } else {
            num_carry_to_resolve.ceil_ilog2()
        };

        let use_sequential_algorithm_to_resolved_grouping_carries =
            sequential_depth <= hillis_steel_depth;

        // This stores the LUTs that output the propagation result of the other groupings
        let grouping_chunk_pgn_luts = if use_sequential_algorithm_to_resolved_grouping_carries {
            // When using the sequential algorithm for the propagation of one grouping to the
            // other we need to shift the PGN state to the correct position, so we later, when
            // using them only lwe_add is needed and so noise management is easy
            //
            // Also, these LUTs are 'negacylic', they are made to exploit the padding bit
            // resulting blocks from these LUTs must be added the constant `1 << index`.
            (0..grouping_size - 1)
                .map(|i| {
                    self.key.generate_lookup_table(|block| {
                        // All bits set to 1 (e.g. 0b1111), means propagate
                        if block == (block_modulus - 1) {
                            0
                        } else {
                            // u64::MAX is -1 in two's complement
                            // We apply the modulus including the padding bit
                            (u64::MAX << i) % (1 << (num_bits_in_block + 1))
                        }
                    })
                })
                .collect::<Vec<_>>()
        } else {
            // This LUT is for when we are using Hillis-Steele prefix-scan to propagate carries
            // between groupings. When using this propagation, the encoding of the states
            // are a bit different.
            //
            // Also, these LUTs are 'negacylic', they are made to exploit the padding bit
            // resulting blocks from these LUTs must be added the constant `1`.
            vec![self.key.generate_lookup_table(|block| {
                if block == (block_modulus - 1) {
                    // All bits set to 1 (e.g. 0b1111), means propagate
                    2
                } else {
                    // u64::MAX is -1 in two's complement
                    // We apply the modulus including the padding bit
                    u64::MAX % (block_modulus * 2)
                }
            })]
        };

        let mut propagation_cum_sums = Vec::with_capacity(num_blocks);
        block_states.chunks(grouping_size).for_each(|grouping| {
            propagation_cum_sums.push(grouping[0].clone());
            for other in &grouping[1..] {
                let mut result = other.clone();
                self.key
                    .unchecked_add_assign(&mut result, propagation_cum_sums.last().unwrap());

                propagation_cum_sums.push(result);
            }
        });

        // Compute the cum sum arrays,
        // each grouping is independent of other groupings,
        // but we store everything flattened (Vec<_>) instead of nested (Vec<Vec<_>>)
        propagation_cum_sums
            .par_iter_mut()
            .enumerate()
            .for_each(|(i, cum_sum_block)| {
                let grouping_index = i / grouping_size;
                let is_in_first_grouping = grouping_index == 0;
                let index_in_grouping = i % grouping_size;

                let lut = if is_in_first_grouping {
                    if index_in_grouping == grouping_size - 1 {
                        &first_grouping_outer_propagation_lut
                    } else {
                        &first_grouping_inner_propagation_luts[index_in_grouping]
                    }
                } else if index_in_grouping == grouping_size - 1 {
                    if use_sequential_algorithm_to_resolved_grouping_carries {
                        &grouping_chunk_pgn_luts[(grouping_index - 1) % (grouping_size - 1)]
                    } else {
                        &grouping_chunk_pgn_luts[0]
                    }
                } else {
                    &other_groupings_inner_propagation_luts[index_in_grouping]
                };

                self.key.apply_lookup_table_assign(cum_sum_block, lut);

                let may_have_its_padding_bit_set =
                    !is_in_first_grouping && index_in_grouping == grouping_size - 1;
                if may_have_its_padding_bit_set {
                    if use_sequential_algorithm_to_resolved_grouping_carries {
                        self.key.unchecked_scalar_add_assign(
                            cum_sum_block,
                            1 << ((grouping_index - 1) % (grouping_size - 1)),
                        );
                    } else {
                        self.key.unchecked_scalar_add_assign(cum_sum_block, 1);
                    }
                    cum_sum_block.degree = Degree::new(message_modulus - 1);
                }
            });

        let mut groupings_pgns = Vec::with_capacity(num_groupings);
        let mut propagation_simulators = Vec::with_capacity(num_blocks);

        // First block does not get a carry from
        propagation_simulators.push(self.key.create_trivial(1));
        for block in propagation_cum_sums.drain(..) {
            if propagation_simulators.len() % grouping_size == 0 {
                groupings_pgns.push(block);
                // The first block in each grouping has its simulator set to 1
                // because it always receives any input borrow that may be generated from
                // previous grouping
                propagation_simulators.push(self.key.create_trivial(1));
            } else {
                propagation_simulators.push(block);
            }
        }

        // Third step: resolving carry propagation between the groups
        let resolved_carries = if groupings_pgns.is_empty() {
            vec![self.key.create_trivial(0)]
        } else if use_sequential_algorithm_to_resolved_grouping_carries {
            self.resolve_carries_of_groups_sequentially(groupings_pgns, grouping_size)
        } else {
            self.resolve_carries_of_groups_using_hillis_steele(groupings_pgns)
        };

        (propagation_simulators, resolved_carries)
    }

    /// This resolves the carries using a Hillis-Steele algorithm
    ///
    /// Blocks must have a value in
    /// - 2 or 1 for generate
    /// - 3 for propagate
    /// - 0 for no carry
    ///
    /// The returned Vec of blocks encrypting 1 if a carry is generated, 0 if not
    pub(crate) fn resolve_carries_of_groups_using_hillis_steele(
        &self,
        groupings_pgns: Vec<Ciphertext>,
    ) -> Vec<Ciphertext> {
        let lut_carry_propagation_sum =
            self.key
                .generate_lookup_table_bivariate(|msb: u64, lsb: u64| -> u64 {
                    if msb == 2 {
                        1 // Remap Generate to 1
                    } else if msb == 3 {
                        // MSB propagates
                        if lsb == 2 {
                            1
                        } else {
                            lsb
                        } // also remap here
                    } else {
                        msb
                    }
                });
        let sum_function = |block_borrow: &mut Ciphertext, previous_block_borrow: &Ciphertext| {
            self.key.unchecked_apply_lookup_table_bivariate_assign(
                block_borrow,
                previous_block_borrow,
                &lut_carry_propagation_sum,
            );
        };
        let mut resolved_carries =
            self.compute_prefix_sum_hillis_steele(groupings_pgns, sum_function);
        resolved_carries.insert(0, self.key.create_trivial(0));
        resolved_carries
    }

    /// This resolves the carries using a sequential algorithm
    /// where each iteration resolves grouping_size - 1 "PGN"
    ///
    /// Blocks must have a value in
    /// - 2 for generate
    /// - 1 for propagate
    /// - 0 for no carry
    ///
    /// This value must be shifted by the position in the block's group.
    ///
    /// The block of the first group (so groupings_pgns[0]) must have a value in
    /// - 1 for generate
    /// - 0 for no carry
    ///
    /// The returned Vec of blocks encrypting 1 if a carry is generated, 0 if not
    pub(crate) fn resolve_carries_of_groups_sequentially(
        &self,
        mut groupings_pgns: Vec<Ciphertext>,
        grouping_size: usize,
    ) -> Vec<Ciphertext> {
        let luts = (0..grouping_size - 1)
            .map(|index| {
                self.key.generate_lookup_table(|propa_cum_sum_block| {
                    (propa_cum_sum_block >> (index + 1)) & 1
                })
            })
            .collect::<Vec<_>>();

        groupings_pgns.rotate_left(1);
        let mut resolved_carries = vec![self.key.create_trivial(0), groupings_pgns.pop().unwrap()];

        for chunk in groupings_pgns.chunks(grouping_size - 1) {
            let mut cum_sums = chunk.to_vec();
            self.key
                .unchecked_add_assign(&mut cum_sums[0], resolved_carries.last().unwrap());

            if chunk.len() > 1 {
                let mut accumulator = cum_sums[0].clone();
                for block in cum_sums[1..].iter_mut() {
                    self.key.unchecked_add_assign(&mut accumulator, block);
                    block.clone_from(&accumulator);
                }
            }

            cum_sums
                .par_iter_mut()
                .zip(luts.par_iter())
                .for_each(|(cum_sum_block, lut)| {
                    self.key.apply_lookup_table_assign(cum_sum_block, lut);
                });

            // Cum sums now contains the output carries
            resolved_carries.append(&mut cum_sums);
        }

        resolved_carries
    }

    fn compute_shifted_blocks_and_block_states(
        &self,
        blocks: &[Ciphertext],
    ) -> (Vec<Ciphertext>, Vec<Ciphertext>) {
        let num_blocks = blocks.len();

        let message_modulus = self.message_modulus().0;

        let block_modulus = self.message_modulus().0 * self.carry_modulus().0;
        let num_bits_in_block = block_modulus.ilog2();

        let grouping_size = num_bits_in_block as usize;

        let shift_block_fn = |block| (block % message_modulus) << 1;
        let mut first_grouping_luts = vec![{
            let first_block_state_fn = |block| {
                if block >= message_modulus {
                    1 // Generates
                } else {
                    0 // Nothing
                }
            };
            self.key
                .generate_many_lookup_table(&[&first_block_state_fn, &shift_block_fn])
        }];
        for i in 1..grouping_size {
            let state_fn = |block| {
                let r = if block >= message_modulus {
                    2 // Generates Carry
                } else if block == message_modulus - 1 {
                    1 // Propagates a carry
                } else {
                    0 // Does not generate carry
                };

                r << (i - 1)
            };
            first_grouping_luts.push(
                self.key
                    .generate_many_lookup_table(&[&state_fn, &shift_block_fn]),
            );
        }

        let other_block_state_luts = (0..grouping_size)
            .map(|i| {
                let state_fn = |block| {
                    let r = if block >= message_modulus {
                        2 // Generates Carry
                    } else if block == message_modulus - 1 {
                        1 // Propagates a carry
                    } else {
                        0 // Does not borrow
                    };

                    r << i
                };
                self.key
                    .generate_many_lookup_table(&[&state_fn, &shift_block_fn])
            })
            .collect::<Vec<_>>();

        // For the last block we do something a bit different because the
        // state we compute will be used (if needed) to compute the output carry
        // of the whole addition. And this computation will be done during the 'cleaning'
        // phase
        let last_block_luts = {
            if blocks.len() == 1 {
                let first_block_state_fn = |block| {
                    if block >= message_modulus {
                        2 << 1 // Generates
                    } else {
                        0 // Nothing
                    }
                };
                self.key
                    .generate_many_lookup_table(&[&first_block_state_fn, &shift_block_fn])
            } else {
                first_grouping_luts[2].clone()
            }
        };

        let tmp = blocks
            .par_iter()
            .enumerate()
            .map(|(index, block)| {
                let grouping_index = index / grouping_size;
                let is_in_first_grouping = grouping_index == 0;
                let index_in_grouping = index % (grouping_size);
                let is_last_index = index == blocks.len() - 1;

                let luts = if is_last_index {
                    &last_block_luts
                } else if is_in_first_grouping {
                    &first_grouping_luts[index_in_grouping]
                } else {
                    &other_block_state_luts[index_in_grouping]
                };
                self.key.apply_many_lookup_table(block, luts)
            })
            .collect::<Vec<_>>();

        let mut shifted_blocks = Vec::with_capacity(num_blocks);
        let mut block_states = Vec::with_capacity(num_blocks);
        for mut blocks in tmp {
            assert_eq!(blocks.len(), 2);
            shifted_blocks.push(blocks.pop().unwrap());
            block_states.push(blocks.pop().unwrap());
        }

        (shifted_blocks, block_states)
    }

    /// Computes a prefix sum/scan in parallel using Hillis & Steel algorithm
    pub(crate) fn compute_prefix_sum_hillis_steele<F>(
        &self,
        mut blocks: Vec<Ciphertext>,
        sum_function: F,
    ) -> Vec<Ciphertext>
    where
        F: for<'a, 'b> Fn(&'a mut Ciphertext, &'b Ciphertext) + Sync,
    {
        debug_assert!(self.key.message_modulus.0 * self.key.carry_modulus.0 >= (1 << 4));

        if blocks.is_empty() || blocks.len() == 1 {
            return blocks;
        }

        let num_blocks = blocks.len();
        let num_steps = blocks.len().ceil_ilog2() as usize;

        let mut space = 1;
        let mut step_output = blocks.clone();
        for _ in 0..num_steps {
            step_output[space..num_blocks]
                .par_iter_mut()
                .enumerate()
                .for_each(|(i, block)| {
                    let prev_block_carry = &blocks[i];
                    sum_function(block, prev_block_carry);
                });
            for i in space..num_blocks {
                blocks[i].clone_from(&step_output[i]);
            }

            space *= 2;
        }

        blocks
    }
}

/// This function is meant to be used to creat the lookup table that prepares
/// the overflow flag.
// Computing the overflow flag is a bit more complex than the carry flag.
//
// The overflow flag is computed by comparing the input carry onto the last bit
// with the output carry of the last bit.
//
// Since we have blocks that encrypts multiple bit,
// we have to compute and encode what the input carry onto the last
// bit is depending on the input carry onto the last block.
//
// So this function creates a lookuptable that when applied to a block
// packing the last blocks (MSB) of 2 number, will resulting in a block
// where:
//
// - at bit index 2 is stored whether overflow happens if the input bloc carry is '2'
// - at bit index 3 is stored whether overflow happens if the input bloc carry is '1'
fn overflow_flag_preparation_lut(
    last_lhs_block: u64,
    last_rhs_block: u64,
    num_bits_in_message: u64,
) -> u64 {
    let mask = (1 << (num_bits_in_message - 1)) - 1;
    let lhs_except_last_bit = last_lhs_block & mask;
    let rhs_except_last_bit = last_rhs_block & mask;

    let overflows_with_given_input_carry = |input_carry| {
        let output_carry =
            ((last_lhs_block + last_rhs_block + input_carry) >> num_bits_in_message) & 1;

        let input_carry_to_last_bit = ((lhs_except_last_bit + rhs_except_last_bit + input_carry)
            >> (num_bits_in_message - 1))
            & 1;

        u64::from(input_carry_to_last_bit != output_carry)
    };

    (overflows_with_given_input_carry(1) << 3) | (overflows_with_given_input_carry(0) << 2)
}

#[cfg(test)]
mod tests {
    use super::should_parallel_propagation_be_faster;
    use crate::integer::gen_keys_radix;
    use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;

    #[test]
    fn test_propagate_single_carry_on_empty_input_ci_run_filter() {
        // Parameters and num blocks do not matter here
        let (_, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, 4);

        sks.propagate_single_carry_parallelized(&mut []);
        // The most interesting part we test is that the code does not panic
    }

    #[test]
    fn test_propagation_choice_ci_run_filter() {
        struct ExpectedChoices {
            num_threads: usize,
            bit_sizes: Vec<(usize, bool)>,
        }

        // These cases have been tested in real conditions by running benchmarks for
        // add_parallelized with `RAYON_NUM_THREADS`
        let cases = [
            ExpectedChoices {
                num_threads: 2,
                bit_sizes: vec![
                    (2, false),
                    (4, false),
                    (8, false),
                    (16, false),
                    (32, false),
                    (64, false),
                    (128, false),
                    (256, false),
                    (512, false),
                ],
            },
            ExpectedChoices {
                num_threads: 4,
                bit_sizes: vec![
                    (2, false),
                    (4, false),
                    (8, true),
                    (16, true),
                    (32, true),
                    (64, true),
                    (128, true),
                    (256, false),
                    (512, false),
                ],
            },
            ExpectedChoices {
                num_threads: 8,
                bit_sizes: vec![
                    (2, false),
                    (4, false),
                    (8, true),
                    (16, true),
                    (32, true),
                    (64, true),
                    (128, true),
                    (256, false),
                    (512, false),
                ],
            },
            ExpectedChoices {
                num_threads: 12,
                bit_sizes: vec![
                    (2, false),
                    (4, false),
                    (8, true),
                    (16, true),
                    (32, true),
                    (64, true),
                    (128, true),
                    (256, true),
                    (512, true),
                ],
            },
            ExpectedChoices {
                num_threads: 128,
                bit_sizes: vec![
                    (2, false),
                    (4, false),
                    (8, true),
                    (16, true),
                    (32, true),
                    (64, true),
                    (128, true),
                    (256, true),
                    (512, true),
                ],
            },
        ];

        const FULL_MODULUS: u64 = 32; // This is 2_2 parameters

        fn bool_to_algo_name(parallel_chosen: bool) -> &'static str {
            if parallel_chosen {
                "parallel"
            } else {
                "sequential"
            }
        }

        for case in cases {
            for (bit_size, expect_parallel) in case.bit_sizes {
                let num_blocks = bit_size / 2;
                let chose_parallel = should_parallel_propagation_be_faster(
                    FULL_MODULUS,
                    num_blocks,
                    case.num_threads,
                );
                assert_eq!(
                    chose_parallel,
                    expect_parallel,
                    "Wrong propagation algorithm chosen for {bit_size} bits ({num_blocks} blocks) and {} threads\n\
                        Expected '{}' but '{}' was chosen\
                    ",
                    case.num_threads,
                    bool_to_algo_name(expect_parallel),
                    bool_to_algo_name(chose_parallel)
                );
            }
        }
    }
}
