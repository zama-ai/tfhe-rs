use crate::core_crypto::commons::numeric::UnsignedInteger;
use crate::integer::ciphertext::IntegerRadixCiphertext;
use crate::integer::server_key::radix_parallel::sub::SignedOperation;
use crate::integer::{BooleanBlock, RadixCiphertext, ServerKey, SignedRadixCiphertext};
use crate::shortint::ciphertext::Degree;
use crate::shortint::Ciphertext;
use rayon::prelude::*;

#[repr(u64)]
#[derive(PartialEq, Eq)]
pub(crate) enum OutputCarry {
    /// The block does not generate nor propagate a carry
    None = 0,
    /// The block generates a carry
    Generated = 1,
    /// The block will propagate a carry if it ever
    /// receives one
    Propagated = 2,
}

/// Function to create the LUT used in parallel prefix sum
/// to compute carry propagation
///
/// If msb propagates it take the value of lsb,
/// this means:
/// - if lsb propagates, msb will propagate (but we don't know yet if there will actually be a carry
///   to propagate),
/// - if lsb generates a carry, as msb propagates it, lsb will generate a carry. Note that this lsb
///   generates might be due to x propagating ('resolved' by an earlier iteration of the loop)
/// - if lsb does not output a carry, msb will have nothing to propagate
///
/// Otherwise, msb either does not generate, or it does generate,
/// but it means it won't propagate
fn prefix_sum_carry_propagation(msb: u64, lsb: u64) -> u64 {
    if msb == OutputCarry::Propagated as u64 {
        lsb
    } else {
        msb
    }
}

fn should_hillis_steele_propagation_be_faster(num_blocks: usize, num_threads: usize) -> bool {
    // Measures have shown that using a parallelized algorithm degrades
    // the latency of a PBS, so we take that into account.
    // (This factor is a bit pessimistic).
    const PARALLEL_LATENCY_PENALTY: usize = 2;
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
    let mut parallel_expected_latency = 2 * compute_latency_of_one_layer(num_blocks, num_threads);
    let max_depth = num_blocks.ceil_ilog2();
    let mut space = 1;
    for _ in 0..max_depth {
        let num_block_at_iter = num_blocks - space;
        let iter_latency = compute_latency_of_one_layer(num_block_at_iter, num_threads);
        parallel_expected_latency += iter_latency;
        space *= 2;
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
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks);
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
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks);
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

        if self.is_eligible_for_parallel_single_carry_propagation(lhs) {
            let _carry = self.unchecked_add_assign_parallelized_low_latency(lhs, rhs);
        } else {
            self.unchecked_add_assign(lhs, rhs);
            self.full_propagate_parallelized(lhs);
        }
    }
    /// Computes the addition of two unsigned ciphertexts and returns the overflow flag
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks);
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
        let mut ct_res = ct_left.clone();
        let overflowed = self.unsigned_overflowing_add_assign_parallelized(&mut ct_res, ct_right);
        (ct_res, overflowed)
    }

    pub fn unsigned_overflowing_add_assign_parallelized(
        &self,
        ct_left: &mut RadixCiphertext,
        ct_right: &RadixCiphertext,
    ) -> BooleanBlock {
        let mut tmp_rhs: RadixCiphertext;
        if ct_left.blocks.is_empty() || ct_right.blocks.is_empty() {
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

        self.unchecked_add_assign_parallelized(lhs, rhs);
        self.unsigned_overflowing_propagate_addition_carry(lhs)
    }

    /// This function takes a ciphertext resulting from an addition of 2 clean ciphertexts
    ///
    /// It propagates the carries in-place, making the ciphertext clean and returns
    /// the boolean indicating overflow
    pub(in crate::integer) fn unsigned_overflowing_propagate_addition_carry(
        &self,
        ct: &mut RadixCiphertext,
    ) -> BooleanBlock {
        if self.is_eligible_for_parallel_single_carry_propagation(ct) {
            let carry = self.propagate_single_carry_parallelized_low_latency(&mut ct.blocks);
            BooleanBlock::new_unchecked(carry)
        } else {
            let len = ct.blocks.len();
            for i in 0..len - 1 {
                let _ = self.propagate_parallelized(ct, i);
            }
            let mut carry = self.propagate_parallelized(ct, len - 1);
            carry.degree = Degree::new(1);
            BooleanBlock::new_unchecked(carry)
        }
    }

    pub fn signed_overflowing_add_parallelized(
        &self,
        ct_left: &SignedRadixCiphertext,
        ct_right: &SignedRadixCiphertext,
    ) -> (SignedRadixCiphertext, BooleanBlock) {
        let mut tmp_lhs: SignedRadixCiphertext;
        let mut tmp_rhs: SignedRadixCiphertext;

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
                tmp_lhs = ct_left.clone();
                self.full_propagate_parallelized(&mut tmp_lhs);
                (&tmp_lhs, ct_right)
            }
            (false, false) => {
                tmp_lhs = ct_left.clone();
                tmp_rhs = ct_right.clone();
                rayon::join(
                    || self.full_propagate_parallelized(&mut tmp_lhs),
                    || self.full_propagate_parallelized(&mut tmp_rhs),
                );
                (&tmp_lhs, &tmp_rhs)
            }
        };

        self.unchecked_signed_overflowing_add_parallelized(lhs, rhs)
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

        if self.is_eligible_for_parallel_single_carry_propagation(ct_left) {
            self.unchecked_signed_overflowing_add_or_sub_parallelized_impl(
                ct_left,
                ct_right,
                SignedOperation::Addition,
            )
        } else {
            self.unchecked_signed_overflowing_add_or_sub(
                ct_left,
                ct_right,
                SignedOperation::Addition,
            )
        }
    }

    pub fn add_parallelized_work_efficient<T>(&self, ct_left: &T, ct_right: &T) -> T
    where
        T: IntegerRadixCiphertext,
    {
        let mut ct_res = ct_left.clone();
        self.add_assign_parallelized_work_efficient(&mut ct_res, ct_right);
        ct_res
    }

    pub fn add_assign_parallelized_work_efficient<T>(&self, ct_left: &mut T, ct_right: &T)
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

        self.unchecked_add_assign_parallelized_work_efficient(lhs, rhs);
    }

    pub(crate) fn is_eligible_for_parallel_single_carry_propagation<T>(&self, ct: &T) -> bool
    where
        T: IntegerRadixCiphertext,
    {
        // having 4-bits is a hard requirement
        // as the parallel implementation uses a bivariate BPS where individual values need
        // 2 bits
        let total_modulus = self.key.message_modulus.0 * self.key.carry_modulus.0;
        let has_enough_bits_per_block = total_modulus >= (1 << 4);
        if !has_enough_bits_per_block {
            return false;
        }

        should_hillis_steele_propagation_be_faster(ct.blocks().len(), rayon::current_num_threads())
    }

    /// This add_assign two numbers
    ///
    /// It uses the Hillis and Steele algorithm to do
    /// prefix sum / cumulative sum in parallel.
    ///
    /// It it not "work efficient" as in, it adds a lot
    /// of work compared to the single threaded approach,
    /// however it is highly parallelized and so is the fastest
    /// assuming enough threads are available.
    ///
    /// At most num_block - 1 threads are used
    ///
    /// Returns the output carry that can be used to check for unsigned addition
    /// overflow.
    ///
    /// # Requirements
    ///
    /// - The parameters have 4 bits in total
    /// - Adding rhs to lhs must not consume more than one carry
    ///
    /// # Output
    ///
    /// - lhs will have its carries empty
    pub(crate) fn unchecked_add_assign_parallelized_low_latency<T>(
        &self,
        lhs: &mut T,
        rhs: &T,
    ) -> Ciphertext
    where
        T: IntegerRadixCiphertext,
    {
        let degree_after_add_does_not_go_beyond_first_carry = lhs
            .blocks()
            .iter()
            .zip(rhs.blocks().iter())
            .all(|(bl, br)| {
                let degree_after_add = bl.degree.get() + br.degree.get();
                degree_after_add < (self.key.message_modulus.0 * 2)
            });
        assert!(degree_after_add_does_not_go_beyond_first_carry);

        self.unchecked_add_assign_parallelized(lhs, rhs);
        self.propagate_single_carry_parallelized_low_latency(lhs.blocks_mut())
    }

    /// This function takes an input slice of shortint ciphertext (aka blocks)
    /// for which at most one bit of carry is consumed in each block, and
    /// it does the carry propagation in place.
    ///
    /// It returns the output carry of the last block
    ///
    /// Used in (among other) 'default' addition:
    /// - first unchecked_add
    /// - at this point at most on bit of carry is taken
    /// - use this function to propagate them in parallel
    pub(crate) fn propagate_single_carry_parallelized_low_latency(
        &self,
        blocks: &mut [Ciphertext],
    ) -> Ciphertext {
        let generates_or_propagates = self.generate_init_carry_array(blocks);
        let (input_carries, output_carry) =
            self.compute_carry_propagation_parallelized_low_latency(generates_or_propagates);

        blocks
            .par_iter_mut()
            .zip(input_carries.par_iter())
            .for_each(|(block, input_carry)| {
                self.key.unchecked_add_assign(block, input_carry);
                self.key.message_extract_assign(block);
            });
        output_carry
    }

    /// Backbone algorithm of parallel carry (only one bit) propagation
    ///
    /// Uses the Hillis and Steele prefix scan
    ///
    /// Requires the blocks to have at least 4 bits
    pub(crate) fn compute_carry_propagation_parallelized_low_latency(
        &self,
        generates_or_propagates: Vec<Ciphertext>,
    ) -> (Vec<Ciphertext>, Ciphertext) {
        if generates_or_propagates.is_empty() {
            return (vec![], self.key.create_trivial(0));
        }

        let lut_carry_propagation_sum = self
            .key
            .generate_lookup_table_bivariate(prefix_sum_carry_propagation);
        // Type annotations are required, otherwise we get confusing errors
        // "implementation of `FnOnce` is not general enough"
        let sum_function = |block_carry: &mut Ciphertext, previous_block_carry: &Ciphertext| {
            self.key.unchecked_apply_lookup_table_bivariate_assign(
                block_carry,
                previous_block_carry,
                &lut_carry_propagation_sum,
            );
        };

        let num_blocks = generates_or_propagates.len();
        let mut carries_out =
            self.compute_prefix_sum_hillis_steele(generates_or_propagates, sum_function);
        let mut last_block_out_carry = self.key.create_trivial(0);
        std::mem::swap(&mut carries_out[num_blocks - 1], &mut last_block_out_carry);
        last_block_out_carry.degree = Degree::new(1);
        // The output carry of block i-1 becomes the input
        // carry of block i
        carries_out.rotate_right(1);
        (carries_out, last_block_out_carry)
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

        if blocks.is_empty() {
            return vec![];
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

    /// This add_assign two numbers
    ///
    /// It is after the Blelloch algorithm to do
    /// prefix sum / cumulative sum in parallel.
    ///
    /// It is not "work efficient" as in, it does not adds
    /// that much work compared to other parallel algorithm,
    /// thus requiring less threads.
    ///
    /// However it is slower.
    ///
    /// At most num_block / 2 threads are used
    ///
    /// # Requirements
    ///
    /// - The parameters have 4 bits in total
    /// - Adding rhs to lhs must not consume more than one carry
    ///
    /// # Output
    ///
    /// - lhs will have its carries empty
    pub(crate) fn unchecked_add_assign_parallelized_work_efficient<T>(&self, lhs: &mut T, rhs: &T)
    where
        T: IntegerRadixCiphertext,
    {
        let degree_after_add_does_not_go_beyond_first_carry = lhs
            .blocks()
            .iter()
            .zip(rhs.blocks().iter())
            .all(|(bl, br)| {
                let degree_after_add = bl.degree.get() + br.degree.get();
                degree_after_add < (self.key.message_modulus.0 * 2)
            });
        assert!(degree_after_add_does_not_go_beyond_first_carry);
        debug_assert!(self.key.message_modulus.0 * self.key.carry_modulus.0 >= (1 << 3));

        self.unchecked_add_assign_parallelized(lhs, rhs);
        let generates_or_propagates = self.generate_init_carry_array(lhs.blocks());
        let carry_out =
            self.compute_carry_propagation_parallelized_work_efficient(generates_or_propagates);

        lhs.blocks_mut()
            .par_iter_mut()
            .zip(carry_out.par_iter())
            .for_each(|(block, carry_in)| {
                self.key.unchecked_add_assign(block, carry_in);
                self.key.message_extract_assign(block);
            });
    }

    pub(crate) fn compute_carry_propagation_parallelized_work_efficient(
        &self,
        mut carry_out: Vec<Ciphertext>,
    ) -> Vec<Ciphertext> {
        debug_assert!(self.key.message_modulus.0 * self.key.carry_modulus.0 >= (1 << 3));

        let num_blocks = carry_out.len();
        let num_steps = carry_out.len().ilog2() as usize;

        let lut_carry_propagation_sum = self
            .key
            .generate_lookup_table_bivariate(prefix_sum_carry_propagation);

        for i in 0..num_steps {
            let two_pow_i_plus_1 = 2usize.checked_pow((i + 1) as u32).unwrap();
            let two_pow_i = 2usize.checked_pow(i as u32).unwrap();

            carry_out
                .par_chunks_exact_mut(two_pow_i_plus_1)
                .for_each(|carry_out| {
                    let (last, head) = carry_out.split_last_mut().unwrap();
                    let current_block = last;
                    let previous_block = &head[two_pow_i - 1];

                    self.key.unchecked_apply_lookup_table_bivariate_assign(
                        current_block,
                        previous_block,
                        &lut_carry_propagation_sum,
                    );
                });
        }

        // Down-Sweep phase
        let mut buffer = Vec::with_capacity(num_blocks / 2);
        self.key
            .create_trivial_assign(&mut carry_out[num_blocks - 1], 0);
        for i in (0..num_steps).rev() {
            let two_pow_i_plus_1 = 2usize.checked_pow((i + 1) as u32).unwrap();
            let two_pow_i = 2usize.checked_pow(i as u32).unwrap();

            (0..num_blocks)
                .into_par_iter()
                .step_by(two_pow_i_plus_1)
                .map(|k| {
                    // Since our carry_propagation LUT ie sum function
                    // is not commutative we have to reverse operands
                    self.key.unchecked_apply_lookup_table_bivariate(
                        &carry_out[k + two_pow_i - 1],
                        &carry_out[k + two_pow_i_plus_1 - 1],
                        &lut_carry_propagation_sum,
                    )
                })
                .collect_into_vec(&mut buffer);

            let mut drainer = buffer.drain(..);
            for k in (0..num_blocks).step_by(two_pow_i_plus_1) {
                let b = drainer.next().unwrap();
                carry_out.swap(k + two_pow_i - 1, k + two_pow_i_plus_1 - 1);
                carry_out[k + two_pow_i_plus_1 - 1] = b;
            }
            drop(drainer);
            assert!(buffer.is_empty());
        }

        // The first step of the Down-Sweep phase sets the
        // first block to 0, so no need to re-do it
        carry_out
    }

    pub(super) fn generate_init_carry_array(&self, sum_blocks: &[Ciphertext]) -> Vec<Ciphertext> {
        let modulus = self.key.message_modulus.0 as u64;

        // This is used for the first pair of blocks
        // as this pair can either generate or not, but never propagate
        let lut_does_block_generate_carry = self.key.generate_lookup_table(|x| {
            if x >= modulus {
                OutputCarry::Generated as u64
            } else {
                OutputCarry::None as u64
            }
        });

        let lut_does_block_generate_or_propagate = self.key.generate_lookup_table(|x| {
            if x >= modulus {
                OutputCarry::Generated as u64
            } else if x == (modulus - 1) {
                OutputCarry::Propagated as u64
            } else {
                OutputCarry::None as u64
            }
        });

        let mut generates_or_propagates = Vec::with_capacity(sum_blocks.len());
        sum_blocks
            .par_iter()
            .enumerate()
            .map(|(i, block)| {
                if i == 0 {
                    // The first block can only output a carry
                    self.key
                        .apply_lookup_table(block, &lut_does_block_generate_carry)
                } else {
                    self.key
                        .apply_lookup_table(block, &lut_does_block_generate_or_propagate)
                }
            })
            .collect_into_vec(&mut generates_or_propagates);

        generates_or_propagates
    }
}

#[cfg(test)]
mod tests {
    use super::should_hillis_steele_propagation_be_faster;
    use crate::integer::gen_keys_radix;
    use crate::shortint::prelude::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

    #[test]
    fn test_propagate_single_carry_on_empty_input_ci_run_filter() {
        // Parameters and num blocks do not matter here
        let (_, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, 4);

        let carry = sks.propagate_single_carry_parallelized_low_latency([].as_mut_slice());

        // The most interesting part we test is that the code does not panic
        assert!(carry.is_trivial());
        assert_eq!(carry.decrypt_trivial().unwrap(), 0u64);
    }

    #[test]
    fn test_hillis_steele_choice_128_threads() {
        // m6i.metal like number of threads
        const NUM_THREADS: usize = 128;
        // 16, 32, 64, 128, 256 512 bits
        for num_blocks in [8, 16, 32, 64, 128, 256] {
            assert!(
                should_hillis_steele_propagation_be_faster(num_blocks, NUM_THREADS),
                "Expected hillis and steele to be chosen for {num_blocks} blocks and {NUM_THREADS} threads"
            );
        }
        // 8 bits
        assert!(!should_hillis_steele_propagation_be_faster(4, NUM_THREADS),);
    }

    #[test]
    fn test_hillis_steele_choice_12_threads() {
        const NUM_THREADS: usize = 12;
        // 8, 16, 32, 64, 128, 256, 512 bits
        for num_blocks in [4, 8, 16, 32, 64, 128, 256] {
            assert!(
                !should_hillis_steele_propagation_be_faster(num_blocks, NUM_THREADS),
                "Expected hillis and steele to *not* be chosen for {num_blocks} blocks and {NUM_THREADS} threads"
            );
        }
    }

    #[test]
    fn test_hillis_steele_choice_8_threads() {
        const NUM_THREADS: usize = 8;
        // 8, 16, 32, 64, 128, 256, 512 bits
        for num_blocks in [4, 8, 16, 32, 64, 128, 256] {
            assert!(
                !should_hillis_steele_propagation_be_faster(num_blocks, NUM_THREADS),
                "Expected hillis and steele to *not* be chosen for {num_blocks} blocks and {NUM_THREADS} threads"
            );
        }
    }

    #[test]
    fn test_hillis_steele_choice_4_threads() {
        const NUM_THREADS: usize = 4;
        // 8, 16, 32, 64, 128, 256, 512 bits
        for num_blocks in [4, 8, 16, 32, 64, 128, 256] {
            assert!(
                !should_hillis_steele_propagation_be_faster(num_blocks, NUM_THREADS),
                "Expected hillis and steele to *not* be chosen for {num_blocks} blocks and {NUM_THREADS} threads"
            );
        }
    }
}
