use crate::core_crypto::commons::numeric::UnsignedInteger;
use crate::integer::ciphertext::IntegerRadixCiphertext;
use crate::integer::server_key::radix_parallel::sub::SignedOperation;
use crate::integer::{
    BooleanBlock, IntegerCiphertext, RadixCiphertext, ServerKey, SignedRadixCiphertext,
};
use crate::shortint::ciphertext::Degree;
use crate::shortint::Ciphertext;
use rayon::prelude::*;
use std::ops::RangeInclusive;

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

    /// Computes the sum of the ciphertexts in parallel.
    ///
    /// Returns a result that has non propagated carries
    pub(crate) fn unchecked_partial_sum_ciphertexts_vec_parallelized<T>(
        &self,
        terms: Vec<T>,
    ) -> Option<T>
    where
        T: IntegerRadixCiphertext,
    {
        if terms.is_empty() {
            return None;
        }

        if terms.len() == 1 {
            return Some(terms.into_iter().next().unwrap());
        }

        let num_blocks = terms[0].blocks().len();
        assert!(
            terms[1..].iter().all(|ct| ct.blocks().len() == num_blocks),
            "Not all ciphertexts have the same number of blocks"
        );

        if terms.len() == 2 {
            return Some(self.add_parallelized(&terms[0], &terms[1]));
        }

        assert!(
            terms
                .iter()
                .all(IntegerRadixCiphertext::block_carries_are_empty),
            "All ciphertexts must have empty carries"
        );

        // Pre-conditions and easy path are met, start the real work
        let message_modulus = self.key.message_modulus.0;
        let carry_modulus = self.key.carry_modulus.0;
        let total_modulus = message_modulus * carry_modulus;
        let message_max = message_modulus - 1;

        let num_elements_to_fill_carry = (total_modulus - 1) / message_max;

        // Re-organize radix terms into columns of blocks
        let mut columns = vec![vec![]; num_blocks];
        for term in terms {
            for (i, block) in term.into_blocks().into_iter().enumerate() {
                if block.degree.get() != 0 {
                    columns[i].push(block);
                }
            }
        }

        if columns.iter().all(Vec::is_empty) {
            return Some(self.create_trivial_radix(0, num_blocks));
        }

        let num_columns = columns.len();
        // Buffer in which we will store resulting columns after an iteration
        let mut columns_buffer = Vec::with_capacity(num_columns);
        let mut colum_output_buffer =
            vec![Vec::<(Ciphertext, Option<Ciphertext>)>::new(); num_blocks];

        let at_least_one_column_has_enough_elements = |columns: &[Vec<Ciphertext>]| {
            columns.iter().any(|c| c.len() > num_elements_to_fill_carry)
        };

        while at_least_one_column_has_enough_elements(&columns) {
            columns
                .par_drain(..)
                .zip(colum_output_buffer.par_iter_mut())
                .enumerate()
                .map(|(column_index, (mut column, out_buf))| {
                    if column.len() < num_elements_to_fill_carry {
                        return column;
                    }
                    column
                        .par_chunks_exact(num_elements_to_fill_carry)
                        .map(|chunk| {
                            let mut result = chunk[0].clone();
                            for c in &chunk[1..] {
                                self.key.unchecked_add_assign(&mut result, c);
                            }

                            if column_index < num_columns - 1 {
                                rayon::join(
                                    || self.key.message_extract(&result),
                                    || Some(self.key.carry_extract(&result)),
                                )
                            } else {
                                (self.key.message_extract(&result), None)
                            }
                        })
                        .collect_into_vec(out_buf);

                    let num_elem_in_rest = column.len() % num_elements_to_fill_carry;
                    column.rotate_right(num_elem_in_rest);
                    column.truncate(num_elem_in_rest);
                    column
                })
                .collect_into_vec(&mut columns_buffer);

            std::mem::swap(&mut columns, &mut columns_buffer);

            // Move resulting message and carry blocks where they belong
            for (i, column_output) in colum_output_buffer.iter_mut().enumerate() {
                for (msg, maybe_carry) in column_output.drain(..) {
                    columns[i].push(msg);

                    if let (Some(carry), true) = (maybe_carry, (i + 1) < columns.len()) {
                        columns[i + 1].push(carry);
                    }
                }
            }
        }

        // Reconstruct a radix from the columns
        let blocks = columns
            .into_iter()
            .map(|mut column| {
                if column.is_empty() {
                    self.key.create_trivial(0)
                } else {
                    let (first_block, other_blocks) =
                        column.as_mut_slice().split_first_mut().unwrap();
                    for other in other_blocks {
                        self.key.unchecked_add_assign(first_block, other);
                    }
                    column.swap_remove(0)
                }
            })
            .collect::<Vec<_>>();
        assert_eq!(blocks.len(), num_blocks);

        Some(T::from_blocks(blocks))
    }

    /// Computes the sum of the ciphertexts in parallel.
    ///
    /// - Returns None if ciphertexts is empty
    ///
    /// - Expects all ciphertexts to have empty carries
    /// - Expects all ciphertexts to have the same size
    pub fn unchecked_sum_ciphertexts_vec_parallelized<T>(&self, ciphertexts: Vec<T>) -> Option<T>
    where
        T: IntegerRadixCiphertext,
    {
        let mut result = self.unchecked_partial_sum_ciphertexts_vec_parallelized(ciphertexts)?;

        self.full_propagate_parallelized(&mut result);
        assert!(result.block_carries_are_empty());

        Some(result)
    }

    /// See [Self::unchecked_sum_ciphertexts_vec_parallelized]
    pub fn unchecked_sum_ciphertexts_parallelized<'a, T, C>(&self, ciphertexts: C) -> Option<T>
    where
        C: IntoIterator<Item = &'a T>,
        T: IntegerRadixCiphertext + 'a,
    {
        let ciphertexts = ciphertexts.into_iter().map(Clone::clone).collect();
        self.unchecked_sum_ciphertexts_vec_parallelized(ciphertexts)
    }

    /// Computes the sum of the ciphertexts in parallel.
    ///
    /// - Returns None if ciphertexts is empty
    ///
    /// See [Self::unchecked_sum_ciphertexts_parallelized] for constraints
    pub fn sum_ciphertexts_parallelized<'a, T, C>(&self, ciphertexts: C) -> Option<T>
    where
        C: IntoIterator<Item = &'a T>,
        T: IntegerRadixCiphertext + 'a,
    {
        let mut ciphertexts = ciphertexts
            .into_iter()
            .map(Clone::clone)
            .collect::<Vec<T>>();
        ciphertexts
            .par_iter_mut()
            .filter(|ct| ct.block_carries_are_empty())
            .for_each(|ct| {
                if !ct.block_carries_are_empty() {
                    self.full_propagate_parallelized(&mut *ct);
                }
            });

        self.unchecked_sum_ciphertexts_vec_parallelized(ciphertexts)
    }

    /// Computes the sum of the ciphertexts in parallel.
    ///
    /// - Returns None if ciphertexts is empty
    ///
    /// See [Self::unchecked_sum_ciphertexts_parallelized] for constraints
    pub fn smart_sum_ciphertexts_parallelized<T, C>(&self, mut ciphertexts: C) -> Option<T>
    where
        C: AsMut<[T]> + AsRef<[T]>,
        T: IntegerRadixCiphertext,
    {
        ciphertexts.as_mut().par_iter_mut().for_each(|ct| {
            if !ct.block_carries_are_empty() {
                self.full_propagate_parallelized(ct);
            }
        });

        self.unchecked_sum_ciphertexts_parallelized(ciphertexts.as_ref())
    }

    /// This sums all ciphertext contained in the chunk into the first element of the chunk
    /// i.e: [A, B, C] -> [A + B + C, B, C]
    /// and returns the inclusive range indicating the range of blocks which where addition were
    /// made that is, if the ciphertexts contains trailing (end or start) trivial zeros some
    /// addition will be skipped (as adding a bunch of zeros is not useful)
    fn unchecked_sum_ciphertext_chunk<T>(&self, chunk: &mut [T]) -> RangeInclusive<usize>
    where
        T: IntegerRadixCiphertext,
    {
        assert_ne!(chunk.len(), 0);
        if chunk.len() <= 1 {
            return 0..=0;
        }
        let num_blocks = chunk[0].blocks().len();
        let (s, rest) = chunk.split_first_mut().unwrap();
        let mut first_block_where_addition_happened = num_blocks - 1;
        let mut last_block_where_addition_happened = 0;
        for a in rest.iter() {
            let first_block_to_add = a
                .blocks()
                .iter()
                .position(|block| block.degree.get() != 0)
                .unwrap_or(num_blocks);
            first_block_where_addition_happened =
                first_block_where_addition_happened.min(first_block_to_add);
            let last_block_to_add = a
                .blocks()
                .iter()
                .rev()
                .position(|block| block.degree.get() != 0)
                .map_or(num_blocks - 1, |pos| num_blocks - pos - 1);
            last_block_where_addition_happened =
                last_block_where_addition_happened.max(last_block_to_add);
            for (ct_left_i, ct_right_i) in &mut s.blocks_mut()
                [first_block_to_add..last_block_to_add + 1]
                .iter_mut()
                .zip(a.blocks()[first_block_to_add..last_block_to_add + 1].iter())
            {
                self.key.unchecked_add_assign(ct_left_i, ct_right_i);
            }
        }

        first_block_where_addition_happened..=last_block_where_addition_happened
    }

    /// - Expects all ciphertexts to have empty carries
    /// - Expects all ciphertexts to have the same size
    pub fn unchecked_unsigned_overflowing_sum_ciphertexts_vec_parallelized(
        &self,
        mut ciphertexts: Vec<RadixCiphertext>,
    ) -> Option<(RadixCiphertext, BooleanBlock)> {
        if ciphertexts.is_empty() {
            return None;
        }

        if ciphertexts.len() == 1 {
            return Some((
                ciphertexts.pop().unwrap(),
                BooleanBlock::new_unchecked(self.key.create_trivial(0)),
            ));
        }

        let num_blocks = ciphertexts[0].blocks().len();
        assert!(
            ciphertexts[1..]
                .iter()
                .all(|ct| ct.blocks().len() == num_blocks),
            "Not all ciphertexts have the same number of blocks"
        );

        if ciphertexts.len() == 2 {
            return Some(
                self.unsigned_overflowing_add_parallelized(&ciphertexts[0], &ciphertexts[1]),
            );
        }

        assert!(
            ciphertexts
                .iter()
                .all(IntegerRadixCiphertext::block_carries_are_empty),
            "All ciphertexts must have empty carries"
        );

        let num_blocks = ciphertexts[0].blocks.len();
        assert!(
            ciphertexts[1..]
                .iter()
                .all(|ct| ct.blocks.len() == num_blocks),
            "Not all ciphertexts have the same number of blocks"
        );
        assert!(
            ciphertexts
                .iter()
                .all(RadixCiphertext::block_carries_are_empty),
            "All ciphertexts must have empty carries"
        );

        let message_modulus = self.key.message_modulus.0;
        let carry_modulus = self.key.carry_modulus.0;
        let total_modulus = message_modulus * carry_modulus;
        let message_max = message_modulus - 1;

        let num_elements_to_fill_carry = (total_modulus - 1) / message_max;

        let mut tmp_out = Vec::new();

        let mut carries = Vec::<Ciphertext>::new();
        while ciphertexts.len() > num_elements_to_fill_carry {
            let mut chunks_iter = ciphertexts.par_chunks_exact_mut(num_elements_to_fill_carry);
            let remainder_len = chunks_iter.remainder().len();

            chunks_iter
                .map(|chunk| {
                    let addition_range = self.unchecked_sum_ciphertext_chunk(chunk);
                    let s = &mut chunk[0];

                    let mut carry_ct = s.clone();
                    rayon::join(
                        || {
                            s.blocks[addition_range.clone()]
                                .par_iter_mut()
                                .for_each(|block| {
                                    self.key.message_extract_assign(block);
                                });
                        },
                        || {
                            // Contrary to non overflowing version we always extract all carries
                            // as we need to track overflows
                            carry_ct.blocks[addition_range.clone()]
                                .par_iter_mut()
                                .for_each(|block| {
                                    self.key.carry_extract_assign(block);
                                });
                            // Blocks for which we do not extract carries, means carry value is 0
                            for block in &mut carry_ct.blocks[..*addition_range.start()] {
                                self.key.create_trivial_assign(block, 0);
                            }
                            for block in &mut carry_ct.blocks[*addition_range.end() + 1..] {
                                self.key.create_trivial_assign(block, 0);
                            }
                        },
                    );

                    let out_carry = if *addition_range.end() == num_blocks - 1 {
                        let carry = carry_ct.blocks[num_blocks - 1].clone();
                        self.key
                            .create_trivial_assign(carry_ct.blocks.last_mut().unwrap(), 0);
                        carry
                    } else {
                        self.key.create_trivial(0)
                    };
                    carry_ct.blocks.rotate_right(1);

                    (s.clone(), carry_ct, out_carry)
                })
                .collect_into_vec(&mut tmp_out);

            // tmp_out elements are tuple of 3 elements (message, carry, last_block_carry)
            let num_ct_created = tmp_out.len() * 2;
            // Ciphertexts not treated in this iteration are at the end of ciphertexts vec.
            // the rotation will make them 'wrap around' and be placed at range index
            // (num_ct_created..remainder_len + num_ct_created)
            // We will then fill the indices in range (0..num_ct_created)
            ciphertexts.rotate_right(remainder_len + num_ct_created);

            // Drain elements out of tmp_out to replace them
            // at the beginning of the ciphertexts left to add
            for (i, (m, c, out_carry)) in tmp_out.drain(..).enumerate() {
                ciphertexts[i * 2] = m;
                ciphertexts[(i * 2) + 1] = c;
                carries.push(out_carry);
            }
            ciphertexts.truncate(num_ct_created + remainder_len);
        }

        // Now we will add the last chunk of terms
        // just as was done above, however we do it
        // we want to use an addition that leaves
        // the resulting ciphertext with empty carries
        let (result, rest) = ciphertexts.split_first_mut().unwrap();
        for term in rest.iter() {
            self.unchecked_add_assign(result, term);
        }

        let (message_blocks, carry_blocks) = rayon::join(
            || {
                result
                    .blocks
                    .par_iter()
                    .map(|block| self.key.message_extract(block))
                    .collect::<Vec<_>>()
            },
            || {
                let mut carry_blocks = Vec::with_capacity(num_blocks);
                result
                    .blocks
                    .par_iter()
                    .map(|block| self.key.carry_extract(block))
                    .collect_into_vec(&mut carry_blocks);
                carries.push(carry_blocks.pop().unwrap());
                carry_blocks.insert(0, self.key.create_trivial(0));
                carry_blocks
            },
        );

        let ((result, overflowed), any_sum_overflowed) = rayon::join(
            || {
                let mut result = RadixCiphertext::from(message_blocks);
                let carry = RadixCiphertext::from(carry_blocks);
                let overflowed =
                    self.unsigned_overflowing_add_assign_parallelized(&mut result, &carry);
                assert!(result.block_carries_are_empty());
                (result, overflowed)
            },
            || {
                let mut carries = RadixCiphertext::from(carries);
                carries.blocks.retain(|block| block.degree.get() != 0);
                self.scalar_ne_parallelized(&carries, 0)
            },
        );

        let overflowed = self.boolean_bitor(&overflowed, &any_sum_overflowed);

        Some((result, overflowed))
    }

    /// Computes the sum of the unsigned ciphertexts in parallel.
    /// Returns a boolean indicating if the sum overflowed, that is,
    /// the result did not fit in a ciphertext.
    ///
    /// See [Self::unchecked_sum_ciphertexts_vec_parallelized]
    pub fn unchecked_unsigned_overflowing_sum_ciphertexts_parallelized<'a, C>(
        &self,
        ciphertexts: C,
    ) -> Option<(RadixCiphertext, BooleanBlock)>
    where
        C: IntoIterator<Item = &'a RadixCiphertext>,
    {
        let ciphertexts = ciphertexts.into_iter().map(Clone::clone).collect();
        self.unchecked_unsigned_overflowing_sum_ciphertexts_vec_parallelized(ciphertexts)
    }

    /// Computes the sum of the unsigned ciphertexts in parallel.
    /// Returns a boolean indicating if the sum overflowed, that is,
    /// the result did not fit in a ciphertext.
    ///
    /// - Returns None if ciphertexts is empty
    ///
    /// See [Self::unchecked_sum_ciphertexts_parallelized] for constraints
    pub fn unsigned_overflowing_sum_ciphertexts_parallelized<'a, C>(
        &self,
        ciphertexts: C,
    ) -> Option<(RadixCiphertext, BooleanBlock)>
    where
        C: IntoIterator<Item = &'a RadixCiphertext>,
    {
        let mut ciphertexts = ciphertexts
            .into_iter()
            .map(Clone::clone)
            .collect::<Vec<_>>();
        ciphertexts
            .par_iter_mut()
            .filter(|ct| ct.block_carries_are_empty())
            .for_each(|ct| {
                if !ct.block_carries_are_empty() {
                    self.full_propagate_parallelized(&mut *ct);
                }
            });

        self.unchecked_unsigned_overflowing_sum_ciphertexts_vec_parallelized(ciphertexts)
    }

    /// Computes the sum of the unsigned ciphertexts in parallel.
    /// Returns a boolean indicating if the sum overflowed, that is,
    /// the result did not fit in a ciphertext.
    ///
    /// - Returns None if ciphertexts is empty
    ///
    /// See [Self::unchecked_sum_ciphertexts_parallelized] for constraints
    pub fn smart_unsigned_overflowing_sum_ciphertexts_parallelized<C>(
        &self,
        mut ciphertexts: C,
    ) -> Option<(RadixCiphertext, BooleanBlock)>
    where
        C: AsMut<[RadixCiphertext]> + AsRef<[RadixCiphertext]>,
    {
        ciphertexts.as_mut().par_iter_mut().for_each(|ct| {
            if !ct.block_carries_are_empty() {
                self.full_propagate_parallelized(ct);
            }
        });

        self.unchecked_unsigned_overflowing_sum_ciphertexts_parallelized(ciphertexts.as_ref())
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
