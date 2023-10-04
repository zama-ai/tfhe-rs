use crate::integer::ciphertext::IntegerRadixCiphertext;
use crate::integer::{RadixCiphertext, ServerKey};
use crate::shortint::Ciphertext;

use rayon::prelude::*;

#[repr(u64)]
#[derive(PartialEq, Eq)]
enum OutputCarry {
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
        if !self.is_add_possible(ct_left, ct_right) {
            rayon::join(
                || self.full_propagate_parallelized(ct_left),
                || self.full_propagate_parallelized(ct_right),
            );
        }
        self.unchecked_add(ct_left, ct_right)
    }

    pub fn smart_add_assign_parallelized<T>(&self, ct_left: &mut T, ct_right: &mut T)
    where
        T: IntegerRadixCiphertext,
    {
        if !self.is_add_possible(ct_left, ct_right) {
            rayon::join(
                || self.full_propagate_parallelized(ct_left),
                || self.full_propagate_parallelized(ct_right),
            );
        }
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
            self.unchecked_add_assign_parallelized_low_latency(lhs, rhs);
        } else {
            self.unchecked_add_assign(lhs, rhs);
            self.full_propagate_parallelized(lhs);
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

        // The fully parallelized way introduces more work
        // and so is slower for low number of blocks
        const MIN_NUM_BLOCKS: usize = 6;
        let has_enough_blocks = ct.blocks().len() >= MIN_NUM_BLOCKS;
        if !has_enough_blocks {
            return false;
        }

        // Use rayon to get that number as the implementation uses rayon for parallelism
        let has_enough_threads = rayon::current_num_threads() >= ct.blocks().len();
        if !has_enough_threads {
            return false;
        }

        true
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
    /// # Requirements
    ///
    /// - The parameters have 4 bits in total
    /// - Adding rhs to lhs must not consume more than one carry
    ///
    /// # Output
    ///
    /// - lhs will have its carries empty
    pub(crate) fn unchecked_add_assign_parallelized_low_latency<T>(&self, lhs: &mut T, rhs: &T)
    where
        T: IntegerRadixCiphertext,
    {
        let degree_after_add_does_not_go_beyond_first_carry = lhs
            .blocks()
            .iter()
            .zip(rhs.blocks().iter())
            .all(|(bl, br)| {
                let degree_after_add = bl.degree.0 + br.degree.0;
                degree_after_add < (self.key.message_modulus.0 * 2)
            });
        assert!(degree_after_add_does_not_go_beyond_first_carry);

        self.unchecked_add_assign_parallelized(lhs, rhs);
        self.propagate_single_carry_parallelized_low_latency(lhs)
    }

    /// This function takes an input ciphertext for which at most one bit of carry
    /// is consumed in each block, and does the carry propagation in place.
    ///
    /// Used in (among other) 'default' addition:
    /// - first unchecked_add
    /// - at this point at most on bit of carry is taken
    /// - use this function to propagate them in parallel
    pub(crate) fn propagate_single_carry_parallelized_low_latency<T>(&self, ct: &mut T)
    where
        T: IntegerRadixCiphertext,
    {
        let generates_or_propagates = self.generate_init_carry_array(ct);
        let (input_carries, _) =
            self.compute_carry_propagation_parallelized_low_latency(generates_or_propagates);

        ct.blocks_mut()
            .par_iter_mut()
            .zip(input_carries.par_iter())
            .for_each(|(block, input_carry)| {
                self.key.unchecked_add_assign(block, input_carry);
                self.key.message_extract_assign(block);
            });
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
        // The output carry of block i-1 becomes the input
        // carry of block i
        carries_out.rotate_right(1);
        (carries_out, last_block_out_carry)
    }

    pub(crate) fn compute_prefix_sum_hillis_steele<F>(
        &self,
        mut generates_or_propagates: Vec<Ciphertext>,
        sum_function: F,
    ) -> Vec<Ciphertext>
    where
        F: for<'a, 'b> Fn(&'a mut Ciphertext, &'b Ciphertext) + Sync,
    {
        debug_assert!(self.key.message_modulus.0 * self.key.carry_modulus.0 >= (1 << 4));

        let num_blocks = generates_or_propagates.len();
        let num_steps = generates_or_propagates.len().ilog2() as usize;

        let mut space = 1;
        let mut step_output = generates_or_propagates.clone();
        for _ in 0..=num_steps {
            step_output[space..num_blocks]
                .par_iter_mut()
                .enumerate()
                .for_each(|(i, block)| {
                    let prev_block_carry = &generates_or_propagates[i];
                    sum_function(block, prev_block_carry);
                });
            for i in space..num_blocks {
                generates_or_propagates[i].clone_from(&step_output[i]);
            }

            space *= 2;
        }

        generates_or_propagates
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
                let degree_after_add = bl.degree.0 + br.degree.0;
                degree_after_add < (self.key.message_modulus.0 * 2)
            });
        assert!(degree_after_add_does_not_go_beyond_first_carry);
        debug_assert!(self.key.message_modulus.0 * self.key.carry_modulus.0 >= (1 << 3));

        self.unchecked_add_assign_parallelized(lhs, rhs);
        let generates_or_propagates = self.generate_init_carry_array(lhs);
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

    pub(super) fn generate_init_carry_array<T>(
        &self,
        sum_ct: &T,
    ) -> Vec<crate::shortint::Ciphertext>
    where
        T: IntegerRadixCiphertext,
    {
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

        let mut generates_or_propagates = Vec::with_capacity(sum_ct.blocks().len());
        sum_ct
            .blocks()
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

    /// op must be associative and commutative
    pub fn smart_binary_op_seq_parallelized<'this, 'item, T>(
        &'this self,
        ct_seq: impl IntoIterator<Item = &'item mut T>,
        op: impl for<'a> Fn(&'a ServerKey, &'a mut T, &'a mut T) -> T + Sync,
    ) -> Option<T>
    where
        T: IntegerRadixCiphertext + 'item + From<Vec<crate::shortint::Ciphertext>>,
    {
        enum CiphertextCow<'a, C: IntegerRadixCiphertext> {
            Borrowed(&'a mut C),
            Owned(C),
        }
        impl<C: IntegerRadixCiphertext> CiphertextCow<'_, C> {
            fn as_mut(&mut self) -> &mut C {
                match self {
                    CiphertextCow::Borrowed(b) => b,
                    CiphertextCow::Owned(o) => o,
                }
            }
        }

        let ct_seq = ct_seq
            .into_iter()
            .map(CiphertextCow::Borrowed)
            .collect::<Vec<_>>();
        let op = &op;

        // overhead of dynamic dispatch is negligible compared to multithreading, PBS, etc.
        // we defer all calls to a single implementation to avoid code bloat and long compile
        // times
        #[allow(clippy::type_complexity)]
        fn reduce_impl<C>(
            sks: &ServerKey,
            mut ct_seq: Vec<CiphertextCow<C>>,
            op: &(dyn for<'a> Fn(&'a ServerKey, &'a mut C, &'a mut C) -> C + Sync),
        ) -> Option<C>
        where
            C: IntegerRadixCiphertext + From<Vec<crate::shortint::Ciphertext>>,
        {
            use rayon::prelude::*;

            if ct_seq.is_empty() {
                None
            } else {
                // we repeatedly divide the number of terms by two by iteratively reducing
                // consecutive terms in the array
                let num_blocks = ct_seq[0].as_mut().blocks().len();
                while ct_seq.len() > 1 {
                    let mut results =
                        vec![sks.create_trivial_radix(0u64, num_blocks); ct_seq.len() / 2];

                    // if the number of elements is odd, we skip the first element
                    let untouched_prefix = ct_seq.len() % 2;
                    let ct_seq_slice = &mut ct_seq[untouched_prefix..];

                    results
                        .par_iter_mut()
                        .zip(ct_seq_slice.par_chunks_exact_mut(2))
                        .for_each(|(ct_res, chunk)| {
                            let (first, second) = chunk.split_at_mut(1);
                            let first = first[0].as_mut();
                            let second = second[0].as_mut();
                            *ct_res = op(sks, first, second);
                        });

                    ct_seq.truncate(untouched_prefix);
                    ct_seq.extend(results.into_iter().map(CiphertextCow::Owned));
                }

                let sum = ct_seq.pop().unwrap();

                Some(match sum {
                    CiphertextCow::Borrowed(b) => b.clone(),
                    CiphertextCow::Owned(o) => o,
                })
            }
        }

        reduce_impl(self, ct_seq, op)
    }

    /// op must be associative and commutative
    pub fn default_binary_op_seq_parallelized<'this, 'item, T>(
        &'this self,
        ct_seq: impl IntoIterator<Item = &'item T>,
        op: impl for<'a> Fn(&'a ServerKey, &'a T, &'a T) -> T + Sync,
    ) -> Option<T>
    where
        T: IntegerRadixCiphertext + 'item + From<Vec<crate::shortint::Ciphertext>>,
    {
        enum CiphertextCow<'a, C: IntegerRadixCiphertext> {
            Borrowed(&'a C),
            Owned(C),
        }
        impl<C: IntegerRadixCiphertext> CiphertextCow<'_, C> {
            fn as_ref(&self) -> &C {
                match self {
                    CiphertextCow::Borrowed(b) => b,
                    CiphertextCow::Owned(o) => o,
                }
            }
        }

        let ct_seq = ct_seq
            .into_iter()
            .map(CiphertextCow::Borrowed)
            .collect::<Vec<_>>();
        let op = &op;

        // overhead of dynamic dispatch is negligible compared to multithreading, PBS, etc.
        // we defer all calls to a single implementation to avoid code bloat and long compile
        // times
        #[allow(clippy::type_complexity)]
        fn reduce_impl<C>(
            sks: &ServerKey,
            mut ct_seq: Vec<CiphertextCow<C>>,
            op: &(dyn for<'a> Fn(&'a ServerKey, &'a C, &'a C) -> C + Sync),
        ) -> Option<C>
        where
            C: IntegerRadixCiphertext + From<Vec<crate::shortint::Ciphertext>>,
        {
            use rayon::prelude::*;

            if ct_seq.is_empty() {
                None
            } else {
                // we repeatedly divide the number of terms by two by iteratively reducing
                // consecutive terms in the array
                let num_blocks = ct_seq[0].as_ref().blocks().len();
                while ct_seq.len() > 1 {
                    let mut results =
                        vec![sks.create_trivial_radix(0u64, num_blocks); ct_seq.len() / 2];
                    // if the number of elements is odd, we skip the first element
                    let untouched_prefix = ct_seq.len() % 2;
                    let ct_seq_slice = &mut ct_seq[untouched_prefix..];

                    results
                        .par_iter_mut()
                        .zip(ct_seq_slice.par_chunks_exact(2))
                        .for_each(|(ct_res, chunk)| {
                            let first = chunk[0].as_ref();
                            let second = chunk[1].as_ref();
                            *ct_res = op(sks, first, second);
                        });

                    ct_seq.truncate(untouched_prefix);
                    ct_seq.extend(results.into_iter().map(CiphertextCow::Owned));
                }

                let sum = ct_seq.pop().unwrap();

                Some(match sum {
                    CiphertextCow::Borrowed(b) => b.clone(),
                    CiphertextCow::Owned(o) => o,
                })
            }
        }

        reduce_impl(self, ct_seq, op)
    }

    /// See [Self::unchecked_sum_ciphertexts_vec_parallelized] for constraints
    pub fn unchecked_sum_ciphertexts_slice_parallelized(
        &self,
        ciphertexts: &[RadixCiphertext],
    ) -> Option<RadixCiphertext> {
        self.unchecked_sum_ciphertexts_vec_parallelized(ciphertexts.to_vec())
    }

    /// Computes the sum of the ciphertexts in parallel.
    ///
    /// - Returns None if ciphertexts is empty
    ///
    /// - Expects all ciphertexts to have empty carries
    /// - Expects all ciphertexts to have the same size
    pub fn unchecked_sum_ciphertexts_vec_parallelized<T>(
        &self,
        mut ciphertexts: Vec<T>,
    ) -> Option<T>
    where
        T: IntegerRadixCiphertext,
    {
        if ciphertexts.is_empty() {
            return None;
        }

        if ciphertexts.len() == 1 {
            return Some(ciphertexts[0].clone());
        }

        if ciphertexts.len() == 2 {
            return Some(self.add_parallelized(&ciphertexts[0], &ciphertexts[1]));
        }

        let num_blocks = ciphertexts[0].blocks().len();
        assert!(
            ciphertexts[1..]
                .iter()
                .all(|ct| ct.blocks().len() == num_blocks),
            "Not all ciphertexts have the same number of blocks"
        );
        assert!(
            ciphertexts.iter().all(|ct| ct.block_carries_are_empty()),
            "All ciphertexts must have empty carries"
        );

        let message_modulus = self.key.message_modulus.0;
        let carry_modulus = self.key.carry_modulus.0;
        let total_modulus = message_modulus * carry_modulus;
        let message_max = message_modulus - 1;

        let num_elements_to_fill_carry = (total_modulus - 1) / message_max;

        let mut tmp_out = Vec::new();

        while ciphertexts.len() > num_elements_to_fill_carry {
            let mut chunks_iter = ciphertexts.par_chunks_exact_mut(num_elements_to_fill_carry);
            let remainder_len = chunks_iter.remainder().len();

            chunks_iter
                .map(|chunk| {
                    let (s, rest) = chunk.split_first_mut().unwrap();
                    let mut first_block_where_addition_happened = num_blocks - 1;
                    let mut last_block_where_addition_happened = num_blocks - 1;
                    for a in rest.iter() {
                        let first_block_to_add = a
                            .blocks()
                            .iter()
                            .position(|block| block.degree.0 != 0)
                            .unwrap_or(num_blocks);
                        first_block_where_addition_happened =
                            first_block_where_addition_happened.min(first_block_to_add);
                        let last_block_to_add = a
                            .blocks()
                            .iter()
                            .rev()
                            .position(|block| block.degree.0 != 0)
                            .map(|pos| num_blocks - pos - 1)
                            .unwrap_or(num_blocks - 1);
                        last_block_where_addition_happened =
                            last_block_where_addition_happened.max(last_block_to_add);
                        for (ct_left_i, ct_right_i) in s.blocks_mut()
                            [first_block_to_add..last_block_to_add + 1]
                            .iter_mut()
                            .zip(a.blocks()[first_block_to_add..last_block_to_add + 1].iter())
                        {
                            self.key.unchecked_add_assign(ct_left_i, ct_right_i);
                        }
                    }

                    // last carry is not interesting
                    let mut carry_blocks = s.blocks()
                        [first_block_where_addition_happened..last_block_where_addition_happened]
                        .to_vec();

                    let message_blocks = s.blocks_mut();

                    rayon::join(
                        || {
                            message_blocks[first_block_where_addition_happened
                                ..last_block_where_addition_happened + 1]
                                .par_iter_mut()
                                .for_each(|block| {
                                    self.key.message_extract_assign(block);
                                });
                        },
                        || {
                            carry_blocks.par_iter_mut().for_each(|block| {
                                self.key.carry_extract_assign(block);
                            });
                        },
                    );

                    let mut carry_ct = RadixCiphertext::from(carry_blocks);
                    let num_blocks_to_add = s.blocks().len() - carry_ct.blocks.len();
                    self.extend_radix_with_trivial_zero_blocks_lsb_assign(
                        &mut carry_ct,
                        num_blocks_to_add,
                    );
                    let carry_ct = T::from(carry_ct.blocks);
                    (s.clone(), carry_ct)
                })
                .collect_into_vec(&mut tmp_out);

            // tmp_out elements are tuple of 2 elements (message, carry)
            let num_ct_created = tmp_out.len() * 2;
            // Ciphertexts not treated in this iteration are at the end of ciphertexts vec.
            // the rotation will make them 'wrap around' and be placed at range index
            // (num_ct_created..remainder_len + num_ct_created)
            // We will then fill the indices in range (0..num_ct_created)
            ciphertexts.rotate_right(remainder_len + num_ct_created);

            // Drain elements out of tmp_out to replace them
            // at the beginning of the ciphertexts left to add
            for (i, (m, c)) in tmp_out.drain(..).enumerate() {
                ciphertexts[i * 2] = m;
                ciphertexts[(i * 2) + 1] = c;
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
                    .blocks()
                    .par_iter()
                    .map(|block| self.key.message_extract(block))
                    .collect::<Vec<_>>()
            },
            || {
                let mut carry_blocks = Vec::with_capacity(num_blocks);
                result.blocks()[..num_blocks - 1] // last carry is not interesting
                    .par_iter()
                    .map(|block| self.key.carry_extract(block))
                    .collect_into_vec(&mut carry_blocks);
                carry_blocks.insert(0, self.key.create_trivial(0));
                carry_blocks
            },
        );

        let mut result = T::from(message_blocks);
        let carry = T::from(carry_blocks);
        self.add_assign_parallelized(&mut result, &carry);
        assert!(result.block_carries_are_empty());

        Some(result)
    }
}
