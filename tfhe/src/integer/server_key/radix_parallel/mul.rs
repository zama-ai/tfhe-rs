use crate::integer::ciphertext::RadixCiphertext;
use crate::integer::ServerKey;
use rayon::prelude::*;

impl ServerKey {
    /// Computes homomorphically a multiplication between a ciphertext encrypting an integer value
    /// and another encrypting a shortint value.
    ///
    /// This function computes the operation without checking if it exceeds the capacity of the
    /// ciphertext.
    ///
    /// The result is assigned to the `ct_left` ciphertext.
    ///
    /// # Warning
    ///
    /// - Multithreaded
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks);
    ///
    /// let clear_1 = 170;
    /// let clear_2 = 3;
    ///
    /// // Encrypt two messages
    /// let mut ct_left = cks.encrypt(clear_1);
    /// let ct_right = cks.encrypt_one_block(clear_2);
    ///
    /// // Compute homomorphically a multiplication
    /// sks.unchecked_block_mul_assign_parallelized(&mut ct_left, &ct_right, 0);
    ///
    /// // Decrypt
    /// let res: u64 = cks.decrypt(&ct_left);
    /// assert_eq!((clear_1 * clear_2) % 256, res);
    /// ```
    pub fn unchecked_block_mul_assign_parallelized(
        &self,
        ct_left: &mut RadixCiphertext,
        ct_right: &crate::shortint::Ciphertext,
        index: usize,
    ) {
        *ct_left = self.unchecked_block_mul_parallelized(ct_left, ct_right, index);
    }

    /// Computes homomorphically a multiplication between a ciphertexts encrypting an integer
    /// value and another encrypting a shortint value.
    ///
    /// This function computes the operation without checking if it exceeds the capacity of the
    /// ciphertext.
    ///
    /// The result is returned as a new ciphertext.
    ///
    /// # Warning
    ///
    /// - Multithreaded
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks);
    ///
    /// let clear_1 = 55;
    /// let clear_2 = 3;
    ///
    /// // Encrypt two messages
    /// let ct_left = cks.encrypt(clear_1);
    /// let ct_right = cks.encrypt_one_block(clear_2);
    ///
    /// // Compute homomorphically a multiplication
    /// let ct_res = sks.unchecked_block_mul_parallelized(&ct_left, &ct_right, 0);
    ///
    /// // Decrypt
    /// let res: u64 = cks.decrypt(&ct_res);
    /// assert_eq!((clear_1 * clear_2) % 256, res);
    /// ```
    pub fn unchecked_block_mul_parallelized(
        &self,
        ct1: &RadixCiphertext,
        ct2: &crate::shortint::Ciphertext,
        index: usize,
    ) -> RadixCiphertext {
        let shifted_ct = self.blockshift(ct1, index);

        let mut result_lsb = shifted_ct.clone();
        let mut result_msb = shifted_ct;
        self.unchecked_block_mul_lsb_msb_parallelized(&mut result_lsb, &mut result_msb, ct2, index);
        result_msb = self.blockshift(&result_msb, 1);

        self.unchecked_add(&result_lsb, &result_msb)
    }

    /// Computes homomorphically a multiplication between a ciphertext encrypting integer value
    /// and another encrypting a shortint value.
    ///
    /// The result is returned as a new ciphertext.
    ///
    /// # Warning
    ///
    /// - Multithreaded
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks);
    ///
    /// let clear_1 = 170;
    /// let clear_2 = 3;
    ///
    /// // Encrypt two messages
    /// let mut ctxt_1 = cks.encrypt(clear_1);
    /// let ctxt_2 = cks.encrypt_one_block(clear_2);
    ///
    /// // Compute homomorphically a multiplication
    /// let ct_res = sks.smart_block_mul_parallelized(&mut ctxt_1, &ctxt_2, 0);
    ///
    /// // Decrypt
    /// let res: u64 = cks.decrypt(&ct_res);
    /// assert_eq!((clear_1 * clear_2) % 256, res);
    /// ```
    pub fn smart_block_mul_parallelized(
        &self,
        ct1: &mut RadixCiphertext,
        ct2: &crate::shortint::Ciphertext,
        index: usize,
    ) -> RadixCiphertext {
        //Makes sure we can do the multiplications
        self.full_propagate_parallelized(ct1);

        let shifted_ct = self.blockshift(ct1, index);

        let mut result_lsb = shifted_ct.clone();
        let mut result_msb = shifted_ct;
        self.unchecked_block_mul_lsb_msb_parallelized(&mut result_lsb, &mut result_msb, ct2, index);
        result_msb = self.blockshift(&result_msb, 1);

        self.smart_add_parallelized(&mut result_lsb, &mut result_msb)
    }

    /// Computes homomorphically a multiplication between a ciphertext encrypting integer value
    /// and another encrypting a shortint value.
    ///
    /// The result is returned as a new ciphertext.
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
    ///```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks);
    ///
    /// let clear_1 = 170;
    /// let clear_2 = 3;
    ///
    /// // Encrypt two messages
    /// let ctxt_1 = cks.encrypt(clear_1);
    /// let ctxt_2 = cks.encrypt_one_block(clear_2);
    ///
    /// // Compute homomorphically a multiplication
    /// let ct_res = sks.block_mul_parallelized(&ctxt_1, &ctxt_2, 0);
    ///
    /// // Decrypt
    /// let res: u64 = cks.decrypt(&ct_res);
    /// assert_eq!((clear_1 * clear_2) % 256, res);
    /// ```
    pub fn block_mul_parallelized(
        &self,
        ct1: &RadixCiphertext,
        ct2: &crate::shortint::Ciphertext,
        index: usize,
    ) -> RadixCiphertext {
        let mut ct_res = ct1.clone();
        self.block_mul_assign_parallelized(&mut ct_res, ct2, index);
        ct_res
    }

    pub fn block_mul_assign_parallelized(
        &self,
        ct1: &mut RadixCiphertext,
        ct2: &crate::shortint::Ciphertext,
        index: usize,
    ) {
        let mut tmp_rhs: crate::shortint::Ciphertext;

        let (lhs, rhs) = match (ct1.block_carries_are_empty(), ct2.carry_is_empty()) {
            (true, true) => (ct1, ct2),
            (true, false) => {
                tmp_rhs = ct2.clone();
                self.key.clear_carry_assign(&mut tmp_rhs);
                (ct1, &tmp_rhs)
            }
            (false, true) => {
                self.full_propagate_parallelized(ct1);
                (ct1, ct2)
            }
            (false, false) => {
                tmp_rhs = ct2.clone();
                rayon::join(
                    || self.full_propagate_parallelized(ct1),
                    || self.key.clear_carry_assign(&mut tmp_rhs),
                );
                (ct1, &tmp_rhs)
            }
        };
        self.unchecked_block_mul_assign_parallelized(lhs, rhs, index);
        self.full_propagate_parallelized(lhs);
    }

    fn unchecked_block_mul_lsb_msb_parallelized(
        &self,
        result_lsb: &mut RadixCiphertext,
        result_msb: &mut RadixCiphertext,
        ct2: &crate::shortint::Ciphertext,
        index: usize,
    ) {
        let len = result_msb.blocks.len() - 1;
        rayon::join(
            || {
                result_lsb.blocks[index..]
                    .par_iter_mut()
                    .for_each(|res_lsb_i| {
                        self.key.unchecked_mul_lsb_assign(res_lsb_i, ct2);
                    });
            },
            || {
                result_msb.blocks[index..len]
                    .par_iter_mut()
                    .for_each(|res_msb_i| {
                        self.key.unchecked_mul_msb_assign(res_msb_i, ct2);
                    });
            },
        );
    }

    pub fn smart_block_mul_assign_parallelized(
        &self,
        ct1: &mut RadixCiphertext,
        ct2: &crate::shortint::Ciphertext,
        index: usize,
    ) {
        *ct1 = self.smart_block_mul_parallelized(ct1, ct2, index);
    }

    /// Sums the terms, putting the result into lhs
    ///
    /// This sums all of the terms in `terms` and overwrites
    /// `lhs` with the result.
    ///
    /// Each of the input term is expected to have _at most_ one carry consumed
    pub(crate) fn sum_multiplication_terms_into(
        &self,
        lhs: &mut RadixCiphertext,
        mut terms: Vec<RadixCiphertext>,
    ) {
        if terms.is_empty() {
            for block in &mut lhs.blocks {
                self.key.create_trivial_assign(block, 0);
            }
            return;
        }

        let num_blocks = lhs.blocks.len();

        let num_bits_in_carry = self.key.carry_modulus.0.ilog2() as u64;
        // Among those bits of carry, we know one is already consumed by
        // the last step of the unchecked_block_mul_parallelized
        // for each of the term.
        //
        // It means we can only do num_bits_in_carry - 1 additions
        // Which then means we can iter on chunks of num_bits_in_carry
        // to add them up as it will result in num_bits_in_carry - 1 additions
        //
        // If we have only one bit of carry, it is consumed
        // and thus the faster algorithm is not possible
        // so we use another one that still works
        if num_bits_in_carry == 1 {
            *lhs = self
                .smart_binary_op_seq_parallelized(&mut terms, |sks, a, b| {
                    sks.smart_add_parallelized(a, b)
                })
                .unwrap_or_else(|| self.create_trivial_zero_radix(num_blocks));

            self.full_propagate_parallelized(lhs);
            return;
        }

        let chunk_size = num_bits_in_carry as usize;

        // For the last chunk, we want to finish it off
        // using an addition that does not leave the resulting ciphertext with
        // non empty carries.
        //
        // We use the fact, that terms are going to be padded with trivial ciphertext
        // to avoid unecessary work.
        //
        // (0) = Trivial, (1) = Non-Trivial
        // a: (0) (1) (1) (1)
        // b: (0) (0) (1) (1)
        //             ^
        //             |- only need to start adding from here,
        //                and only need to handle carries from here
        //
        // As we want to handle the last chunk separately
        // only reduce until we have one last chunk
        while terms.len() > chunk_size {
            terms.par_chunks_exact_mut(chunk_size).for_each(|chunk| {
                let (s, rest) = chunk.split_first_mut().unwrap();
                let mut first_block_where_addition_happenned = num_blocks - 1;
                let mut last_block_where_addition_happenned = num_blocks - 1;
                for a in rest.iter() {
                    let first_block_to_add = a
                        .blocks
                        .iter()
                        .position(|block| block.degree.0 != 0)
                        .unwrap_or(num_blocks);
                    first_block_where_addition_happenned =
                        first_block_where_addition_happenned.min(first_block_to_add);
                    let last_block_to_add = a
                        .blocks
                        .iter()
                        .rev()
                        .position(|block| block.degree.0 != 0)
                        .map(|pos| num_blocks - pos - 1)
                        .unwrap_or(num_blocks - 1);
                    last_block_where_addition_happenned =
                        last_block_where_addition_happenned.max(last_block_to_add);
                    for (ct_left_i, ct_right_i) in s.blocks
                        [first_block_to_add..last_block_to_add + 1]
                        .iter_mut()
                        .zip(a.blocks[first_block_to_add..last_block_to_add + 1].iter())
                    {
                        self.key.unchecked_add_assign(ct_left_i, ct_right_i);
                    }
                }

                // last carry is not interesting
                let mut carry_blocks = s.blocks
                    [first_block_where_addition_happenned..last_block_where_addition_happenned + 1]
                    .to_vec();

                let message_blocks = &mut s.blocks;

                rayon::join(
                    || {
                        message_blocks[first_block_where_addition_happenned
                            ..last_block_where_addition_happenned + 1]
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

                for (ct_left_i, ct_right_i) in message_blocks
                    [first_block_where_addition_happenned + 1..]
                    .iter_mut()
                    .zip(carry_blocks.iter())
                {
                    self.key.unchecked_add_assign(ct_left_i, ct_right_i);
                }
            });

            // terms is organized like so:
            // [S, C,..., S, C,.., S, C,..,U, U]
            // where S is the sum of its following C as done by
            // the chunked loop, and U are elements that did not create a complete chunk
            //
            // We want to get it to [S, S, S, U, U, C, C...]
            // then truncate to only keep the Ss
            for index_of_first_chunk_block in (0..terms.len()).step_by(chunk_size) {
                let from = index_of_first_chunk_block;
                let to = index_of_first_chunk_block / chunk_size;
                terms.swap(from, to);
            }
            let rest = terms.len() % chunk_size;
            for i in 0..rest {
                let from = (terms.len() / chunk_size) + 1 + i;
                let to = terms.len() - 1 - i;
                terms.swap(from, to);
            }
            terms.truncate((terms.len() / chunk_size) + rest);
        }
        assert!(terms.len() <= chunk_size);

        // Now we will add the last chunk of terms
        // just as was done above, however we do it
        // we want to use an addition that leaves
        // the resulting ciphertext with empty carries
        let (result, rest) = terms.split_first_mut().unwrap();
        for term in rest.iter() {
            self.unchecked_add_assign(result, term);
        }

        std::mem::swap(&mut lhs.blocks, &mut result.blocks);
        self.full_propagate_parallelized(lhs);
        assert!(lhs.block_carries_are_empty());
    }

    /// Computes homomorphically a multiplication between two ciphertexts encrypting integer values.
    ///
    /// This function computes the operation without checking if it exceeds the capacity of the
    /// ciphertext.
    ///
    /// The result is assigned to the `ct_left` ciphertext.
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
    /// let clear_1 = 255;
    /// let clear_2 = 143;
    ///
    /// // Encrypt two messages
    /// let mut ctxt_1 = cks.encrypt(clear_1);
    /// let ctxt_2 = cks.encrypt(clear_2);
    ///
    /// // Compute homomorphically a multiplication
    /// let ct_res = sks.unchecked_mul_parallelized(&mut ctxt_1, &ctxt_2);
    ///
    /// // Decrypt
    /// let res: u64 = cks.decrypt(&ct_res);
    /// assert_eq!((clear_1 * clear_2) % 256, res);
    /// ```
    pub fn unchecked_mul_assign_parallelized(
        &self,
        lhs: &mut RadixCiphertext,
        rhs: &RadixCiphertext,
    ) {
        if rhs.holds_boolean_value() {
            self.zero_out_if_condition_is_false(lhs, &rhs.blocks[0]);
            return;
        }

        if lhs.holds_boolean_value() {
            let mut cloned_rhs = rhs.clone();
            self.zero_out_if_condition_is_false(&mut cloned_rhs, &lhs.blocks[0]);
            *lhs = cloned_rhs;
            return;
        }

        let terms = rhs
            .blocks
            .par_iter()
            .enumerate()
            .filter_map(|(i, block)| {
                if block.degree.0 == 0 {
                    // Block is a trivial 0, no need to waste time multiplying
                    None
                } else {
                    Some(self.unchecked_block_mul_parallelized(lhs, block, i))
                }
            })
            .collect::<Vec<_>>();

        self.sum_multiplication_terms_into(lhs, terms);
    }

    /// Computes homomorphically a multiplication between two ciphertexts encrypting integer values.
    ///
    /// This function computes the operation without checking if it exceeds the capacity of the
    /// ciphertext.
    ///
    /// The result is returned as a new ciphertext.
    ///
    /// # Warning
    ///
    /// - Multithreaded
    pub fn unchecked_mul_parallelized(
        &self,
        lhs: &RadixCiphertext,
        rhs: &RadixCiphertext,
    ) -> RadixCiphertext {
        let mut result = lhs.clone();
        self.unchecked_mul_assign_parallelized(&mut result, rhs);
        result
    }

    /// Computes homomorphically a multiplication between two ciphertexts encrypting integer values.
    ///
    /// The result is assigned to the `ct_left` ciphertext.
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
    /// let clear_1 = 170;
    /// let clear_2 = 6;
    ///
    /// // Encrypt two messages
    /// let mut ctxt_1 = cks.encrypt(clear_1);
    /// let mut ctxt_2 = cks.encrypt(clear_2);
    ///
    /// // Compute homomorphically a multiplication
    /// let ct_res = sks.smart_mul_parallelized(&mut ctxt_1, &mut ctxt_2);
    /// // Decrypt
    /// let res: u64 = cks.decrypt(&ct_res);
    /// assert_eq!((clear_1 * clear_2) % 256, res);
    /// ```
    pub fn smart_mul_assign_parallelized(
        &self,
        lhs: &mut RadixCiphertext,
        rhs: &mut RadixCiphertext,
    ) {
        rayon::join(
            || {
                if !lhs.block_carries_are_empty() {
                    self.full_propagate_parallelized(lhs)
                }
            },
            || {
                if !rhs.block_carries_are_empty() {
                    self.full_propagate_parallelized(rhs)
                }
            },
        );

        self.unchecked_mul_assign_parallelized(lhs, rhs);
    }

    /// Computes homomorphically a multiplication between two ciphertexts encrypting integer values.
    ///
    /// The result is returned as a new ciphertext.
    ///
    /// # Warning
    ///
    /// - Multithreaded
    pub fn smart_mul_parallelized(
        &self,
        lhs: &mut RadixCiphertext,
        rhs: &mut RadixCiphertext,
    ) -> RadixCiphertext {
        rayon::join(
            || {
                if !lhs.block_carries_are_empty() {
                    self.full_propagate_parallelized(lhs)
                }
            },
            || {
                if !rhs.block_carries_are_empty() {
                    self.full_propagate_parallelized(rhs)
                }
            },
        );

        self.unchecked_mul_parallelized(lhs, rhs)
    }

    /// Computes homomorphically a multiplication between two ciphertexts encrypting integer values.
    ///
    /// The result is assigned to the `ct_left` ciphertext.
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
    /// let clear_1 = 170;
    /// let clear_2 = 6;
    ///
    /// // Encrypt two messages
    /// let ctxt_1 = cks.encrypt(clear_1);
    /// let ctxt_2 = cks.encrypt(clear_2);
    ///
    /// // Compute homomorphically a multiplication
    /// let ct_res = sks.mul_parallelized(&ctxt_1, &ctxt_2);
    /// // Decrypt
    /// let res: u64 = cks.decrypt(&ct_res);
    /// assert_eq!((clear_1 * clear_2) % 256, res);
    /// ```
    pub fn mul_parallelized(
        &self,
        ct1: &RadixCiphertext,
        ct2: &RadixCiphertext,
    ) -> RadixCiphertext {
        let mut ct_res = ct1.clone();
        self.mul_assign_parallelized(&mut ct_res, ct2);
        ct_res
    }

    pub fn mul_assign_parallelized(&self, ct1: &mut RadixCiphertext, ct2: &RadixCiphertext) {
        let mut tmp_rhs: RadixCiphertext;

        let (lhs, rhs) = match (ct1.block_carries_are_empty(), ct2.block_carries_are_empty()) {
            (true, true) => (ct1, ct2),
            (true, false) => {
                tmp_rhs = ct2.clone();
                self.full_propagate_parallelized(&mut tmp_rhs);
                (ct1, &tmp_rhs)
            }
            (false, true) => {
                self.full_propagate_parallelized(ct1);
                (ct1, ct2)
            }
            (false, false) => {
                tmp_rhs = ct2.clone();
                rayon::join(
                    || self.full_propagate_parallelized(ct1),
                    || self.full_propagate_parallelized(&mut tmp_rhs),
                );
                (ct1, &tmp_rhs)
            }
        };

        self.unchecked_mul_assign_parallelized(lhs, rhs);
    }
}
