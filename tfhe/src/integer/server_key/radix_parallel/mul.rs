use crate::integer::ciphertext::IntegerRadixCiphertext;
use crate::integer::{BooleanBlock, RadixCiphertext, ServerKey, SignedRadixCiphertext, I256};
use crate::shortint::ciphertext::{Degree, NoiseLevel};
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
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    ///
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, num_blocks);
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
    pub fn unchecked_block_mul_assign_parallelized<T>(
        &self,
        ct_left: &mut T,
        ct_right: &crate::shortint::Ciphertext,
        index: usize,
    ) where
        T: IntegerRadixCiphertext,
    {
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
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    ///
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, num_blocks);
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
    pub fn unchecked_block_mul_parallelized<T>(
        &self,
        ct1: &T,
        ct2: &crate::shortint::Ciphertext,
        index: usize,
    ) -> T
    where
        T: IntegerRadixCiphertext,
    {
        let shifted_ct = self.blockshift(ct1, index);
        let mut result_lsb = shifted_ct.clone();

        if self.message_modulus().0 == 2 {
            result_lsb.blocks_mut()[index..]
                .par_iter_mut()
                .for_each(|res_lsb_i| {
                    self.key.unchecked_mul_lsb_assign(res_lsb_i, ct2);
                });

            result_lsb
        } else {
            let mut result_msb = shifted_ct;
            self.unchecked_block_mul_lsb_msb_parallelized(
                &mut result_lsb,
                &mut result_msb,
                ct2,
                index,
            );
            result_msb = self.blockshift(&result_msb, 1);

            self.unchecked_add(&result_lsb, &result_msb)
        }
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
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    ///
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, num_blocks);
    ///
    /// let clear_1 = 170;
    /// let clear_2 = 3;
    ///
    /// // Encrypt two messages
    /// let mut ctxt_1 = cks.encrypt(clear_1);
    /// let mut ctxt_2 = cks.encrypt_one_block(clear_2);
    ///
    /// // Compute homomorphically a multiplication
    /// let ct_res = sks.smart_block_mul_parallelized(&mut ctxt_1, &mut ctxt_2, 0);
    ///
    /// // Decrypt
    /// let res: u64 = cks.decrypt(&ct_res);
    /// assert_eq!((clear_1 * clear_2) % 256, res);
    /// ```
    // by convention smart operations take mut refs to their inputs, even if they do not modify them
    #[allow(clippy::needless_pass_by_ref_mut)]
    pub fn smart_block_mul_parallelized<T>(
        &self,
        ct1: &mut T,
        ct2: &mut crate::shortint::Ciphertext,
        index: usize,
    ) -> T
    where
        T: IntegerRadixCiphertext,
    {
        // Makes sure we can do the multiplications
        if !ct1.block_carries_are_empty() {
            self.full_propagate_parallelized(ct1);
        }
        if ct2.noise_level() != NoiseLevel::NOMINAL || !ct2.carry_is_empty() {
            self.key.message_extract_assign(ct2);
        }

        let shifted_ct = self.blockshift(ct1, index);
        let mut result_lsb = shifted_ct.clone();

        if self.message_modulus().0 == 2 {
            result_lsb.blocks_mut()[index..]
                .par_iter_mut()
                .for_each(|res_lsb_i| {
                    self.key.unchecked_mul_lsb_assign(res_lsb_i, ct2);
                });

            result_lsb
        } else {
            let mut result_msb = shifted_ct;
            self.unchecked_block_mul_lsb_msb_parallelized(
                &mut result_lsb,
                &mut result_msb,
                ct2,
                index,
            );
            result_msb = self.blockshift(&result_msb, 1);

            self.smart_add_parallelized(&mut result_lsb, &mut result_msb)
        }
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
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    ///
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, num_blocks);
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
    pub fn block_mul_parallelized<T>(
        &self,
        ct1: &T,
        ct2: &crate::shortint::Ciphertext,
        index: usize,
    ) -> T
    where
        T: IntegerRadixCiphertext,
    {
        let mut ct_res = ct1.clone();
        self.block_mul_assign_parallelized(&mut ct_res, ct2, index);
        ct_res
    }

    pub fn block_mul_assign_parallelized<T>(
        &self,
        ct1: &mut T,
        ct2: &crate::shortint::Ciphertext,
        index: usize,
    ) where
        T: IntegerRadixCiphertext,
    {
        let mut tmp_rhs: crate::shortint::Ciphertext;
        let (lhs, rhs) = match (ct1.block_carries_are_empty(), ct2.carry_is_empty()) {
            (true, true) => (ct1, ct2),
            (true, false) => {
                tmp_rhs = ct2.clone();
                self.key.message_extract_assign(&mut tmp_rhs);
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
                    || self.key.message_extract_assign(&mut tmp_rhs),
                );
                (ct1, &tmp_rhs)
            }
        };

        self.unchecked_block_mul_assign_parallelized(lhs, rhs, index);
        self.full_propagate_parallelized(lhs);
    }

    fn unchecked_block_mul_lsb_msb_parallelized<T>(
        &self,
        result_lsb: &mut T,
        result_msb: &mut T,
        ct2: &crate::shortint::Ciphertext,
        index: usize,
    ) where
        T: IntegerRadixCiphertext,
    {
        let len = result_msb.blocks().len() - 1;
        rayon::join(
            || {
                result_lsb.blocks_mut()[index..]
                    .par_iter_mut()
                    .for_each(|res_lsb_i| {
                        self.key.unchecked_mul_lsb_assign(res_lsb_i, ct2);
                    });
            },
            || {
                result_msb.blocks_mut()[index..len]
                    .par_iter_mut()
                    .for_each(|res_msb_i| {
                        self.key.unchecked_mul_msb_assign(res_msb_i, ct2);
                    });
            },
        );
    }

    pub fn smart_block_mul_assign_parallelized<T>(
        &self,
        ct1: &mut T,
        ct2: &mut crate::shortint::Ciphertext,
        index: usize,
    ) where
        T: IntegerRadixCiphertext,
    {
        *ct1 = self.smart_block_mul_parallelized(ct1, ct2, index);
    }

    /// This functions computes the terms resulting from multiplying each block
    /// of rhs with lhs. When summed these terms will give the low part of the result.
    /// i.e. in a (lhs: Nbit * rhs: Nbit) multiplication, summing the terms will give a N bit result
    fn compute_terms_for_mul_low<T>(&self, lhs: &T, rhs: &T) -> Vec<T>
    where
        T: IntegerRadixCiphertext,
    {
        let message_modulus = self.key.message_modulus.0;

        let lsb_block_mul_lut = self
            .key
            .generate_lookup_table_bivariate(|x, y| (x * y) % message_modulus);

        let msb_block_mul_lut = self
            .key
            .generate_lookup_table_bivariate(|x, y| (x * y) / message_modulus);

        let message_part_terms_generator = rhs
            .blocks()
            .par_iter()
            .enumerate()
            .filter(|(_, block)| block.degree.get() != 0)
            .map(|(i, rhs_block)| {
                let mut result = self.blockshift(lhs, i);
                result.blocks_mut()[i..]
                    .par_iter_mut()
                    .filter(|block| block.degree.get() != 0)
                    .for_each(|lhs_block| {
                        self.key.unchecked_apply_lookup_table_bivariate_assign(
                            lhs_block,
                            rhs_block,
                            &lsb_block_mul_lut,
                        );
                    });

                result
            });

        if self.message_modulus().0 > 2 {
            // Multiplying 2 blocks generates some part this is in the carry
            // we have to compute them.
            message_part_terms_generator
                .chain(
                    rhs.blocks()[..rhs.blocks().len() - 1] // last block carry would be thrown away
                        .par_iter()
                        .enumerate()
                        .filter(|(_, block)| block.degree.get() != 0)
                        .map(|(i, rhs_block)| {
                            // Here we are doing (a * b) / modulus
                            // that is, getting the carry part of the block multiplication
                            // so the shift is one block longer
                            let mut result = self.blockshift(lhs, i + 1);
                            result.blocks_mut()[i + 1..]
                                .par_iter_mut()
                                .filter(|block| block.degree.get() != 0)
                                .for_each(|lhs_block| {
                                    self.key.unchecked_apply_lookup_table_bivariate_assign(
                                        lhs_block,
                                        rhs_block,
                                        &msb_block_mul_lut,
                                    );
                                });

                            result
                        }),
                )
                .collect::<Vec<_>>()
        } else {
            message_part_terms_generator.collect::<Vec<_>>()
        }
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
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    ///
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, num_blocks);
    ///
    /// let clear_1 = 255;
    /// let clear_2 = 143;
    ///
    /// // Encrypt two messages
    /// let ctxt_1 = cks.encrypt(clear_1);
    /// let ctxt_2 = cks.encrypt(clear_2);
    ///
    /// // Compute homomorphically a multiplication
    /// let ct_res = sks.unchecked_mul_parallelized(&ctxt_1, &ctxt_2);
    ///
    /// // Decrypt
    /// let res: u64 = cks.decrypt(&ct_res);
    /// assert_eq!((clear_1 * clear_2) % 256, res);
    /// ```
    pub fn unchecked_mul_assign_parallelized<T>(&self, lhs: &mut T, rhs: &T)
    where
        T: IntegerRadixCiphertext,
    {
        if rhs.holds_boolean_value() {
            self.zero_out_if_condition_is_false(lhs, &rhs.blocks()[0]);
            return;
        }

        if lhs.holds_boolean_value() {
            let mut cloned_rhs = rhs.clone();
            self.zero_out_if_condition_is_false(&mut cloned_rhs, &lhs.blocks()[0]);
            *lhs = cloned_rhs;
            return;
        }

        let terms = self.compute_terms_for_mul_low(lhs, rhs);

        if let Some(result) = self.unchecked_sum_ciphertexts_vec_parallelized(terms) {
            *lhs = result;
        } else {
            self.create_trivial_zero_assign_radix(lhs);
        }
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
    pub fn unchecked_mul_parallelized<T>(&self, lhs: &T, rhs: &T) -> T
    where
        T: IntegerRadixCiphertext,
    {
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
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    ///
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, num_blocks);
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
    pub fn smart_mul_assign_parallelized<T>(&self, lhs: &mut T, rhs: &mut T)
    where
        T: IntegerRadixCiphertext,
    {
        rayon::join(
            || {
                if !lhs.block_carries_are_empty() {
                    self.full_propagate_parallelized(lhs);
                }
            },
            || {
                if !rhs.block_carries_are_empty() {
                    self.full_propagate_parallelized(rhs);
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
    pub fn smart_mul_parallelized<T>(&self, lhs: &mut T, rhs: &mut T) -> T
    where
        T: IntegerRadixCiphertext,
    {
        rayon::join(
            || {
                if !lhs.block_carries_are_empty() {
                    self.full_propagate_parallelized(lhs);
                }
            },
            || {
                if !rhs.block_carries_are_empty() {
                    self.full_propagate_parallelized(rhs);
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
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    ///
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, num_blocks);
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
    pub fn mul_parallelized<T>(&self, ct1: &T, ct2: &T) -> T
    where
        T: IntegerRadixCiphertext,
    {
        let mut ct_res = ct1.clone();
        self.mul_assign_parallelized(&mut ct_res, ct2);
        ct_res
    }

    pub fn mul_assign_parallelized<T>(&self, ct1: &mut T, ct2: &T)
    where
        T: IntegerRadixCiphertext,
    {
        let mut tmp_rhs;

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

    pub fn unchecked_unsigned_overflowing_mul_parallelized(
        &self,
        lhs: &RadixCiphertext,
        rhs: &RadixCiphertext,
    ) -> (RadixCiphertext, BooleanBlock) {
        let mul_result_is_non_zero = self
            .key
            .generate_lookup_table_bivariate(|x, y| u64::from((x * y) != 0));

        let (all_shifted_lhs, high_part) = rayon::join(
            || self.compute_terms_for_mul_low(lhs, rhs),
            || {
                let (mut a, mut b) = rayon::join(
                    || {
                        let mut indices = vec![];
                        for i in 1..rhs.blocks.len() {
                            for j in lhs.blocks.len() - i..lhs.blocks.len() {
                                indices.push((i, j));
                            }
                        }

                        indices
                            .into_par_iter()
                            .map(|(i, j)| {
                                self.key.unchecked_apply_lookup_table_bivariate(
                                    &lhs.blocks[j],
                                    &rhs.blocks[i],
                                    &mul_result_is_non_zero,
                                )
                            })
                            .collect::<Vec<_>>()
                    },
                    || {
                        let lut = self.key.generate_lookup_table_bivariate(|x, y| {
                            u64::from((x * y) >= self.key.message_modulus.0)
                        });

                        rhs.blocks
                            .par_iter()
                            .enumerate()
                            .map(|(i, rhs_block)| {
                                self.key.unchecked_apply_lookup_table_bivariate(
                                    &lhs.blocks[lhs.blocks.len() - i - 1],
                                    rhs_block,
                                    &lut,
                                )
                            })
                            .collect::<Vec<_>>()
                    },
                );
                a.append(&mut b);
                a
            },
        );

        let (sum_result, high_part_is_non_zero) = rayon::join(
            || {
                self.unchecked_unsigned_overflowing_sum_ciphertexts_vec_parallelized(
                    all_shifted_lhs,
                )
            },
            || {
                let high_part = RadixCiphertext::from(high_part);
                self.unchecked_scalar_ne_parallelized(&high_part, 0)
            },
        );

        if let Some((result, sum_overflowed)) = sum_result {
            let final_overflow = self.boolean_bitor(&sum_overflowed, &high_part_is_non_zero);
            (result, final_overflow)
        } else {
            // We can end up here, if all blocks of either rhs, or lhs were trivial zeros
            let result = self.create_trivial_zero_radix(lhs.blocks.len());
            (result, high_part_is_non_zero)
        }
    }

    pub fn unchecked_unsigned_overflowing_mul_assign_parallelized(
        &self,
        lhs: &mut RadixCiphertext,
        rhs: &RadixCiphertext,
    ) -> BooleanBlock {
        let (result, overflowed) = self.unchecked_unsigned_overflowing_mul_parallelized(lhs, rhs);
        *lhs = result;
        overflowed
    }

    /// Computes homomorphically a multiplication along with an overflow flag
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
    /// let clear_1 = 128u8;
    /// let clear_2 = 5u8;
    ///
    /// // Encrypt two messages
    /// let ctxt_1 = cks.encrypt(clear_1);
    /// let ctxt_2 = cks.encrypt(clear_2);
    ///
    /// // Compute homomorphically a multiplication
    /// let (ct_res, ct_overflowed) = sks.unsigned_overflowing_mul_parallelized(&ctxt_1, &ctxt_2);
    /// // Decrypt
    /// let res: u8 = cks.decrypt(&ct_res);
    /// let overflowed = cks.decrypt_bool(&ct_overflowed);
    ///
    /// let (expected_result, expected_overflowed) = clear_1.overflowing_mul(clear_2);
    /// assert_eq!(res, expected_result);
    /// assert_eq!(overflowed, expected_overflowed);
    /// ```
    pub fn unsigned_overflowing_mul_parallelized(
        &self,
        ct1: &RadixCiphertext,
        ct2: &RadixCiphertext,
    ) -> (RadixCiphertext, BooleanBlock) {
        let mut ct_res = ct1.clone();
        let overflowed = self.unsigned_overflowing_mul_assign_parallelized(&mut ct_res, ct2);
        (ct_res, overflowed)
    }

    pub fn unsigned_overflowing_mul_assign_parallelized(
        &self,
        ct1: &mut RadixCiphertext,
        ct2: &RadixCiphertext,
    ) -> BooleanBlock {
        let mut tmp_rhs;

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

        self.unchecked_unsigned_overflowing_mul_assign_parallelized(lhs, rhs)
    }

    /// Computes homomorphically a multiplication along with an overflow flag
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
    /// let clear_1 = -128i8;
    /// let clear_2 = 5i8;
    ///
    /// // Encrypt two messages
    /// let ctxt_1 = cks.encrypt_signed(clear_1);
    /// let ctxt_2 = cks.encrypt_signed(clear_2);
    ///
    /// // Compute homomorphically a multiplication
    /// let (ct_res, ct_overflowed) = sks.signed_overflowing_mul_parallelized(&ctxt_1, &ctxt_2);
    /// // Decrypt
    /// let res: i8 = cks.decrypt_signed(&ct_res);
    /// let overflowed = cks.decrypt_bool(&ct_overflowed);
    ///
    /// let (expected_result, expected_overflowed) = clear_1.overflowing_mul(clear_2);
    /// assert_eq!(res, expected_result);
    /// assert_eq!(overflowed, expected_overflowed);
    /// ```
    pub fn signed_overflowing_mul_parallelized(
        &self,
        lhs: &SignedRadixCiphertext,
        rhs: &SignedRadixCiphertext,
    ) -> (SignedRadixCiphertext, BooleanBlock) {
        // Note: Naive implementation of signed mul with overflow
        // surely there are optimized way of computing this

        // Do a full multiplication (Nbits * Nbits) = 2Nbits result
        let bigger_lhs = self.extend_radix_with_sign_msb(lhs, lhs.blocks.len());
        let bigger_rhs = self.extend_radix_with_sign_msb(rhs, rhs.blocks.len());
        let mut full_result = self.mul_parallelized(&bigger_lhs, &bigger_rhs);

        let num_bits_of_message = self.message_modulus().0.ilog2();
        let total_num_bits = num_bits_of_message * lhs.blocks.len() as u32;

        let (is_lt_min, is_gt_max) = if total_num_bits > I256::BITS {
            let mut max_trivial: SignedRadixCiphertext =
                self.create_trivial_max_radix(lhs.blocks.len());
            let mut min_trivial: SignedRadixCiphertext =
                self.create_trivial_min_radix(lhs.blocks.len());

            // Manually do sign extension as we know the sign, max is positive
            // so pad with 0s, min is negative, so pad with 1s
            max_trivial
                .blocks
                .resize_with(bigger_lhs.blocks.len(), || self.key.create_trivial(0));
            min_trivial.blocks.resize_with(bigger_lhs.blocks.len(), || {
                self.key.create_trivial(self.message_modulus().0 - 1)
            });

            rayon::join(
                || self.unchecked_lt_parallelized(&full_result, &min_trivial),
                || self.unchecked_gt_parallelized(&full_result, &max_trivial),
            )
        } else {
            let max_scalar = I256::MAX >> (I256::BITS - total_num_bits);
            let min_scalar = I256::from(-1i32) << (total_num_bits - 1);

            rayon::join(
                || self.unchecked_scalar_lt_parallelized(&full_result, min_scalar),
                || self.unchecked_scalar_gt_parallelized(&full_result, max_scalar),
            )
        };

        assert_eq!(is_gt_max.0.degree.get(), 1);
        assert_eq!(is_gt_max.0.degree.get(), 1);

        let mut overflowed = self.boolean_bitor(&is_lt_min, &is_gt_max);
        // after_bitor does not give the correct degree
        overflowed.0.degree = Degree::new(1);

        full_result.blocks.truncate(lhs.blocks.len());
        (full_result, overflowed)
    }
}
