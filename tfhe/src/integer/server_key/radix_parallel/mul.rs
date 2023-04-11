use std::sync::Mutex;

use crate::integer::ciphertext::RadixCiphertext;
use crate::integer::ServerKey;
use crate::shortint::PBSOrderMarker;
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
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(&PARAM_MESSAGE_2_CARRY_2, num_blocks);
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
    pub fn unchecked_block_mul_assign_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        ct_left: &mut RadixCiphertext<PBSOrder>,
        ct_right: &crate::shortint::CiphertextBase<PBSOrder>,
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
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(&PARAM_MESSAGE_2_CARRY_2, num_blocks);
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
    pub fn unchecked_block_mul_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        ct1: &RadixCiphertext<PBSOrder>,
        ct2: &crate::shortint::CiphertextBase<PBSOrder>,
        index: usize,
    ) -> RadixCiphertext<PBSOrder> {
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
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(&PARAM_MESSAGE_2_CARRY_2, num_blocks);
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
    pub fn smart_block_mul_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        ct1: &mut RadixCiphertext<PBSOrder>,
        ct2: &crate::shortint::CiphertextBase<PBSOrder>,
        index: usize,
    ) -> RadixCiphertext<PBSOrder> {
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
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(&PARAM_MESSAGE_2_CARRY_2, num_blocks);
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
    pub fn block_mul_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        ct1: &RadixCiphertext<PBSOrder>,
        ct2: &crate::shortint::CiphertextBase<PBSOrder>,
        index: usize,
    ) -> RadixCiphertext<PBSOrder> {
        let mut ct_res = ct1.clone();
        self.block_mul_assign_parallelized(&mut ct_res, ct2, index);
        ct_res
    }

    pub fn block_mul_assign_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        ct1: &mut RadixCiphertext<PBSOrder>,
        ct2: &crate::shortint::CiphertextBase<PBSOrder>,
        index: usize,
    ) {
        let mut tmp_rhs: crate::shortint::CiphertextBase<PBSOrder>;

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

    fn unchecked_block_mul_lsb_msb_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        result_lsb: &mut RadixCiphertext<PBSOrder>,
        result_msb: &mut RadixCiphertext<PBSOrder>,
        ct2: &crate::shortint::CiphertextBase<PBSOrder>,
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

    pub fn smart_block_mul_assign_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        ct1: &mut RadixCiphertext<PBSOrder>,
        ct2: &crate::shortint::CiphertextBase<PBSOrder>,
        index: usize,
    ) {
        *ct1 = self.smart_block_mul_parallelized(ct1, ct2, index);
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
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(&PARAM_MESSAGE_2_CARRY_2, num_blocks);
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
    pub fn unchecked_mul_assign_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        ct1: &mut RadixCiphertext<PBSOrder>,
        ct2: &RadixCiphertext<PBSOrder>,
    ) {
        *ct1 = self.unchecked_mul_parallelized(ct1, ct2);
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
    pub fn unchecked_mul_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        ct1: &mut RadixCiphertext<PBSOrder>,
        ct2: &RadixCiphertext<PBSOrder>,
    ) -> RadixCiphertext<PBSOrder> {
        let mut result = self.create_trivial_zero_radix(ct1.blocks.len());

        let terms = Mutex::new(Vec::new());

        ct2.blocks.par_iter().enumerate().for_each(|(i, ct2_i)| {
            let term = self.unchecked_block_mul_parallelized(ct1, ct2_i, i);
            terms.lock().unwrap().push(term);
        });

        let terms = terms.into_inner().unwrap();

        for term in terms {
            self.unchecked_add_assign(&mut result, &term);
        }

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
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(&PARAM_MESSAGE_2_CARRY_2, num_blocks);
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
    pub fn smart_mul_assign_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        ct1: &mut RadixCiphertext<PBSOrder>,
        ct2: &mut RadixCiphertext<PBSOrder>,
    ) {
        *ct1 = self.smart_mul_parallelized(ct1, ct2);
    }

    /// Computes homomorphically a multiplication between two ciphertexts encrypting integer values.
    ///
    /// The result is returned as a new ciphertext.
    ///
    /// # Warning
    ///
    /// - Multithreaded
    pub fn smart_mul_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        ct1: &mut RadixCiphertext<PBSOrder>,
        ct2: &mut RadixCiphertext<PBSOrder>,
    ) -> RadixCiphertext<PBSOrder> {
        rayon::join(
            || self.full_propagate_parallelized(ct1),
            || self.full_propagate_parallelized(ct2),
        );

        let terms = Mutex::new(Vec::new());
        ct2.blocks.par_iter().enumerate().for_each(|(i, ct2_i)| {
            let term = self.unchecked_block_mul_parallelized(ct1, ct2_i, i);
            terms.lock().unwrap().push(term);
        });
        let mut terms = terms.into_inner().unwrap();

        self.smart_binary_op_seq_parallelized(&mut terms, ServerKey::smart_add_parallelized)
            .unwrap_or_else(|| self.create_trivial_zero_radix(ct1.blocks.len()))
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
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(&PARAM_MESSAGE_2_CARRY_2, num_blocks);
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
    pub fn mul_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        ct1: &RadixCiphertext<PBSOrder>,
        ct2: &RadixCiphertext<PBSOrder>,
    ) -> RadixCiphertext<PBSOrder> {
        let mut ct_res = ct1.clone();
        self.mul_assign_parallelized(&mut ct_res, ct2);
        ct_res
    }

    pub fn mul_assign_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        ct1: &mut RadixCiphertext<PBSOrder>,
        ct2: &RadixCiphertext<PBSOrder>,
    ) {
        let mut tmp_rhs: RadixCiphertext<PBSOrder>;

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
        self.full_propagate_parallelized(lhs);
    }
}
