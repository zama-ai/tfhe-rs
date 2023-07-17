use crate::integer::block_decomposition::{BlockDecomposer, DecomposableInto};
use crate::integer::ciphertext::RadixCiphertext;
use crate::integer::server_key::radix::scalar_mul::ScalarMultiplier;
use crate::integer::server_key::CheckError;
use crate::integer::server_key::CheckError::CarryFull;
use crate::integer::ServerKey;
use rayon::prelude::*;

impl ServerKey {
    /// Computes homomorphically a multiplication between a scalar and a ciphertext.
    ///
    /// This function computes the operation without checking if it exceeds the capacity of the
    /// ciphertext.
    ///
    /// The result is returned as a new ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size);
    ///
    /// let msg = 30;
    /// let scalar = 3;
    ///
    /// let ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a scalar multiplication:
    /// let ct_res = sks.unchecked_small_scalar_mul_parallelized(&ct, scalar);
    ///
    /// let clear: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(scalar * msg, clear);
    /// ```
    pub fn unchecked_small_scalar_mul_parallelized(
        &self,
        ctxt: &RadixCiphertext,
        scalar: u64,
    ) -> RadixCiphertext {
        let mut ct_result = ctxt.clone();
        self.unchecked_small_scalar_mul_assign_parallelized(&mut ct_result, scalar);
        ct_result
    }

    pub fn unchecked_small_scalar_mul_assign_parallelized(
        &self,
        ctxt: &mut RadixCiphertext,
        scalar: u64,
    ) {
        ctxt.blocks.par_iter_mut().for_each(|ct_i| {
            self.key.unchecked_scalar_mul_assign(ct_i, scalar as u8);
        });
    }

    /// Computes homomorphically a multiplication between a scalar and a ciphertext.
    ///
    /// If the operation can be performed, the result is returned in a new ciphertext.
    /// Otherwise [CheckError::CarryFull] is returned.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size);
    ///
    /// let msg = 33;
    /// let scalar = 3;
    ///
    /// let ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a scalar multiplication:
    /// let ct_res = sks.checked_small_scalar_mul_parallelized(&ct, scalar);
    ///
    /// match ct_res {
    ///     Err(x) => panic!("{:?}", x),
    ///     Ok(y) => {
    ///         let clear: u64 = cks.decrypt(&y);
    ///         assert_eq!(msg * scalar, clear);
    ///     }
    /// }
    /// ```
    pub fn checked_small_scalar_mul_parallelized(
        &self,
        ct: &RadixCiphertext,
        scalar: u64,
    ) -> Result<RadixCiphertext, CheckError> {
        // If the ciphertext cannot be multiplied without exceeding the capacity of a ciphertext
        if self.is_small_scalar_mul_possible(ct, scalar) {
            Ok(self.unchecked_small_scalar_mul_parallelized(ct, scalar))
        } else {
            Err(CarryFull)
        }
    }

    /// Computes homomorphically a multiplication between a scalar and a ciphertext.
    ///
    /// If the operation can be performed, the result is assigned to the ciphertext given
    /// as parameter.
    /// Otherwise [CheckError::CarryFull] is returned.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size);
    ///
    /// let msg = 33;
    /// let scalar = 3;
    ///
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a scalar multiplication:
    /// sks.checked_small_scalar_mul_assign_parallelized(&mut ct, scalar);
    ///
    /// let clear_res: u64 = cks.decrypt(&ct);
    /// assert_eq!(clear_res, msg * scalar);
    /// ```
    pub fn checked_small_scalar_mul_assign_parallelized(
        &self,
        ct: &mut RadixCiphertext,
        scalar: u64,
    ) -> Result<(), CheckError> {
        // If the ciphertext cannot be multiplied without exceeding the capacity of a ciphertext
        if self.is_small_scalar_mul_possible(ct, scalar) {
            self.unchecked_small_scalar_mul_assign_parallelized(ct, scalar);
            Ok(())
        } else {
            Err(CarryFull)
        }
    }

    /// Computes homomorphically a multiplication between a scalar and a ciphertext.
    ///
    /// `small` means the scalar value shall fit in a __shortint block__.
    /// For example, if the parameters are PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    /// the scalar should fit in 2 bits.
    ///
    /// The result is returned as a new ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let modulus = 1 << 8;
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size);
    ///
    /// let msg = 13;
    /// let scalar = 3;
    ///
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a scalar multiplication:
    /// let ct_res = sks.smart_small_scalar_mul_parallelized(&mut ct, scalar);
    ///
    /// // Decrypt:
    /// let clear: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg * scalar % modulus, clear);
    /// ```
    pub fn smart_small_scalar_mul_parallelized(
        &self,
        ctxt: &mut RadixCiphertext,
        scalar: u64,
    ) -> RadixCiphertext {
        if !self.is_small_scalar_mul_possible(ctxt, scalar) {
            self.full_propagate_parallelized(ctxt);
        }
        self.unchecked_small_scalar_mul_parallelized(ctxt, scalar)
    }

    /// Computes homomorphically a multiplication between a scalar and a ciphertext.
    ///
    /// `small` means the scalar shall value fit in a __shortint block__.
    /// For example, if the parameters are PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    /// the scalar should fit in 2 bits.
    ///
    /// The result is assigned to the input ciphertext
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let modulus = 1 << 8;
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size);
    ///
    /// let msg = 9;
    /// let scalar = 3;
    ///
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a scalar multiplication:
    /// sks.smart_small_scalar_mul_assign_parallelized(&mut ct, scalar);
    ///
    /// // Decrypt:
    /// let clear: u64 = cks.decrypt(&ct);
    /// assert_eq!(msg * scalar % modulus, clear);
    /// ```
    pub fn smart_small_scalar_mul_assign_parallelized(
        &self,
        ctxt: &mut RadixCiphertext,
        scalar: u64,
    ) {
        if !self.is_small_scalar_mul_possible(ctxt, scalar) {
            self.full_propagate_parallelized(ctxt);
        }
        self.unchecked_small_scalar_mul_assign_parallelized(ctxt, scalar);
    }

    /// Computes homomorphically a multiplication between a scalar and a ciphertext.
    ///
    /// `small` means the scalar value shall fit in a __shortint block__.
    /// For example, if the parameters are PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    /// the scalar should fit in 2 bits.
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
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let modulus = 1 << 8;
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size);
    ///
    /// let msg = 13;
    /// let scalar = 3;
    ///
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a scalar multiplication:
    /// let ct_res = sks.small_scalar_mul_parallelized(&mut ct, scalar);
    ///
    /// // Decrypt:
    /// let clear: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg * scalar % modulus, clear);
    /// ```
    pub fn small_scalar_mul_parallelized(
        &self,
        ctxt: &RadixCiphertext,
        scalar: u64,
    ) -> RadixCiphertext {
        let mut ct_res = ctxt.clone();
        self.small_scalar_mul_assign_parallelized(&mut ct_res, scalar);
        ct_res
    }

    /// Computes homomorphically a multiplication between a scalar and a ciphertext.
    ///
    /// `small` means the scalar shall value fit in a __shortint block__.
    /// For example, if the parameters are PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    /// the scalar should fit in 2 bits.
    ///
    /// The result is assigned to the input ciphertext
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
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let modulus = 1 << 8;
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size);
    ///
    /// let msg = 9;
    /// let scalar = 3;
    ///
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a scalar multiplication:
    /// sks.small_scalar_mul_assign_parallelized(&mut ct, scalar);
    ///
    /// // Decrypt:
    /// let clear: u64 = cks.decrypt(&ct);
    /// assert_eq!(msg * scalar % modulus, clear);
    /// ```
    pub fn small_scalar_mul_assign_parallelized(&self, ctxt: &mut RadixCiphertext, scalar: u64) {
        if !ctxt.block_carries_are_empty() {
            self.full_propagate_parallelized(ctxt);
        }
        self.unchecked_small_scalar_mul_assign_parallelized(ctxt, scalar);
        self.full_propagate_parallelized(ctxt);
    }
    pub fn unchecked_scalar_mul_parallelized<T>(
        &self,
        ct: &RadixCiphertext,
        scalar: T,
    ) -> RadixCiphertext
    where
        T: ScalarMultiplier + DecomposableInto<u8>,
    {
        let mut ct_res = ct.clone();
        self.unchecked_scalar_mul_assign_parallelized(&mut ct_res, scalar);
        ct_res
    }

    pub fn unchecked_scalar_mul_assign_parallelized<T>(&self, lhs: &mut RadixCiphertext, scalar: T)
    where
        T: ScalarMultiplier + DecomposableInto<u8>,
    {
        if scalar == T::ZERO || lhs.blocks.is_empty() {
            for block in &mut lhs.blocks {
                self.key.create_trivial_assign(block, 0);
            }
            return;
        }

        if scalar == T::ONE {
            return;
        }

        if scalar.is_power_of_two() {
            // Shifting cost one bivariate PBS so its always faster
            // than multiplying
            self.unchecked_scalar_left_shift_assign_parallelized(lhs, scalar.ilog2() as u64);
            return;
        }

        let message_modulus = self.key.message_modulus.0 as u64;
        let num_blocks = lhs.blocks.len();

        // key is the small scalar we multiply by
        // value is the vector of blockshifts
        let mut task_map = vec![vec![]; message_modulus as usize];

        let decomposer = BlockDecomposer::with_early_stop_at_zero(scalar, message_modulus.ilog2())
            .iter_as::<u8>()
            .take(num_blocks);
        for (i, scalar_block) in decomposer.enumerate() {
            if scalar_block != 0 {
                task_map[scalar_block as usize].push(i);
            }
        }

        // This can happen if scalar % (nb_blocks * message_modulus) == 0
        if task_map.iter().all(Vec::is_empty) {
            for block in &mut lhs.blocks {
                self.key.create_trivial_assign(block, 0);
            }
            return;
        }

        let terms = task_map[1..] // Ignore multiplications by zero
            .into_par_iter()
            .enumerate()
            .filter(|(_, block_indices)| !block_indices.is_empty())
            .map(|(i, block_indices)| -> Vec<RadixCiphertext> {
                let scalar = i + 1;

                let min_index = block_indices.iter().min().unwrap();

                let mut tmp = lhs.clone();
                if scalar != 1 {
                    tmp.blocks[0..num_blocks - min_index]
                        .par_iter_mut()
                        .for_each(|ct_i| {
                            if ct_i.degree.0 != 0 {
                                self.key.unchecked_scalar_mul_assign(ct_i, scalar as u8)
                            }
                        });
                    let (mut message_blocks, carry_blocks) = rayon::join(
                        || {
                            tmp.blocks[0..num_blocks - min_index]
                                .par_iter()
                                .map(|block| self.key.message_extract(block))
                                .collect::<Vec<_>>()
                        },
                        || {
                            let mut carry_blocks = Vec::new();
                            tmp.blocks[..num_blocks - min_index - 1]
                                .par_iter()
                                .map(|block| self.key.carry_extract(block))
                                .collect_into_vec(&mut carry_blocks);

                            carry_blocks.insert(0, self.key.create_trivial(0));
                            carry_blocks
                        },
                    );
                    for i in 0..num_blocks - min_index {
                        std::mem::swap(&mut tmp.blocks[i], &mut message_blocks[i]);
                        self.key
                            .unchecked_add_assign(&mut tmp.blocks[i], &carry_blocks[i]);
                    }
                }

                block_indices
                    .par_iter()
                    .copied()
                    .map(|i| self.blockshift(&tmp, i))
                    .collect::<Vec<_>>()
            })
            .flatten()
            .collect::<Vec<_>>();

        self.sum_multiplication_terms_into(lhs, terms);
    }

    /// Computes homomorphically a multiplication between a scalar and a ciphertext.
    ///
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let modulus = 1 << 8;
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size);
    ///
    /// let msg = 230;
    /// let scalar = 376;
    ///
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a scalar multiplication:
    /// let ct_res = sks.smart_scalar_mul_parallelized(&mut ct, scalar);
    ///
    /// // Decrypt:
    /// let clear: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg * scalar % modulus, clear);
    /// ```
    pub fn smart_scalar_mul_parallelized<T>(
        &self,
        lhs: &mut RadixCiphertext,
        scalar: T,
    ) -> RadixCiphertext
    where
        T: ScalarMultiplier + DecomposableInto<u8>,
    {
        if !lhs.block_carries_are_empty() {
            self.full_propagate_parallelized(lhs);
        }

        self.unchecked_scalar_mul_parallelized(lhs, scalar)
    }

    pub fn smart_scalar_mul_assign_parallelized<T>(&self, lhs: &mut RadixCiphertext, scalar: T)
    where
        T: ScalarMultiplier + DecomposableInto<u8>,
    {
        if !lhs.block_carries_are_empty() {
            self.full_propagate_parallelized(lhs);
        }

        self.unchecked_scalar_mul_assign_parallelized(lhs, scalar);
    }

    /// Computes homomorphically a multiplication between a scalar and a ciphertext.
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
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let modulus = 1 << 8;
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size);
    ///
    /// let msg = 230;
    /// let scalar = 376;
    ///
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a scalar multiplication:
    /// let ct_res = sks.scalar_mul_parallelized(&mut ct, scalar);
    ///
    /// // Decrypt:
    /// let clear: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg * scalar % modulus, clear);
    /// ```
    pub fn scalar_mul_parallelized<T>(&self, ct: &RadixCiphertext, scalar: T) -> RadixCiphertext
    where
        T: ScalarMultiplier + DecomposableInto<u8>,
    {
        let mut ct_res = ct.clone();
        self.scalar_mul_assign_parallelized(&mut ct_res, scalar);
        ct_res
    }

    pub fn scalar_mul_assign_parallelized<T>(&self, lhs: &mut RadixCiphertext, scalar: T)
    where
        T: ScalarMultiplier + DecomposableInto<u8>,
    {
        if !lhs.block_carries_are_empty() {
            self.full_propagate_parallelized(lhs);
        }

        self.unchecked_scalar_mul_assign_parallelized(lhs, scalar);
    }
}
