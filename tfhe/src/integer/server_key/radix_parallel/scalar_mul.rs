use crate::integer::block_decomposition::{BlockDecomposer, DecomposableInto};
use crate::integer::ciphertext::{IntegerRadixCiphertext, RadixCiphertext};
use crate::integer::server_key::radix::scalar_mul::ScalarMultiplier;
use crate::integer::server_key::CheckError;
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
    /// Otherwise a [CheckError] is returned.
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
        self.is_small_scalar_mul_possible(ct, scalar)?;
        Ok(self.unchecked_small_scalar_mul_parallelized(ct, scalar))
    }

    /// Computes homomorphically a multiplication between a scalar and a ciphertext.
    ///
    /// If the operation can be performed, the result is assigned to the ciphertext given
    /// as parameter.
    /// Otherwise a [CheckError] is returned.
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
        self.is_small_scalar_mul_possible(ct, scalar)?;
        self.unchecked_small_scalar_mul_assign_parallelized(ct, scalar);
        Ok(())
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
        if self.is_small_scalar_mul_possible(ctxt, scalar).is_err() {
            self.full_propagate_parallelized(ctxt);
        }
        self.is_small_scalar_mul_possible(ctxt, scalar).unwrap();
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
        if self.is_small_scalar_mul_possible(ctxt, scalar).is_err() {
            self.full_propagate_parallelized(ctxt);
        }
        self.is_small_scalar_mul_possible(ctxt, scalar).unwrap();
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

    pub fn unchecked_scalar_mul_parallelized<T, Scalar>(&self, ct: &T, scalar: Scalar) -> T
    where
        T: IntegerRadixCiphertext,
        Scalar: ScalarMultiplier + DecomposableInto<u8>,
    {
        let mut ct_res = ct.clone();
        self.unchecked_scalar_mul_assign_parallelized(&mut ct_res, scalar);
        ct_res
    }

    pub fn unchecked_scalar_mul_assign_parallelized<T, Scalar>(&self, lhs: &mut T, scalar: Scalar)
    where
        T: IntegerRadixCiphertext,
        Scalar: ScalarMultiplier + DecomposableInto<u8>,
    {
        if scalar == Scalar::ZERO || lhs.blocks().is_empty() {
            for block in lhs.blocks_mut() {
                self.key.create_trivial_assign(block, 0);
            }
            return;
        }

        if scalar == Scalar::ONE {
            return;
        }

        if scalar.is_power_of_two() {
            // Shifting cost one bivariate PBS so its always faster
            // than multiplying
            self.unchecked_scalar_left_shift_assign_parallelized(lhs, scalar.ilog2() as u64);
            return;
        }

        let num_blocks = lhs.blocks().len();
        let msg_bits = self.key.message_modulus.0.ilog2() as usize;

        let scalar_bits = BlockDecomposer::with_early_stop_at_zero(scalar, 1)
            .iter_as::<u8>()
            .collect::<Vec<_>>();

        // We don't want to compute shifts if we are not going to use the
        // resulting value
        let mut has_at_least_one_set = vec![false; msg_bits];
        for (i, bit) in scalar_bits.iter().copied().enumerate() {
            if bit == 1 {
                has_at_least_one_set[i % msg_bits] = true;
            }
        }

        // Contains all shifted values of lhs for shift in range (0..msg_bits)
        // The idea is that with these we can create all other shift that are in
        // range (0..total_bits) for free (block rotation)
        let preshifted_lhs = (0..msg_bits)
            .into_par_iter()
            .map(|shift_amount| {
                if has_at_least_one_set[shift_amount] {
                    self.unchecked_scalar_left_shift_parallelized(lhs, shift_amount)
                } else {
                    self.create_trivial_zero_radix(num_blocks)
                }
            })
            .collect::<Vec<_>>();

        let num_ciphertext_bits = msg_bits * num_blocks;
        let all_shifted_lhs = scalar_bits
            .iter()
            .enumerate()
            .take(num_ciphertext_bits) // shift beyond that are technically resulting in 0s
            .filter(|(_, &rhs_bit)| rhs_bit == 1)
            .map(|(i, _)| self.blockshift(&preshifted_lhs[i % msg_bits], i / msg_bits))
            .collect::<Vec<_>>();

        if let Some(result) = self.unchecked_sum_ciphertexts_vec_parallelized(all_shifted_lhs) {
            *lhs = result;
        } else {
            self.create_trivial_zero_assign_radix(lhs);
        }
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
    pub fn smart_scalar_mul_parallelized<T, Scalar>(&self, lhs: &mut T, scalar: Scalar) -> T
    where
        T: IntegerRadixCiphertext,
        Scalar: ScalarMultiplier + DecomposableInto<u8>,
    {
        if !lhs.block_carries_are_empty() {
            self.full_propagate_parallelized(lhs);
        }

        self.unchecked_scalar_mul_parallelized(lhs, scalar)
    }

    pub fn smart_scalar_mul_assign_parallelized<T, Scalar>(&self, lhs: &mut T, scalar: Scalar)
    where
        T: IntegerRadixCiphertext,
        Scalar: ScalarMultiplier + DecomposableInto<u8>,
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
    pub fn scalar_mul_parallelized<T, Scalar>(&self, ct: &T, scalar: Scalar) -> T
    where
        T: IntegerRadixCiphertext,
        Scalar: ScalarMultiplier + DecomposableInto<u8>,
    {
        let mut ct_res = ct.clone();
        self.scalar_mul_assign_parallelized(&mut ct_res, scalar);
        ct_res
    }

    pub fn scalar_mul_assign_parallelized<T, Scalar>(&self, lhs: &mut T, scalar: Scalar)
    where
        T: IntegerRadixCiphertext,
        Scalar: ScalarMultiplier + DecomposableInto<u8>,
    {
        if !lhs.block_carries_are_empty() {
            self.full_propagate_parallelized(lhs);
        }

        self.unchecked_scalar_mul_assign_parallelized(lhs, scalar);
    }
}
