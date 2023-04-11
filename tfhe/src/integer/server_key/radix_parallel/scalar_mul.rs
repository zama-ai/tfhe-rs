use crate::integer::ciphertext::RadixCiphertext;
use crate::integer::server_key::CheckError;
use crate::integer::server_key::CheckError::CarryFull;
use crate::integer::ServerKey;
use crate::shortint::PBSOrderMarker;
use rayon::prelude::*;
use std::collections::HashMap;
use std::sync::Mutex;

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
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix(&PARAM_MESSAGE_2_CARRY_2, size);
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
    pub fn unchecked_small_scalar_mul_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        ctxt: &RadixCiphertext<PBSOrder>,
        scalar: u64,
    ) -> RadixCiphertext<PBSOrder> {
        let mut ct_result = ctxt.clone();
        self.unchecked_small_scalar_mul_assign_parallelized(&mut ct_result, scalar);
        ct_result
    }

    pub fn unchecked_small_scalar_mul_assign_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        ctxt: &mut RadixCiphertext<PBSOrder>,
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
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix(&PARAM_MESSAGE_2_CARRY_2, size);
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
    pub fn checked_small_scalar_mul_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        ct: &RadixCiphertext<PBSOrder>,
        scalar: u64,
    ) -> Result<RadixCiphertext<PBSOrder>, CheckError> {
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
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix(&PARAM_MESSAGE_2_CARRY_2, size);
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
    pub fn checked_small_scalar_mul_assign_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        ct: &mut RadixCiphertext<PBSOrder>,
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
    /// For example, if the parameters are PARAM_MESSAGE_2_CARRY_2,
    /// the scalar should fit in 2 bits.
    ///
    /// The result is returned as a new ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let modulus = 1 << 8;
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix(&PARAM_MESSAGE_2_CARRY_2, size);
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
    pub fn smart_small_scalar_mul_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        ctxt: &mut RadixCiphertext<PBSOrder>,
        scalar: u64,
    ) -> RadixCiphertext<PBSOrder> {
        if !self.is_small_scalar_mul_possible(ctxt, scalar) {
            self.full_propagate_parallelized(ctxt);
        }
        self.unchecked_small_scalar_mul_parallelized(ctxt, scalar)
    }

    /// Computes homomorphically a multiplication between a scalar and a ciphertext.
    ///
    /// `small` means the scalar shall value fit in a __shortint block__.
    /// For example, if the parameters are PARAM_MESSAGE_2_CARRY_2,
    /// the scalar should fit in 2 bits.
    ///
    /// The result is assigned to the input ciphertext
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let modulus = 1 << 8;
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix(&PARAM_MESSAGE_2_CARRY_2, size);
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
    pub fn smart_small_scalar_mul_assign_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        ctxt: &mut RadixCiphertext<PBSOrder>,
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
    /// For example, if the parameters are PARAM_MESSAGE_2_CARRY_2,
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
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let modulus = 1 << 8;
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix(&PARAM_MESSAGE_2_CARRY_2, size);
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
    pub fn small_scalar_mul_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        ctxt: &RadixCiphertext<PBSOrder>,
        scalar: u64,
    ) -> RadixCiphertext<PBSOrder> {
        let mut ct_res = ctxt.clone();
        self.small_scalar_mul_assign_parallelized(&mut ct_res, scalar);
        ct_res
    }

    /// Computes homomorphically a multiplication between a scalar and a ciphertext.
    ///
    /// `small` means the scalar shall value fit in a __shortint block__.
    /// For example, if the parameters are PARAM_MESSAGE_2_CARRY_2,
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
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let modulus = 1 << 8;
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix(&PARAM_MESSAGE_2_CARRY_2, size);
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
    pub fn small_scalar_mul_assign_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        ctxt: &mut RadixCiphertext<PBSOrder>,
        scalar: u64,
    ) {
        if !ctxt.block_carries_are_empty() {
            self.full_propagate_parallelized(ctxt);
        }
        self.unchecked_small_scalar_mul_assign_parallelized(ctxt, scalar);
        self.full_propagate_parallelized(ctxt);
    }

    /// Computes homomorphically a multiplication between a scalar and a ciphertext.
    ///
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let modulus = 1 << 8;
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix(&PARAM_MESSAGE_2_CARRY_2, size);
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
    pub fn smart_scalar_mul_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        ct: &mut RadixCiphertext<PBSOrder>,
        scalar: u64,
    ) -> RadixCiphertext<PBSOrder> {
        let zero = self.create_trivial_zero_radix(ct.blocks.len());
        if scalar == 0 || ct.blocks.is_empty() {
            return zero;
        }

        let b = self.key.message_modulus.0 as u64;
        let n = ct.blocks.len();

        //Propagate the carries before doing the multiplications
        self.full_propagate_parallelized(ct);
        let ct = &*ct;

        // key is the small scalar we multiply by
        // value is the vector of blockshifts
        let mut task_map = HashMap::<u64, Vec<usize>>::new();

        let mut b_i = 1_u64;
        for i in 0..n {
            let u_i = (scalar / b_i) % b;
            task_map.entry(u_i).or_insert_with(Vec::new).push(i);
            b_i *= b;
        }

        let terms = Mutex::new(Vec::<RadixCiphertext<PBSOrder>>::new());
        task_map.par_iter().for_each(|(&u_i, blockshifts)| {
            if u_i == 0 {
                return;
            }

            let blockshifts = &**blockshifts;
            let min_blockshift = *blockshifts.iter().min().unwrap();

            let mut tmp = ct.clone();
            if u_i != 1 {
                tmp.blocks[0..n - min_blockshift]
                    .par_iter_mut()
                    .for_each(|ct_i| self.key.unchecked_scalar_mul_assign(ct_i, u_i as u8));
            }

            let tmp = &tmp;
            blockshifts.par_iter().for_each(|&shift| {
                let term = self.blockshift(tmp, shift);
                terms.lock().unwrap().push(term);
            });
        });
        let mut terms = terms.into_inner().unwrap();
        self.smart_binary_op_seq_parallelized(&mut terms, ServerKey::smart_add_parallelized)
            .unwrap_or(zero)
    }

    pub fn smart_scalar_mul_assign_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        ctxt: &mut RadixCiphertext<PBSOrder>,
        scalar: u64,
    ) {
        *ctxt = self.smart_scalar_mul_parallelized(ctxt, scalar);
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
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let modulus = 1 << 8;
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix(&PARAM_MESSAGE_2_CARRY_2, size);
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
    pub fn scalar_mul_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        ct: &RadixCiphertext<PBSOrder>,
        scalar: u64,
    ) -> RadixCiphertext<PBSOrder> {
        let mut ct_res = ct.clone();
        self.scalar_mul_assign_parallelized(&mut ct_res, scalar);
        ct_res
    }

    pub fn scalar_mul_assign_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        ct: &mut RadixCiphertext<PBSOrder>,
        scalar: u64,
    ) {
        let zero = self.create_trivial_zero_radix(ct.blocks.len());
        if scalar == 0 || ct.blocks.is_empty() {
            *ct = zero;
            return;
        }

        let b = self.key.message_modulus.0 as u64;
        let n = ct.blocks.len();

        //Propagate the carries before doing the multiplications
        self.full_propagate_parallelized(ct);

        // key is the small scalar we multiply by
        // value is the vector of blockshifts
        let mut task_map = HashMap::<u64, Vec<usize>>::new();

        let mut b_i = 1_u64;
        for i in 0..n {
            let u_i = (scalar / b_i) % b;
            task_map.entry(u_i).or_insert_with(Vec::new).push(i);
            b_i *= b;
        }

        let terms = Mutex::new(Vec::<RadixCiphertext<PBSOrder>>::new());
        task_map.par_iter().for_each(|(&u_i, blockshifts)| {
            if u_i == 0 {
                return;
            }

            let blockshifts = &**blockshifts;
            let min_blockshift = *blockshifts.iter().min().unwrap();

            let mut tmp = ct.clone();
            if u_i != 1 {
                tmp.blocks[0..n - min_blockshift]
                    .par_iter_mut()
                    .for_each(|ct_i| self.key.unchecked_scalar_mul_assign(ct_i, u_i as u8));
            }

            let tmp = &tmp;
            blockshifts.par_iter().for_each(|&shift| {
                let term = self.blockshift(tmp, shift);
                terms.lock().unwrap().push(term);
            });
        });
        let terms = terms.into_inner().unwrap();
        *ct = self
            .default_binary_op_seq_parallelized(&terms, ServerKey::add_parallelized)
            .unwrap_or(zero);
    }
}
