use crate::core_crypto::prelude::{Numeric, UnsignedInteger};
use crate::integer::block_decomposition::{BlockDecomposer, DecomposableInto};
use crate::integer::ciphertext::RadixCiphertext;
use crate::integer::server_key::CheckError;
use crate::integer::server_key::CheckError::CarryFull;
use crate::integer::{ServerKey, U256, U512};
use std::collections::BTreeMap;

pub trait ScalarMultiplier: Numeric {
    fn is_power_of_two(self) -> bool;

    fn ilog2(self) -> u32;
}

impl<T> ScalarMultiplier for T
where
    T: UnsignedInteger,
{
    fn is_power_of_two(self) -> bool {
        self.is_power_of_two()
    }

    fn ilog2(self) -> u32 {
        self.ilog2()
    }
}

impl ScalarMultiplier for U256 {
    fn is_power_of_two(self) -> bool {
        self.is_power_of_two()
    }

    fn ilog2(self) -> u32 {
        self.ilog2()
    }
}

impl ScalarMultiplier for U512 {
    fn is_power_of_two(self) -> bool {
        self.is_power_of_two()
    }

    fn ilog2(self) -> u32 {
        self.ilog2()
    }
}

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
    /// let ct_res = sks.unchecked_small_scalar_mul(&ct, scalar);
    ///
    /// let clear: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(scalar * msg, clear);
    /// ```
    pub fn unchecked_small_scalar_mul(
        &self,
        ctxt: &RadixCiphertext,
        scalar: u64,
    ) -> RadixCiphertext {
        let mut ct_result = ctxt.clone();
        self.unchecked_small_scalar_mul_assign(&mut ct_result, scalar);

        ct_result
    }

    pub fn unchecked_small_scalar_mul_assign(&self, ctxt: &mut RadixCiphertext, scalar: u64) {
        for ct_i in ctxt.blocks.iter_mut() {
            self.key.unchecked_scalar_mul_assign(ct_i, scalar as u8);
        }
    }

    ///Verifies if ct1 can be multiplied by scalar.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size);
    ///
    /// let msg = 25u64;
    /// let scalar1 = 3;
    ///
    /// let ct = cks.encrypt(msg);
    ///
    /// // Verification if the scalar multiplication can be computed:
    /// let res = sks.is_small_scalar_mul_possible(&ct, scalar1);
    ///
    /// assert_eq!(true, res);
    ///
    /// let scalar2 = 7;
    /// // Verification if the scalar multiplication can be computed:
    /// let res = sks.is_small_scalar_mul_possible(&ct, scalar2);
    /// assert_eq!(false, res);
    /// ```
    pub fn is_small_scalar_mul_possible(&self, ctxt: &RadixCiphertext, scalar: u64) -> bool {
        for ct_i in ctxt.blocks.iter() {
            if !self.key.is_scalar_mul_possible(ct_i, scalar as u8) {
                return false;
            }
        }
        true
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
    /// let ct_res = sks.checked_small_scalar_mul(&ct, scalar);
    ///
    /// match ct_res {
    ///     Err(x) => panic!("{:?}", x),
    ///     Ok(y) => {
    ///         let clear: u64 = cks.decrypt(&y);
    ///         assert_eq!(msg * scalar, clear);
    ///     }
    /// }
    /// ```
    pub fn checked_small_scalar_mul(
        &self,
        ct: &RadixCiphertext,
        scalar: u64,
    ) -> Result<RadixCiphertext, CheckError> {
        let mut ct_result = ct.clone();

        // If the ciphertext cannot be multiplied without exceeding the capacity of a ciphertext
        if self.is_small_scalar_mul_possible(ct, scalar) {
            ct_result = self.unchecked_small_scalar_mul(&ct_result, scalar);

            Ok(ct_result)
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
    /// sks.checked_small_scalar_mul_assign(&mut ct, scalar);
    ///
    /// let clear_res: u64 = cks.decrypt(&ct);
    /// assert_eq!(clear_res, msg * scalar);
    /// ```
    pub fn checked_small_scalar_mul_assign(
        &self,
        ct: &mut RadixCiphertext,
        scalar: u64,
    ) -> Result<(), CheckError> {
        // If the ciphertext cannot be multiplied without exceeding the capacity of a ciphertext
        if self.is_small_scalar_mul_possible(ct, scalar) {
            self.unchecked_small_scalar_mul_assign(ct, scalar);
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
    /// let scalar = 5;
    ///
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a scalar multiplication:
    /// let ct_res = sks.smart_small_scalar_mul(&mut ct, scalar);
    ///
    /// // Decrypt:
    /// let clear: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg * scalar % modulus, clear);
    /// ```
    pub fn smart_small_scalar_mul(
        &self,
        ctxt: &mut RadixCiphertext,
        scalar: u64,
    ) -> RadixCiphertext {
        if !self.is_small_scalar_mul_possible(ctxt, scalar) {
            self.full_propagate(ctxt);
        }
        self.unchecked_small_scalar_mul(ctxt, scalar)
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
    /// sks.smart_small_scalar_mul_assign(&mut ct, scalar);
    ///
    /// // Decrypt:
    /// let clear: u64 = cks.decrypt(&ct);
    /// assert_eq!(msg * scalar % modulus, clear);
    /// ```
    pub fn smart_small_scalar_mul_assign(&self, ctxt: &mut RadixCiphertext, scalar: u64) {
        if !self.is_small_scalar_mul_possible(ctxt, scalar) {
            self.full_propagate(ctxt);
        }
        self.unchecked_small_scalar_mul_assign(ctxt, scalar);
    }

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
    /// let msg = 1u64;
    /// let power = 2;
    ///
    /// let ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a scalar multiplication:
    /// let ct_res = sks.blockshift(&ct, power);
    ///
    /// // Decrypt:
    /// let clear: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(16, clear);
    /// ```
    pub fn blockshift(&self, ctxt: &RadixCiphertext, shift: usize) -> RadixCiphertext {
        let mut result = ctxt.clone();
        result.blocks.rotate_right(shift);
        for block in &mut result.blocks[..shift] {
            self.key.create_trivial_assign(block, 0);
        }
        result
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
    /// let ct_res = sks.smart_scalar_mul(&mut ct, scalar);
    ///
    /// // Decrypt:
    /// let clear: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg * scalar % modulus, clear);
    /// ```
    pub fn smart_scalar_mul<T>(&self, ctxt: &mut RadixCiphertext, scalar: T) -> RadixCiphertext
    where
        T: ScalarMultiplier + DecomposableInto<u8>,
    {
        if scalar == T::ZERO {
            return self.create_trivial_zero_radix(ctxt.blocks.len());
        }

        if scalar == T::ONE {
            return ctxt.clone();
        }

        //Propagate the carries before doing the multiplications
        self.full_propagate(ctxt);

        //Store the computations
        let mut map: BTreeMap<u64, RadixCiphertext> = BTreeMap::new();

        let mut result = self.create_trivial_zero_radix(ctxt.blocks.len());

        let mut tmp;

        let decomposer =
            BlockDecomposer::with_early_stop_at_zero(scalar, self.key.message_modulus.0.ilog2())
                .iter_as::<u8>()
                .take(ctxt.blocks.len());
        for (i, scalar_block) in decomposer.enumerate() {
            if scalar_block == 0 {
                continue;
            }

            if scalar_block == 1 {
                // tmp = ctxt * 1 * b^i
                tmp = self.blockshift(ctxt, i);
            } else {
                tmp = map
                    .entry(scalar_block as u64)
                    .or_insert_with(|| self.smart_small_scalar_mul(ctxt, scalar_block as u64))
                    .clone();

                //tmp = ctxt* u_i * b^i
                tmp = self.blockshift(&tmp, i);
            }

            //update the result
            self.smart_add_assign(&mut result, &mut tmp);
        }

        result
    }

    pub fn smart_scalar_mul_assign<T>(&self, ctxt: &mut RadixCiphertext, scalar: T)
    where
        T: ScalarMultiplier + DecomposableInto<u8>,
    {
        *ctxt = self.smart_scalar_mul(ctxt, scalar);
    }
}
