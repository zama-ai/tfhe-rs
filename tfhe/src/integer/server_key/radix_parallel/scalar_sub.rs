use crate::integer::block_decomposition::DecomposableInto;
use crate::integer::ciphertext::RadixCiphertext;
use crate::integer::server_key::radix::scalar_sub::TwosComplementNegation;
use crate::integer::ServerKey;

impl ServerKey {
    /// Computes homomorphically a subtraction of a ciphertext by a scalar.
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
    /// let msg = 165;
    /// let scalar = 112;
    ///
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically an addition:
    /// let ct_res = sks.smart_scalar_sub_parallelized(&mut ct, scalar);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg - scalar, dec);
    /// ```
    pub fn smart_scalar_sub_parallelized<T>(
        &self,
        ct: &mut RadixCiphertext,
        scalar: T,
    ) -> RadixCiphertext
    where
        T: TwosComplementNegation + DecomposableInto<u8>,
    {
        if !self.is_scalar_sub_possible(ct, scalar) {
            self.full_propagate_parallelized(ct);
        }
        self.unchecked_scalar_sub(ct, scalar)
    }

    pub fn smart_scalar_sub_assign_parallelized<T>(&self, ct: &mut RadixCiphertext, scalar: T)
    where
        T: TwosComplementNegation + DecomposableInto<u8>,
    {
        if !self.is_scalar_sub_possible(ct, scalar) {
            self.full_propagate_parallelized(ct);
        }
        self.unchecked_scalar_sub_assign(ct, scalar);
    }

    /// Computes homomorphically a subtraction of a ciphertext by a scalar.
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
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size);
    ///
    /// let msg = 165;
    /// let scalar = 112;
    ///
    /// let ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically an addition:
    /// let ct_res = sks.scalar_sub_parallelized(&ct, scalar);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg - scalar, dec);
    /// ```
    pub fn scalar_sub_parallelized<T>(&self, ct: &RadixCiphertext, scalar: T) -> RadixCiphertext
    where
        T: TwosComplementNegation + DecomposableInto<u8>,
    {
        let mut ct_res = ct.clone();
        self.scalar_sub_assign_parallelized(&mut ct_res, scalar);
        ct_res
    }

    pub fn scalar_sub_assign_parallelized<T>(&self, ct: &mut RadixCiphertext, scalar: T)
    where
        T: TwosComplementNegation + DecomposableInto<u8>,
    {
        if !ct.block_carries_are_empty() {
            self.full_propagate_parallelized(ct);
        };

        self.unchecked_scalar_sub_assign(ct, scalar);

        if self.is_eligible_for_parallel_carryless_add() {
            self.propagate_single_carry_parallelized_low_latency(ct);
        } else {
            self.full_propagate_parallelized(ct);
        }
    }
}
