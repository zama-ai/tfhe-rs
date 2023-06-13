use crate::integer::block_decomposition::{BlockDecomposer, DecomposableInto};
use crate::integer::ciphertext::RadixCiphertext;
use crate::integer::ServerKey;
use rayon::prelude::*;

impl ServerKey {
    pub fn unchecked_scalar_bitand_parallelized<T>(
        &self,
        lhs: &RadixCiphertext,
        rhs: T,
    ) -> RadixCiphertext
    where
        T: DecomposableInto<u8>,
    {
        let mut result = lhs.clone();
        self.unchecked_scalar_bitand_assign_parallelized(&mut result, rhs);
        result
    }

    pub fn unchecked_scalar_bitand_assign_parallelized<T>(&self, lhs: &mut RadixCiphertext, rhs: T)
    where
        T: DecomposableInto<u8>,
    {
        let message_modulus = self.key.message_modulus.0;
        assert!(message_modulus.is_power_of_two());

        let clear_blocks = BlockDecomposer::with_early_stop_at_zero(rhs, message_modulus.ilog2())
            .iter_as::<u8>()
            .collect::<Vec<_>>();

        lhs.blocks
            .par_iter_mut()
            .zip(clear_blocks.par_iter().copied())
            .for_each(|(lhs_block, clear_block)| {
                self.key
                    .unchecked_scalar_bitand_assign(lhs_block, clear_block);
            });

        // Blocks beyond clear_blocks.len() should be 'bitanded'
        // with '0', however, no matter the block value the result will be 0
        let n = clear_blocks.len();
        for block in &mut lhs.blocks[n..] {
            self.key.create_trivial_assign(block, 0);
        }
    }

    pub fn smart_scalar_bitand_parallelized<T>(
        &self,
        lhs: &mut RadixCiphertext,
        rhs: T,
    ) -> RadixCiphertext
    where
        T: DecomposableInto<u8>,
    {
        if !lhs.block_carries_are_empty() {
            self.full_propagate(lhs);
        }
        let mut result = lhs.clone();
        self.unchecked_scalar_bitand_assign_parallelized(&mut result, rhs);
        result
    }

    pub fn smart_scalar_bitand_assign_parallelized<T>(&self, lhs: &mut RadixCiphertext, rhs: T)
    where
        T: DecomposableInto<u8>,
    {
        if !lhs.block_carries_are_empty() {
            self.full_propagate(lhs);
        }
        self.unchecked_scalar_bitand_assign_parallelized(lhs, rhs);
    }

    /// Computes homomorphically a bitand between a ciphertexts and a clear value
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
    /// let msg1 = 14u8;
    /// let msg2 = 97u8;
    ///
    /// let ct1 = cks.encrypt(msg1);
    ///
    /// let ct_res = sks.scalar_bitand_parallelized(&ct1, msg2);
    ///
    /// // Decrypt:
    /// let dec_result: u8 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, msg1 & msg2);
    /// ```
    pub fn scalar_bitand_parallelized<T>(&self, lhs: &RadixCiphertext, rhs: T) -> RadixCiphertext
    where
        T: DecomposableInto<u8>,
    {
        let mut result = lhs.clone();
        self.scalar_bitand_assign_parallelized(&mut result, rhs);
        result
    }

    /// Computes homomorphically a bitand between a ciphertexts and a clear value
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
    /// let msg1 = 123u8;
    /// let msg2 = 34u8;
    ///
    /// let mut ct1 = cks.encrypt(msg1);
    ///
    /// sks.scalar_bitand_assign_parallelized(&mut ct1, msg2);
    ///
    /// // Decrypt:
    /// let dec_result: u8 = cks.decrypt(&ct1);
    /// assert_eq!(dec_result, msg1 & msg2);
    /// ```
    pub fn scalar_bitand_assign_parallelized<T>(&self, lhs: &mut RadixCiphertext, rhs: T)
    where
        T: DecomposableInto<u8>,
    {
        if !lhs.block_carries_are_empty() {
            self.full_propagate(lhs);
        }
        self.unchecked_scalar_bitand_assign_parallelized(lhs, rhs);
    }

    pub fn unchecked_scalar_bitor_parallelized<T>(
        &self,
        lhs: &RadixCiphertext,
        rhs: T,
    ) -> RadixCiphertext
    where
        T: DecomposableInto<u8>,
    {
        let mut result = lhs.clone();
        self.unchecked_scalar_bitor_assign_parallelized(&mut result, rhs);
        result
    }

    pub fn unchecked_scalar_bitor_assign_parallelized<T>(&self, lhs: &mut RadixCiphertext, rhs: T)
    where
        T: DecomposableInto<u8>,
    {
        let message_modulus = self.key.message_modulus.0;
        assert!(message_modulus.is_power_of_two());

        let clear_blocks = BlockDecomposer::with_early_stop_at_zero(rhs, message_modulus.ilog2())
            .iter_as::<u8>()
            .collect::<Vec<_>>();

        lhs.blocks
            .par_iter_mut()
            .zip(clear_blocks.par_iter().copied())
            .for_each(|(lhs_block, clear_block)| {
                self.key
                    .unchecked_scalar_bitor_assign(lhs_block, clear_block);
            });

        // Blocks beyond clear_blocks.len() should be 'ored'
        // with '0', which means they keep their value
    }

    pub fn smart_scalar_bitor_parallelized<T>(
        &self,
        lhs: &mut RadixCiphertext,
        rhs: T,
    ) -> RadixCiphertext
    where
        T: DecomposableInto<u8>,
    {
        if !lhs.block_carries_are_empty() {
            self.full_propagate(lhs);
        }
        let mut result = lhs.clone();
        self.unchecked_scalar_bitor_assign_parallelized(&mut result, rhs);
        result
    }

    pub fn smart_scalar_bitor_assign_parallelized<T>(&self, lhs: &mut RadixCiphertext, rhs: T)
    where
        T: DecomposableInto<u8>,
    {
        if !lhs.block_carries_are_empty() {
            self.full_propagate(lhs);
        }
        self.unchecked_scalar_bitor_assign_parallelized(lhs, rhs);
    }

    /// Computes homomorphically a bitor between a ciphertexts and a clear value
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
    /// let msg1 = 14u8;
    /// let msg2 = 97u8;
    ///
    /// let ct1 = cks.encrypt(msg1);
    ///
    /// let ct_res = sks.scalar_bitor_parallelized(&ct1, msg2);
    ///
    /// // Decrypt:
    /// let dec_result: u8 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, msg1 | msg2);
    /// ```
    pub fn scalar_bitor_parallelized<T>(&self, lhs: &RadixCiphertext, rhs: T) -> RadixCiphertext
    where
        T: DecomposableInto<u8>,
    {
        let mut result = lhs.clone();
        self.scalar_bitor_assign_parallelized(&mut result, rhs);
        result
    }

    /// Computes homomorphically a bitor between a ciphertexts and a clear value
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
    /// let msg1 = 123u8;
    /// let msg2 = 34u8;
    ///
    /// let mut ct1 = cks.encrypt(msg1);
    ///
    /// sks.scalar_bitor_assign_parallelized(&mut ct1, msg2);
    ///
    /// // Decrypt:
    /// let dec_result: u8 = cks.decrypt(&ct1);
    /// assert_eq!(dec_result, msg1 | msg2);
    /// ```
    pub fn scalar_bitor_assign_parallelized<T>(&self, lhs: &mut RadixCiphertext, rhs: T)
    where
        T: DecomposableInto<u8>,
    {
        if !lhs.block_carries_are_empty() {
            self.full_propagate(lhs);
        }
        self.unchecked_scalar_bitor_assign_parallelized(lhs, rhs);
    }

    pub fn unchecked_scalar_bitxor_parallelized<T>(
        &self,
        lhs: &RadixCiphertext,
        rhs: T,
    ) -> RadixCiphertext
    where
        T: DecomposableInto<u8>,
    {
        let mut result = lhs.clone();
        self.unchecked_scalar_bitxor_assign_parallelized(&mut result, rhs);
        result
    }

    pub fn unchecked_scalar_bitxor_assign_parallelized<T>(&self, lhs: &mut RadixCiphertext, rhs: T)
    where
        T: DecomposableInto<u8>,
    {
        let message_modulus = self.key.message_modulus.0;
        assert!(message_modulus.is_power_of_two());

        let clear_blocks = BlockDecomposer::with_early_stop_at_zero(rhs, message_modulus.ilog2())
            .iter_as::<u8>()
            .collect::<Vec<_>>();

        lhs.blocks
            .par_iter_mut()
            .zip(clear_blocks.par_iter().copied())
            .for_each(|(lhs_block, clear_block)| {
                self.key
                    .unchecked_scalar_bitxor_assign(lhs_block, clear_block);
            });

        // Blocks beyond clear_blocks.len() should be 'xored'
        // with '0', which means they keep their value
    }

    pub fn smart_scalar_bitxor_parallelized<T>(
        &self,
        lhs: &mut RadixCiphertext,
        rhs: T,
    ) -> RadixCiphertext
    where
        T: DecomposableInto<u8>,
    {
        if !lhs.block_carries_are_empty() {
            self.full_propagate(lhs);
        }
        let mut result = lhs.clone();
        self.unchecked_scalar_bitxor_assign_parallelized(&mut result, rhs);
        result
    }

    pub fn smart_scalar_bitxor_assign_parallelized<T>(&self, lhs: &mut RadixCiphertext, rhs: T)
    where
        T: DecomposableInto<u8>,
    {
        if !lhs.block_carries_are_empty() {
            self.full_propagate(lhs);
        }
        self.unchecked_scalar_bitxor_assign_parallelized(lhs, rhs);
    }

    /// Computes homomorphically a bitxor between a ciphertexts and a clear value
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
    /// let msg1 = 14u8;
    /// let msg2 = 97u8;
    ///
    /// let ct1 = cks.encrypt(msg1);
    ///
    /// let ct_res = sks.scalar_bitxor_parallelized(&ct1, msg2);
    ///
    /// // Decrypt:
    /// let dec_result: u8 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, msg1 ^ msg2);
    /// ```
    pub fn scalar_bitxor_parallelized<T>(&self, lhs: &RadixCiphertext, rhs: T) -> RadixCiphertext
    where
        T: DecomposableInto<u8>,
    {
        let mut result = lhs.clone();
        self.scalar_bitxor_assign_parallelized(&mut result, rhs);
        result
    }

    /// Computes homomorphically a bitxor between a ciphertexts and a clear value
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
    /// let msg1 = 123u8;
    /// let msg2 = 34u8;
    ///
    /// let mut ct1 = cks.encrypt(msg1);
    ///
    /// sks.scalar_bitxor_assign_parallelized(&mut ct1, msg2);
    ///
    /// // Decrypt:
    /// let dec_result: u8 = cks.decrypt(&ct1);
    /// assert_eq!(dec_result, msg1 ^ msg2);
    /// ```
    pub fn scalar_bitxor_assign_parallelized<T>(&self, lhs: &mut RadixCiphertext, rhs: T)
    where
        T: DecomposableInto<u8>,
    {
        if !lhs.block_carries_are_empty() {
            self.full_propagate(lhs);
        }
        self.unchecked_scalar_bitxor_assign_parallelized(lhs, rhs);
    }
}
