mod add;
mod bitwise_op;
mod comparison;
mod mul;
pub(crate) mod neg;
mod scalar_add;
pub(super) mod scalar_mul;
pub(super) mod scalar_sub;
mod shift;
pub(super) mod slice;
mod sub;

use super::ServerKey;
use crate::integer::block_decomposition::DecomposableInto;
use crate::integer::ciphertext::{IntegerCiphertext, IntegerRadixCiphertext, RadixCiphertext};
use crate::integer::encryption::encrypt_words_radix_impl;
use crate::integer::{BooleanBlock, SignedRadixCiphertext};

mod even_odd;
#[cfg(test)]
mod tests;

impl ServerKey {
    pub fn create_trivial_zero_assign_radix<T>(&self, ctxt: &mut T)
    where
        T: IntegerRadixCiphertext,
    {
        for block in ctxt.blocks_mut() {
            self.key.create_trivial_assign(block, 0);
        }
    }

    /// Create a ciphertext filled with zeros
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::{gen_keys_radix, RadixCiphertext};
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    ///
    /// let num_blocks = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, num_blocks);
    ///
    /// let ctxt: RadixCiphertext = sks.create_trivial_zero_radix(num_blocks);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ctxt);
    /// assert_eq!(0, dec);
    /// ```
    pub fn create_trivial_zero_radix<T>(&self, num_blocks: usize) -> T
    where
        T: IntegerRadixCiphertext,
    {
        let mut vec_res = Vec::with_capacity(num_blocks);
        for _ in 0..num_blocks {
            vec_res.push(self.key.create_trivial(0_u64));
        }

        T::from_blocks(vec_res)
    }

    pub fn create_trivial_boolean_block(&self, value: bool) -> BooleanBlock {
        BooleanBlock::new_unchecked(self.key.create_trivial(u64::from(value)))
    }

    pub fn create_trivial_max_radix<T>(&self, num_blocks: usize) -> T
    where
        T: IntegerRadixCiphertext,
    {
        let block_with_all_ones = self.key.create_trivial(self.key.message_modulus.0 - 1);
        if T::IS_SIGNED {
            // The max of a two's complement number is a 0 in msb and then only 1
            let mut trivial_blocks = vec![block_with_all_ones; num_blocks - 1];
            // msb blocks has its last bit set to 0, the rest are 1
            trivial_blocks.push(self.key.create_trivial((self.message_modulus().0 >> 1) - 1));
            T::from_blocks(trivial_blocks)
        } else {
            // Max value is simply all bits set to one
            T::from_blocks(vec![block_with_all_ones; num_blocks])
        }
    }

    pub fn create_trivial_min_radix<T>(&self, num_blocks: usize) -> T
    where
        T: IntegerRadixCiphertext,
    {
        if T::IS_SIGNED {
            // create num_blocks -1 blocks containing 0
            let mut trivial_blocks = vec![self.key.create_trivial(0); num_blocks - 1];
            // msb block has its msb set to 1, rest is 0
            let num_bits_of_message = self.message_modulus().0.ilog2();
            trivial_blocks.push(
                self.key
                    .create_trivial((self.message_modulus().0 - 1) << (num_bits_of_message - 1)),
            );
            T::from_blocks(trivial_blocks)
        } else {
            // Min value is simply 0
            self.create_trivial_zero_radix(num_blocks)
        }
    }

    /// Create a trivial radix ciphertext
    ///
    /// Trivial means that the value is not encrypted
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::{gen_keys_radix, RadixCiphertext};
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    ///
    /// let num_blocks = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, num_blocks);
    ///
    /// let ctxt: RadixCiphertext = sks.create_trivial_radix(212u64, num_blocks);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ctxt);
    /// assert_eq!(212, dec);
    /// ```
    pub fn create_trivial_radix<T, C>(&self, value: T, num_blocks: usize) -> C
    where
        T: DecomposableInto<u64>,
        C: IntegerRadixCiphertext + From<Vec<crate::shortint::Ciphertext>>,
    {
        encrypt_words_radix_impl(
            &self.key,
            value,
            num_blocks,
            crate::shortint::ServerKey::create_trivial,
        )
    }

    /// Prepend trivial zero LSB blocks to an existing [`RadixCiphertext`]. This can be useful for
    /// casting operations.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::integer::{gen_keys_radix, IntegerCiphertext};
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    ///
    /// let num_blocks = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, num_blocks);
    ///
    /// let msg = 7u64;
    ///
    /// let mut ct1 = cks.encrypt(msg);
    /// assert_eq!(ct1.blocks().len(), 4);
    ///
    /// let added_blocks = 2;
    /// sks.extend_radix_with_trivial_zero_blocks_lsb_assign(&mut ct1, added_blocks);
    /// assert_eq!(ct1.blocks().len(), 6);
    ///
    /// // Decrypt
    /// let res: u64 = cks.decrypt(&ct1);
    /// assert_eq!(
    ///     7 * (PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128
    ///         .message_modulus
    ///         .0)
    ///         .pow(added_blocks as u32),
    ///     res
    /// );
    /// ```
    pub fn extend_radix_with_trivial_zero_blocks_lsb_assign(
        &self,
        ct: &mut RadixCiphertext,
        num_blocks: usize,
    ) {
        self.extend_radix_with_trivial_zero_blocks_msb_assign(ct, num_blocks);
        ct.blocks.rotate_right(num_blocks);
    }

    /// Prepend trivial zero LSB blocks to an existing [`RadixCiphertext`] and returns the result as
    /// a new [`RadixCiphertext`]. This can be useful for casting operations.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::integer::{gen_keys_radix, IntegerCiphertext};
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    ///
    /// let num_blocks = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, num_blocks);
    ///
    /// let msg = 7u64;
    ///
    /// let ct1 = cks.encrypt(msg);
    /// assert_eq!(ct1.blocks().len(), 4);
    ///
    /// let added_blocks = 2;
    /// let ct_res = sks.extend_radix_with_trivial_zero_blocks_lsb(&ct1, added_blocks);
    /// assert_eq!(ct_res.blocks().len(), 6);
    ///
    /// // Decrypt
    /// let res: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(
    ///     7 * (PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128
    ///         .message_modulus
    ///         .0)
    ///         .pow(added_blocks as u32),
    ///     res
    /// );
    /// ```
    pub fn extend_radix_with_trivial_zero_blocks_lsb(
        &self,
        ct: &RadixCiphertext,
        num_blocks: usize,
    ) -> RadixCiphertext {
        let mut ct_res = ct.clone();
        self.extend_radix_with_trivial_zero_blocks_lsb_assign(&mut ct_res, num_blocks);
        ct_res
    }

    /// Append trivial zero MSB blocks to an existing [`RadixCiphertext`]. This can be useful for
    /// casting operations.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::integer::{gen_keys_radix, IntegerCiphertext};
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    ///
    /// let num_blocks = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, num_blocks);
    ///
    /// let msg = 7u64;
    ///
    /// let mut ct1 = cks.encrypt(msg);
    /// assert_eq!(ct1.blocks().len(), 4);
    ///
    /// sks.extend_radix_with_trivial_zero_blocks_msb_assign(&mut ct1, 2);
    /// assert_eq!(ct1.blocks().len(), 6);
    ///
    /// // Decrypt
    /// let res: u64 = cks.decrypt(&ct1);
    /// assert_eq!(7, res);
    /// ```
    pub fn extend_radix_with_trivial_zero_blocks_msb_assign(
        &self,
        ct: &mut RadixCiphertext,
        num_blocks: usize,
    ) {
        let block_trivial_zero = self.key.create_trivial(0);
        ct.blocks
            .resize(ct.blocks.len() + num_blocks, block_trivial_zero);
    }

    /// Append trivial zero MSB blocks to an existing [`RadixCiphertext`] and returns the result as
    /// a new [`RadixCiphertext`]. This can be useful for casting operations.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::integer::{gen_keys_radix, IntegerCiphertext};
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    ///
    /// let num_blocks = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, num_blocks);
    ///
    /// let msg = 7u64;
    ///
    /// let ct1 = cks.encrypt(msg);
    /// assert_eq!(ct1.blocks().len(), 4);
    ///
    /// let ct_res = sks.extend_radix_with_trivial_zero_blocks_msb(&ct1, 2);
    /// assert_eq!(ct_res.blocks().len(), 6);
    ///
    /// // Decrypt
    /// let res: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(7, res);
    /// ```
    pub fn extend_radix_with_trivial_zero_blocks_msb(
        &self,
        ct: &RadixCiphertext,
        num_blocks: usize,
    ) -> RadixCiphertext {
        let mut ct_res = ct.clone();
        self.extend_radix_with_trivial_zero_blocks_msb_assign(&mut ct_res, num_blocks);
        ct_res
    }

    /// Remove LSB blocks from an existing [`RadixCiphertext`]. This can be useful for casting
    /// operations.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::integer::{gen_keys_radix, IntegerCiphertext};
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    ///
    /// let num_blocks = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, num_blocks);
    ///
    /// let msg = 119u64;
    ///
    /// let mut ct1 = cks.encrypt(msg);
    /// assert_eq!(ct1.blocks().len(), 4);
    ///
    /// sks.trim_radix_blocks_lsb_assign(&mut ct1, 2);
    /// assert_eq!(ct1.blocks().len(), 2);
    ///
    /// // Decrypt
    /// let res: u64 = cks.decrypt(&ct1);
    /// assert_eq!(7, res);
    /// ```
    pub fn trim_radix_blocks_lsb_assign(&self, ct: &mut RadixCiphertext, num_blocks: usize) {
        ct.blocks.rotate_left(num_blocks);
        self.trim_radix_blocks_msb_assign(ct, num_blocks);
    }

    /// Remove LSB blocks from an existing [`RadixCiphertext`] and returns the result as a new
    /// [`RadixCiphertext`]. This can be useful for casting operations.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::integer::{gen_keys_radix, IntegerCiphertext};
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    ///
    /// let num_blocks = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, num_blocks);
    ///
    /// let msg = 119u64;
    ///
    /// let ct1 = cks.encrypt(msg);
    /// assert_eq!(ct1.blocks().len(), 4);
    ///
    /// let ct_res = sks.trim_radix_blocks_lsb(&ct1, 2);
    /// assert_eq!(ct_res.blocks().len(), 2);
    ///
    /// // Decrypt
    /// let res: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(7, res);
    /// ```
    pub fn trim_radix_blocks_lsb(
        &self,
        ct: &RadixCiphertext,
        num_blocks: usize,
    ) -> RadixCiphertext {
        let mut ct_res = ct.clone();
        self.trim_radix_blocks_lsb_assign(&mut ct_res, num_blocks);
        ct_res
    }

    /// Remove MSB blocks from an existing [`RadixCiphertext`]. This can be useful for
    /// casting operations.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::integer::{gen_keys_radix, IntegerCiphertext};
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    ///
    /// let num_blocks = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, num_blocks);
    ///
    /// let msg = 119u64;
    ///
    /// let mut ct1 = cks.encrypt(msg);
    /// assert_eq!(ct1.blocks().len(), 4);
    ///
    /// sks.trim_radix_blocks_msb_assign(&mut ct1, 2);
    /// assert_eq!(ct1.blocks().len(), 2);
    ///
    /// // Decrypt
    /// let res: u64 = cks.decrypt(&ct1);
    /// assert_eq!(7, res);
    /// ```
    pub fn trim_radix_blocks_msb_assign(&self, ct: &mut RadixCiphertext, num_blocks: usize) {
        let len = ct.blocks.len();
        ct.blocks.truncate(len - num_blocks);
        if !ct.block_carries_are_empty() {
            self.full_propagate_parallelized(ct);
        }
    }

    /// Remove MSB blocks from an existing [`RadixCiphertext`] and returns the result as a new
    /// [`RadixCiphertext`]. This can be useful for casting operations.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::integer::{gen_keys_radix, IntegerCiphertext};
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    ///
    /// let num_blocks = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, num_blocks);
    ///
    /// let msg = 119u64;
    ///
    /// let ct1 = cks.encrypt(msg);
    /// assert_eq!(ct1.blocks().len(), 4);
    ///
    /// let ct_res = sks.trim_radix_blocks_msb(&ct1, 2);
    /// assert_eq!(ct_res.blocks().len(), 2);
    ///
    /// // Decrypt
    /// let res: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(7, res);
    /// ```
    pub fn trim_radix_blocks_msb(
        &self,
        ct: &RadixCiphertext,
        num_blocks: usize,
    ) -> RadixCiphertext {
        let mut ct_res = ct.clone();
        self.trim_radix_blocks_msb_assign(&mut ct_res, num_blocks);
        ct_res
    }

    /// Extends the most significant blocks using the sign bit.
    /// Used to cast [SignedRadixCiphertext]
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::integer::{gen_keys_radix, IntegerCiphertext};
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    ///
    /// let num_blocks = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, num_blocks);
    ///
    /// let msg = -1i8;
    ///
    /// let mut ct1 = cks.encrypt_signed(msg);
    /// assert_eq!(ct1.blocks().len(), 4);
    ///
    /// sks.extend_radix_with_sign_msb_assign(&mut ct1, 4);
    /// assert_eq!(ct1.blocks().len(), 8);
    ///
    /// // Decrypt
    /// let res: i16 = cks.decrypt_signed(&ct1);
    /// assert_eq!(-1, res);
    /// ```
    pub fn extend_radix_with_sign_msb_assign(
        &self,
        ct: &mut SignedRadixCiphertext,
        num_blocks: usize,
    ) {
        if !ct.block_carries_are_empty() {
            self.full_propagate_parallelized(ct)
        }
        let message_modulus = self.key.message_modulus.0;
        let num_bits_in_block = message_modulus.ilog2();
        let padding_block_creator_lut = self.key.generate_lookup_table(|x| {
            let x = x % message_modulus;
            let x_sign_bit = (x >> (num_bits_in_block - 1)) & 1;
            // padding is a message full of 1 if sign bit is one
            // else padding is a zero message
            (message_modulus - 1) * x_sign_bit
        });
        let last_block = ct
            .blocks
            .last()
            .expect("Cannot sign extend an empty ciphertext");
        let padding_block = self
            .key
            .apply_lookup_table(last_block, &padding_block_creator_lut);

        let new_len = num_blocks + ct.blocks.len();
        ct.blocks.resize(new_len, padding_block);
    }

    /// Extends the most significant blocks using the sign bit.
    /// Used to cast [SignedRadixCiphertext]
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::integer::{gen_keys_radix, IntegerCiphertext};
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    ///
    /// let num_blocks = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, num_blocks);
    ///
    /// let msg = -2i8;
    ///
    /// let ct1 = cks.encrypt_signed(msg);
    /// assert_eq!(ct1.blocks().len(), 4);
    ///
    /// let ct_res = sks.extend_radix_with_sign_msb(&ct1, 4);
    /// assert_eq!(ct_res.blocks().len(), 8);
    ///
    /// // Decrypt
    /// let res: i16 = cks.decrypt_signed(&ct_res);
    /// assert_eq!(-2, res);
    /// ```
    pub fn extend_radix_with_sign_msb(
        &self,
        ct: &SignedRadixCiphertext,
        num_blocks: usize,
    ) -> SignedRadixCiphertext {
        let mut result = ct.clone();
        self.extend_radix_with_sign_msb_assign(&mut result, num_blocks);
        result
    }

    /// Cast a RadixCiphertext or SignedRadixCiphertext to a RadixCiphertext
    /// with a possibly different number of blocks
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::integer::{gen_keys_radix, IntegerCiphertext};
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    ///
    /// let num_blocks = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, num_blocks);
    ///
    /// let msg = -2i8;
    ///
    /// let ct1 = cks.encrypt_signed(msg);
    /// assert_eq!(ct1.blocks().len(), 4);
    ///
    /// let ct_res = sks.cast_to_unsigned(ct1, 8);
    /// assert_eq!(ct_res.blocks().len(), 8);
    ///
    /// // Decrypt
    /// let res: u16 = cks.decrypt(&ct_res);
    /// assert_eq!(msg as u16, res);
    /// ```
    pub fn cast_to_unsigned<T: IntegerRadixCiphertext>(
        &self,
        mut source: T,
        target_num_blocks: usize,
    ) -> RadixCiphertext {
        if !source.block_carries_are_empty() {
            self.full_propagate_parallelized(&mut source);
        }

        let blocks = source.into_blocks();
        let current_num_blocks = blocks.len();

        let blocks = if T::IS_SIGNED {
            // Casting from signed to unsigned
            // We have to trim or sign extend first
            if target_num_blocks > current_num_blocks {
                let mut ct_as_signed_radix = SignedRadixCiphertext::from_blocks(blocks);
                let num_blocks_to_add = target_num_blocks - current_num_blocks;
                self.extend_radix_with_sign_msb_assign(&mut ct_as_signed_radix, num_blocks_to_add);
                ct_as_signed_radix.blocks
            } else {
                let mut ct_as_unsigned_radix = crate::integer::RadixCiphertext::from_blocks(blocks);
                let num_blocks_to_remove = current_num_blocks - target_num_blocks;
                self.trim_radix_blocks_msb_assign(&mut ct_as_unsigned_radix, num_blocks_to_remove);
                ct_as_unsigned_radix.blocks
            }
        } else {
            // Casting from unsigned to unsigned, this is just about trimming/extending with zeros
            let mut ct_as_unsigned_radix = crate::integer::RadixCiphertext::from_blocks(blocks);
            if target_num_blocks > current_num_blocks {
                let num_blocks_to_add = target_num_blocks - current_num_blocks;
                self.extend_radix_with_trivial_zero_blocks_msb_assign(
                    &mut ct_as_unsigned_radix,
                    num_blocks_to_add,
                );
            } else {
                let num_blocks_to_remove = current_num_blocks - target_num_blocks;
                self.trim_radix_blocks_msb_assign(&mut ct_as_unsigned_radix, num_blocks_to_remove);
            }
            ct_as_unsigned_radix.blocks
        };

        assert_eq!(
            blocks.len(),
            target_num_blocks,
            "internal error, wrong number of blocks after casting"
        );
        crate::integer::RadixCiphertext::from(blocks)
    }

    /// Cast a RadixCiphertext or SignedRadixCiphertext to a SignedRadixCiphertext
    /// with a possibly different number of blocks
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::integer::{gen_keys_radix, IntegerCiphertext};
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    ///
    /// let num_blocks = 8;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, num_blocks);
    ///
    /// let msg = u16::MAX;
    ///
    /// let ct1 = cks.encrypt(msg);
    /// assert_eq!(ct1.blocks().len(), num_blocks);
    ///
    /// let ct_res = sks.cast_to_signed(ct1, 4);
    /// assert_eq!(ct_res.blocks().len(), 4);
    ///
    /// // Decrypt
    /// let res: i8 = cks.decrypt_signed(&ct_res);
    /// assert_eq!(msg as i8, res);
    /// ```
    pub fn cast_to_signed<T: IntegerRadixCiphertext>(
        &self,
        mut source: T,
        target_num_blocks: usize,
    ) -> SignedRadixCiphertext {
        if !source.block_carries_are_empty() {
            self.full_propagate_parallelized(&mut source);
        }

        let current_num_blocks = source.blocks().len();

        let blocks = if T::IS_SIGNED {
            // Casting from signed to signed
            if target_num_blocks > current_num_blocks {
                let mut ct_as_signed_radix =
                    SignedRadixCiphertext::from_blocks(source.into_blocks());
                let num_blocks_to_add = target_num_blocks - current_num_blocks;
                self.extend_radix_with_sign_msb_assign(&mut ct_as_signed_radix, num_blocks_to_add);
                ct_as_signed_radix.blocks
            } else {
                let mut ct_as_unsigned_radix = RadixCiphertext::from_blocks(source.into_blocks());
                let num_blocks_to_remove = current_num_blocks - target_num_blocks;
                self.trim_radix_blocks_msb_assign(&mut ct_as_unsigned_radix, num_blocks_to_remove);
                ct_as_unsigned_radix.blocks
            }
        } else {
            // casting from unsigned to signed
            let mut ct_as_unsigned_radix = RadixCiphertext::from_blocks(source.into_blocks());
            if target_num_blocks > current_num_blocks {
                let num_blocks_to_add = target_num_blocks - current_num_blocks;
                self.extend_radix_with_trivial_zero_blocks_msb_assign(
                    &mut ct_as_unsigned_radix,
                    num_blocks_to_add,
                );
            } else {
                let num_blocks_to_remove = current_num_blocks - target_num_blocks;
                self.trim_radix_blocks_msb_assign(&mut ct_as_unsigned_radix, num_blocks_to_remove);
            }
            ct_as_unsigned_radix.blocks
        };

        assert_eq!(
            blocks.len(),
            target_num_blocks,
            "internal error, wrong number of blocks after casting"
        );
        SignedRadixCiphertext::from_blocks(blocks)
    }

    /// Propagate the carry of the 'index' block to the next one.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::integer::{gen_keys_radix, IntegerCiphertext};
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    ///
    /// let num_blocks = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, num_blocks);
    ///
    /// let msg = 7u64;
    ///
    /// let ct1 = cks.encrypt(msg);
    /// let ct2 = cks.encrypt(msg);
    ///
    /// // Compute homomorphically an addition:
    /// let mut ct_res = sks.unchecked_add(&ct1, &ct2);
    /// sks.propagate(&mut ct_res, 0);
    ///
    /// // Decrypt one block:
    /// let res: u64 = cks.decrypt_one_block(&ct_res.blocks()[1]);
    /// assert_eq!(3, res);
    /// ```
    pub fn propagate<T>(&self, ctxt: &mut T, index: usize)
    where
        T: IntegerRadixCiphertext,
    {
        let carry = self.key.carry_extract(&ctxt.blocks()[index]);

        ctxt.blocks_mut()[index] = self.key.message_extract(&ctxt.blocks()[index]);

        //add the carry to the next block
        if index < ctxt.blocks().len() - 1 {
            let next_block = &mut ctxt.blocks_mut()[index + 1];
            if self
                .key
                .max_noise_level
                .validate(next_block.noise_level() + carry.noise_level())
                .is_err()
            {
                let id_lut = self.key.generate_lookup_table(|x| x);
                self.key.apply_lookup_table_assign(next_block, &id_lut);
            }
            self.key
                .unchecked_add_assign(&mut ctxt.blocks_mut()[index + 1], &carry);
        }
    }

    /// Propagate all the carries.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    ///
    /// let num_blocks = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, num_blocks);
    ///
    /// let msg = 10;
    ///
    /// let ct1 = cks.encrypt(msg);
    /// let ct2 = cks.encrypt(msg);
    ///
    /// // Compute homomorphically an addition:
    /// let mut ct_res = sks.unchecked_add(&ct1, &ct2);
    /// sks.full_propagate(&mut ct_res);
    ///
    /// // Decrypt:
    /// let res: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg + msg, res);
    /// ```
    pub fn full_propagate<T>(&self, ctxt: &mut T)
    where
        T: IntegerRadixCiphertext,
    {
        self.partial_propagate(ctxt, 0);
    }

    /// Propagates carries from
    /// start_index to then end.
    ///
    /// Last carry is not propagated as
    /// it has nothing to propagate to.
    fn partial_propagate<T>(&self, ctxt: &mut T, start_index: usize)
    where
        T: IntegerRadixCiphertext,
    {
        let len = ctxt.blocks().len();
        for i in start_index..len {
            self.propagate(ctxt, i);
        }
    }
}
