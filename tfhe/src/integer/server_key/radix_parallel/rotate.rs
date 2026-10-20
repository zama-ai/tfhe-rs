use super::shift::BarrelShifterOperation;
use crate::integer::bigint::{U1024, U2048};
use crate::integer::ciphertext::{IntegerRadixCiphertext, RadixCiphertext};
use crate::integer::{ServerKey, U256, U512};

impl ServerKey {
    //======================================================================
    //                Rotate Right
    //======================================================================

    pub fn unchecked_rotate_right_parallelized<T>(&self, ct: &T, n: &RadixCiphertext) -> T
    where
        T: IntegerRadixCiphertext,
    {
        let mut result = ct.clone();
        self.unchecked_rotate_right_assign_parallelized(&mut result, n);
        result
    }

    pub fn unchecked_rotate_right_assign_parallelized<T>(&self, ct: &mut T, n: &RadixCiphertext)
    where
        T: IntegerRadixCiphertext,
    {
        self.unchecked_rotate_bits_assign(ct, n, BarrelShifterOperation::RightRotate);
    }

    /// Computes homomorphically a rotation of bits.
    ///
    /// Shifts the bits to the right by a specified amount,
    /// `n`, wrapping the truncated bits to the beginning of the resulting integer.
    ///
    /// The result is returned as a new ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, size);
    ///
    /// let msg = 128u8;
    /// let n = 2;
    ///
    /// let ct = cks.encrypt(msg as u64);
    /// let n_ct = cks.encrypt(n as u64);
    ///
    /// let ct_res = sks.rotate_right_parallelized(&ct, &n_ct);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg.rotate_right(n as u32) as u64, dec);
    /// ```
    pub fn rotate_right_assign_parallelized<T>(&self, ct: &mut T, rotate: &RadixCiphertext)
    where
        T: IntegerRadixCiphertext,
    {
        let rotate = self.clean_for_default_binary_assign_op(ct, rotate);
        self.unchecked_rotate_right_assign_parallelized(ct, &rotate);
    }

    pub fn rotate_right_parallelized<T>(&self, ct: &T, rotate: &RadixCiphertext) -> T
    where
        T: IntegerRadixCiphertext,
    {
        let mut ct_res = ct.clone();
        self.rotate_right_assign_parallelized(&mut ct_res, rotate);
        ct_res
    }

    //======================================================================
    //                Rotate Left
    //======================================================================

    pub fn unchecked_rotate_left_parallelized<T>(&self, ct_left: &T, n: &RadixCiphertext) -> T
    where
        T: IntegerRadixCiphertext,
    {
        let mut result = ct_left.clone();
        self.unchecked_rotate_left_assign_parallelized(&mut result, n);
        result
    }

    pub fn unchecked_rotate_left_assign_parallelized<T>(&self, ct: &mut T, n: &RadixCiphertext)
    where
        T: IntegerRadixCiphertext,
    {
        self.unchecked_rotate_bits_assign(ct, n, BarrelShifterOperation::LeftRotate);
    }

    /// Rotates the bits of `ct` by `amount` reduced modulo the number of bits of `ct`.
    ///
    ///
    /// Inputs must not have carries.
    fn unchecked_rotate_bits_assign<T>(
        &self,
        ct: &mut T,
        amount: &RadixCiphertext,
        operation: BarrelShifterOperation,
    ) where
        T: IntegerRadixCiphertext,
    {
        assert!(matches!(
            operation,
            BarrelShifterOperation::LeftRotate | BarrelShifterOperation::RightRotate
        ));

        let bits_per_block = self.message_modulus().0.ilog2();
        let num_bits_encrypted_by_ct = ct.blocks().len() as u64 * u64::from(bits_per_block);
        let num_bits_encrypted_by_amount = amount.blocks.len() as u32 * bits_per_block;

        // For all block sizes, unchecked_shift_rotate_assign uses a barrel shifter,
        // which truncates the `amount` to only take the ⌈log₂(num_bits)⌉.
        // This is a modular reduction  only when `num_bits` is a power of two.
        // For non powers of two, Rotating a radix that encrypts 6 bits, by `8`
        // would rotate by 0 instead of 2 (8 % 6 = 2, 8 % 2^⌈log₂(6)⌉ = 8 % 8 = 0)
        //
        // So to have the consistent modular reduction `amount % nb_bits(ct)`, we will
        // use a scalar_rem, but for powers of two we can skip it.
        //
        // And there's a reason we skip the call to the remainder op:
        // the remainder op would introduce a PBS, to cut the bits of the last block
        // when the number of bits to keep is not a multiple of the number of bits in a block.
        // The truncation of the barrel shifter used in the rotate does it naturally, without
        // extra cost.
        // e.g: rot(FheUint32, x), 2_2 params -> num_bits_encrypted_by_ct = 32 -> it is power of 2,
        // the number of bits to keep is log2(32) = 5, 5 is not a multiple of 2, thus the remainder
        // op would do a PBS to clear the high bit of the 3rd block, whereas the barrel shifter
        // already handles this trimming nicely
        if num_bits_encrypted_by_ct.is_power_of_two() {
            self.unchecked_shift_rotate_bits_assign(ct, amount, operation);
            return;
        }

        // The scalar division requires the scalar type used to have a number of bits >= to the
        // number of bits the ciphertext encrypts
        //
        // The ciphertext we use in the division is the `amount`, so we need to pick a scalar type
        // that has at least as many bits as what `amount` encrypts. This type is used to
        // store the number of bits encrypted by the `ct` to be rotated
        //
        // So that we can do `amount` % num_bits_encrypted_by_ct
        //
        // Currently there's a limit that amount cannot encrypt more than 2048 bits,
        // but don't be lost, it does not mean amount can encrypt a value in [0, 2048], but
        // that it can encrypt a value in [0, 2**2048[
        let amount = if num_bits_encrypted_by_amount <= u64::BITS {
            self.unchecked_scalar_rem_parallelized(amount, num_bits_encrypted_by_ct)
        } else if num_bits_encrypted_by_amount <= u128::BITS {
            self.unchecked_scalar_rem_parallelized(amount, u128::from(num_bits_encrypted_by_ct))
        } else if num_bits_encrypted_by_amount <= 256 {
            self.unchecked_scalar_rem_parallelized(amount, U256::from(num_bits_encrypted_by_ct))
        } else if num_bits_encrypted_by_amount <= 512 {
            self.unchecked_scalar_rem_parallelized(amount, U512::from(num_bits_encrypted_by_ct))
        } else if num_bits_encrypted_by_amount <= 1024 {
            self.unchecked_scalar_rem_parallelized(amount, U1024::from(num_bits_encrypted_by_ct))
        } else if num_bits_encrypted_by_amount <= 2048 {
            self.unchecked_scalar_rem_parallelized(amount, U2048::from(num_bits_encrypted_by_ct))
        } else {
            panic!(
                "rotations by an `amount` that encrypts more than 2048 bits are not supported, \
                got {num_bits_encrypted_by_amount} bits, consider casting the amount to a smaller \
                radix"
            );
        };
        self.unchecked_shift_rotate_bits_assign(ct, &amount, operation);
    }

    pub fn rotate_left_assign_parallelized<T>(&self, ct: &mut T, rotate: &RadixCiphertext)
    where
        T: IntegerRadixCiphertext,
    {
        let rotate = self.clean_for_default_binary_assign_op(ct, rotate);
        self.unchecked_rotate_left_assign_parallelized(ct, &rotate);
    }

    /// Computes homomorphically a rotation of bits.
    ///
    /// Shifts the bits to the left by a specified amount,
    /// `n`, wrapping the truncated bits to the end of the resulting integer.
    ///
    /// The result is returned as a new ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, size);
    ///
    /// let msg = 128u8;
    /// let n = 2;
    ///
    /// let ct = cks.encrypt(msg as u64);
    /// let n_ct = cks.encrypt(n as u64);
    ///
    /// let ct_res = sks.rotate_left_parallelized(&ct, &n_ct);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg.rotate_left(n as u32) as u64, dec);
    /// ```
    pub fn rotate_left_parallelized<T>(&self, ct: &T, rotate: &RadixCiphertext) -> T
    where
        T: IntegerRadixCiphertext,
    {
        let mut ct_res = ct.clone();
        self.rotate_left_assign_parallelized(&mut ct_res, rotate);
        ct_res
    }
}
