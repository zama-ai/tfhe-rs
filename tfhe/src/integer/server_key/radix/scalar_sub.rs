use crate::core_crypto::prelude::Numeric;
use crate::integer::block_decomposition::{BlockDecomposer, DecomposableInto};
use crate::integer::ciphertext::IntegerRadixCiphertext;
use crate::integer::ServerKey;

pub trait TwosComplementNegation {
    fn twos_complement_negation(self) -> Self;
}

impl<T> TwosComplementNegation for T
where
    T: Numeric + std::ops::Not<Output = Self> + std::ops::Add<Self, Output = Self>,
{
    fn twos_complement_negation(self) -> Self {
        let flipped = !self;
        // The negation wraps like the two's complement it computes: `flipped + 1` overflows
        // only for `flipped == MAX` (zero for unsigned types, the minimum for signed ones),
        // and wraps to `!MAX` in both cases
        if flipped == Self::MAX {
            !Self::MAX
        } else {
            flipped + Self::ONE
        }
    }
}

impl ServerKey {
    /// Computes homomorphically a subtraction between a ciphertext and a scalar.
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
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, num_blocks);
    ///
    /// let msg = 40;
    /// let scalar = 3;
    ///
    /// let ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically an addition:
    /// let ct_res = sks.unchecked_scalar_sub(&ct, scalar);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg - scalar, dec);
    /// ```
    pub fn unchecked_scalar_sub<T, Scalar>(&self, ct: &T, scalar: Scalar) -> T
    where
        T: IntegerRadixCiphertext,
        Scalar: DecomposableInto<u8>,
    {
        let mut result = ct.clone();
        self.unchecked_scalar_sub_assign(&mut result, scalar);
        result
    }

    // Creates an iterator that returns the `num_blocks` blocks of the negated value of `scalar`,
    // that is of `-scalar` on a radix of `num_blocks` blocks
    //
    // Returns
    // - `None` if scalar is zero
    // - `Some` if scalar is non-zero
    //
    pub(crate) fn create_negated_block_decomposer<Scalar>(
        &self,
        scalar: Scalar,
        num_blocks: usize,
    ) -> Option<impl Iterator<Item = u8>>
    where
        Scalar: DecomposableInto<u8>,
    {
        if scalar == Scalar::ZERO {
            return None;
        }
        let message_modulus = self.key.message_modulus.0;
        let bits_in_message = message_modulus.ilog2();
        assert!(bits_in_message <= u8::BITS);

        // -scalar = !scalar + 1, computed on the blocks of the scalar extended to the radix
        // width (sign extended if it is signed). Negating the scalar in its own type would give
        // the wrong upper blocks for a negative scalar narrower than the radix (its opposite is
        // positive), and overflow for the minimum of a signed type.
        let max_block_value = message_modulus - 1;
        let mut carry = 1;
        let decomposer = BlockDecomposer::with_block_count(scalar, bits_in_message, num_blocks)
            .iter_as::<u8>()
            .map(move |block| {
                let negated_block = max_block_value - u64::from(block) + carry;
                carry = negated_block / message_modulus;
                (negated_block % message_modulus) as u8
            });
        Some(decomposer)
    }

    pub fn unchecked_scalar_sub_assign<T, Scalar>(&self, ct: &mut T, scalar: Scalar)
    where
        T: IntegerRadixCiphertext,
        Scalar: DecomposableInto<u8>,
    {
        let Some(decomposer) = self.create_negated_block_decomposer(scalar, ct.blocks().len())
        else {
            // subtraction by zero
            return;
        };
        for (ciphertext_block, scalar_block) in ct.blocks_mut().iter_mut().zip(decomposer) {
            self.key
                .unchecked_scalar_add_assign(ciphertext_block, scalar_block);
        }
    }
}
