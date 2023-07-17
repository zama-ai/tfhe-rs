mod add;
mod bit_extractor;
mod bitwise_op;
mod comparison;
mod div_mod;
mod mul;
mod neg;
mod rotate;
mod scalar_add;
mod scalar_bitwise_op;
mod scalar_comparison;
mod scalar_div_mod;
mod scalar_mul;
mod scalar_rotate;
mod scalar_shift;
mod scalar_sub;
mod shift;
mod sub;

#[cfg(test)]
mod tests;

use super::ServerKey;
use crate::integer::ciphertext::RadixCiphertext;
pub use scalar_div_mod::{MiniUnsignedInteger, Reciprocable};

// parallelized versions
impl ServerKey {
    /// Propagate the carry of the 'index' block to the next one.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::integer::{gen_keys_radix, IntegerCiphertext};
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks);
    ///
    /// let msg = 7u64;
    ///
    /// let ct1 = cks.encrypt(msg);
    /// let ct2 = cks.encrypt(msg);
    ///
    /// // Compute homomorphically an addition:
    /// let mut ct_res = sks.unchecked_add(&ct1, &ct2);
    /// sks.propagate_parallelized(&mut ct_res, 0);
    ///
    /// // Decrypt one block:
    /// let res: u64 = cks.decrypt_one_block(&ct_res.blocks()[1]);
    /// assert_eq!(3, res);
    /// ```
    pub fn propagate_parallelized(&self, ctxt: &mut RadixCiphertext, index: usize) {
        let (carry, message) = rayon::join(
            || self.key.carry_extract(&ctxt.blocks[index]),
            || self.key.message_extract(&ctxt.blocks[index]),
        );
        ctxt.blocks[index] = message;

        //add the carry to the next block
        if index < ctxt.blocks.len() - 1 {
            self.key
                .unchecked_add_assign(&mut ctxt.blocks[index + 1], &carry);
        }
    }

    pub fn partial_propagate_parallelized(&self, ctxt: &mut RadixCiphertext, start_index: usize) {
        let len = ctxt.blocks.len();
        for i in start_index..len {
            self.propagate_parallelized(ctxt, i);
        }
    }

    /// Propagate all the carries.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks);
    ///
    /// let msg = 10u64;
    ///
    /// let mut ct1 = cks.encrypt(msg);
    /// let mut ct2 = cks.encrypt(msg);
    ///
    /// // Compute homomorphically an addition:
    /// let mut ct_res = sks.unchecked_add(&mut ct1, &mut ct2);
    /// sks.full_propagate_parallelized(&mut ct_res);
    ///
    /// // Decrypt:
    /// let res: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg + msg, res);
    /// ```
    pub fn full_propagate_parallelized(&self, ctxt: &mut RadixCiphertext) {
        self.partial_propagate_parallelized(ctxt, 0)
    }
}
