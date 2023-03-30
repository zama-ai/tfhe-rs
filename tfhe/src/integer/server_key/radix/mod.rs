mod add;
mod bitwise_op;
mod comparison;
mod mul;
mod neg;
mod scalar_add;
mod scalar_mul;
mod scalar_sub;
mod shift;
mod sub;

use super::ServerKey;

use crate::integer::ciphertext::RadixCiphertext;
use crate::shortint::PBSOrderMarker;

#[cfg(test)]
mod tests;

impl ServerKey {
    /// Create a ciphertext filled with zeros
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::{gen_keys_radix, RadixCiphertextBig};
    /// use tfhe::shortint::parameters::DEFAULT_PARAMETERS;
    ///
    /// let num_blocks = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(&DEFAULT_PARAMETERS, num_blocks);
    ///
    /// let ctxt: RadixCiphertextBig = sks.create_trivial_zero_radix(num_blocks);
    ///
    /// // Decrypt:
    /// let dec = cks.decrypt(&ctxt);
    /// assert_eq!(0, dec);
    /// ```
    pub fn create_trivial_zero_radix<PBSOrder: PBSOrderMarker>(
        &self,
        num_blocks: usize,
    ) -> RadixCiphertext<PBSOrder> {
        let mut vec_res = Vec::with_capacity(num_blocks);
        for _ in 0..num_blocks {
            vec_res.push(self.key.create_trivial(0_u64));
        }

        RadixCiphertext::from(vec_res)
    }

    /// Propagate the carry of the 'index' block to the next one.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::integer::{gen_keys_radix, IntegerCiphertext};
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// let num_blocks = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(&PARAM_MESSAGE_2_CARRY_2, num_blocks);
    ///
    /// let msg = 7;
    ///
    /// let ct1 = cks.encrypt(msg);
    /// let ct2 = cks.encrypt(msg);
    ///
    /// // Compute homomorphically an addition:
    /// let mut ct_res = sks.unchecked_add(&ct1, &ct2);
    /// sks.propagate(&mut ct_res, 0);
    ///
    /// // Decrypt one block:
    /// let res = cks.decrypt_one_block(&ct_res.blocks()[1]);
    /// assert_eq!(3, res);
    /// ```
    pub fn propagate<PBSOrder: PBSOrderMarker>(
        &self,
        ctxt: &mut RadixCiphertext<PBSOrder>,
        index: usize,
    ) {
        let carry = self.key.carry_extract(&ctxt.blocks[index]);

        ctxt.blocks[index] = self.key.message_extract(&ctxt.blocks[index]);

        //add the carry to the next block
        if index < ctxt.blocks.len() - 1 {
            self.key
                .unchecked_add_assign(&mut ctxt.blocks[index + 1], &carry);
        }
    }

    /// Propagate all the carries.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::integer::{gen_keys_radix, IntegerCiphertext};
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// let num_blocks = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(&PARAM_MESSAGE_2_CARRY_2, num_blocks);
    ///
    /// let msg = 10;
    ///
    /// let mut ct1 = cks.encrypt(msg);
    /// let mut ct2 = cks.encrypt(msg);
    ///
    /// // Compute homomorphically an addition:
    /// let mut ct_res = sks.unchecked_add(&mut ct1, &mut ct2);
    /// sks.full_propagate(&mut ct_res);
    ///
    /// // Decrypt:
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!(msg + msg, res);
    /// ```
    pub fn full_propagate<PBSOrder: PBSOrderMarker>(&self, ctxt: &mut RadixCiphertext<PBSOrder>) {
        let len = ctxt.blocks.len();
        for i in 0..len {
            self.propagate(ctxt, i);
        }
    }
}
