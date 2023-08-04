mod add;
mod bit_extractor;
mod bitwise_op;
mod cmux;
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
mod tests_signed;
#[cfg(test)]
mod tests_unsigned;

use crate::integer::ciphertext::IntegerRadixCiphertext;

use super::ServerKey;
pub use scalar_div_mod::{MiniUnsignedInteger, Reciprocable};

use rayon::prelude::*;

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
    pub fn propagate_parallelized<T>(&self, ctxt: &mut T, index: usize)
    where
        T: IntegerRadixCiphertext,
    {
        let (carry, message) = rayon::join(
            || self.key.carry_extract(&ctxt.blocks()[index]),
            || self.key.message_extract(&ctxt.blocks()[index]),
        );
        ctxt.blocks_mut()[index] = message;

        //add the carry to the next block
        if index < ctxt.blocks().len() - 1 {
            self.key
                .unchecked_add_assign(&mut ctxt.blocks_mut()[index + 1], &carry);
        }
    }

    pub fn partial_propagate_parallelized<T>(&self, ctxt: &mut T, start_index: usize)
    where
        T: IntegerRadixCiphertext,
    {
        // The fully parallelized way introduces more work
        // and so is slower for low number of blocks
        const MIN_NUM_BLOCKS: usize = 6;
        if self.is_eligible_for_parallel_carryless_add() && ctxt.blocks().len() >= MIN_NUM_BLOCKS {
            let num_blocks = ctxt.blocks().len();

            let (mut message_blocks, carry_blocks) = rayon::join(
                || {
                    ctxt.blocks()[start_index..]
                        .par_iter()
                        .map(|block| self.key.message_extract(block))
                        .collect::<Vec<_>>()
                },
                || {
                    let mut carry_blocks = Vec::with_capacity(num_blocks);
                    // No need to compute the carry of the last block, we would just throw it away
                    ctxt.blocks()[start_index..num_blocks - 1]
                        .par_iter()
                        .map(|block| self.key.carry_extract(block))
                        .collect_into_vec(&mut carry_blocks);
                    carry_blocks.insert(0, self.key.create_trivial(0));
                    carry_blocks
                },
            );

            ctxt.blocks_mut()[start_index..].swap_with_slice(&mut message_blocks);
            let carries = T::from_blocks(carry_blocks);
            self.unchecked_add_assign_parallelized(ctxt, &carries);
            self.propagate_single_carry_parallelized_low_latency(ctxt)
        } else {
            let len = ctxt.blocks().len();
            for i in start_index..len {
                self.propagate_parallelized(ctxt, i);
            }
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
    pub fn full_propagate_parallelized<T>(&self, ctxt: &mut T)
    where
        T: IntegerRadixCiphertext,
    {
        self.partial_propagate_parallelized(ctxt, 0)
    }
}
