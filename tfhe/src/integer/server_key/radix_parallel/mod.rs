mod abs;
mod add;
mod bit_extractor;
mod bitwise_op;
mod cmux;
mod comparison;
mod div_mod;
mod modulus_switch_compression;
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
pub(crate) mod sub;

mod ilog2;
#[cfg(test)]
pub(crate) mod tests_cases_unsigned;
#[cfg(test)]
pub(crate) mod tests_signed;
#[cfg(test)]
pub(crate) mod tests_unsigned;
mod vector_comparisons;

use super::ServerKey;
use crate::integer::ciphertext::IntegerRadixCiphertext;
use rayon::prelude::*;
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
    pub fn propagate_parallelized<T>(
        &self,
        ctxt: &mut T,
        index: usize,
    ) -> crate::shortint::Ciphertext
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

        carry
    }

    /// Propagates carries starting from start_index.
    ///
    /// Does nothing if start_index >= ctxt.len() or ctxt is empty
    pub fn partial_propagate_parallelized<T>(&self, ctxt: &mut T, mut start_index: usize)
    where
        T: IntegerRadixCiphertext,
    {
        if start_index >= ctxt.blocks().len() || ctxt.blocks().is_empty() {
            return;
        }

        // Extract message blocks and carry blocks from the
        // input block slice.
        // Carries Vec has one less block than message Vec
        let extract_message_and_carry_blocks = |blocks: &[crate::shortint::Ciphertext]| {
            let num_blocks = blocks.len();

            rayon::join(
                || {
                    blocks
                        .par_iter()
                        .map(|block| self.key.message_extract(block))
                        .collect::<Vec<_>>()
                },
                || {
                    let mut carry_blocks = Vec::with_capacity(num_blocks);
                    // No need to compute the carry of the last block, we would just throw it away
                    blocks[..num_blocks - 1]
                        .par_iter()
                        .map(|block| self.key.carry_extract(block))
                        .collect_into_vec(&mut carry_blocks);
                    carry_blocks
                },
            )
        };

        if self.is_eligible_for_parallel_single_carry_propagation(ctxt) {
            let highest_degree = ctxt.blocks()[start_index..]
                .iter()
                .max_by(|block_a, block_b| block_a.degree.get().cmp(&block_b.degree.get()))
                .map(|block| block.degree.get())
                .unwrap(); // We checked for emptiness earlier
            if highest_degree <= (self.key.message_modulus.0 - 1) * 2 {
                let _ = self.propagate_single_carry_parallelized_low_latency(
                    &mut ctxt.blocks_mut()[start_index..],
                );
            } else {
                // At least one of the blocks has more than one carry,
                // we need to extract message and carries, then add + propagate
                let (mut message_blocks, carry_blocks) =
                    extract_message_and_carry_blocks(&ctxt.blocks()[start_index..]);

                ctxt.blocks_mut()[start_index..].swap_with_slice(&mut message_blocks);
                for (block, carry) in ctxt.blocks_mut()[start_index + 1..]
                    .iter_mut()
                    .zip(carry_blocks.iter())
                {
                    self.key.unchecked_add_assign(block, carry);
                }
                // We can start propagation one index later as we already did the first block
                let _ = self.propagate_single_carry_parallelized_low_latency(
                    &mut ctxt.blocks_mut()[start_index + 1..],
                );
            }
        } else {
            let maybe_highest_degree = ctxt
                // We do not care about degree of 'first' block as it won't receive any carries
                .blocks()[start_index + 1..]
                .iter()
                .max_by(|block_a, block_b| block_a.degree.get().cmp(&block_b.degree.get()))
                .map(|block| block.degree.get());

            if maybe_highest_degree.is_some_and(|degree| degree > self.key.max_degree.get()) {
                // At least one of the blocks than can receive a carry, won't be able too
                // so we need to do a first 'partial' round
                let (mut message_blocks, carry_blocks) =
                    extract_message_and_carry_blocks(&ctxt.blocks()[start_index..]);
                ctxt.blocks_mut()[start_index..].swap_with_slice(&mut message_blocks);
                for (block, carry) in ctxt.blocks_mut()[start_index + 1..]
                    .iter_mut()
                    .zip(carry_blocks.iter())
                {
                    self.key.unchecked_add_assign(block, carry);
                }
                // We can start propagation one index later as we already did the first block
                start_index += 1;
            }

            let len = ctxt.blocks().len();
            // If start_index >= len, the range is considered empty
            for i in start_index..len {
                let _ = self.propagate_parallelized(ctxt, i);
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
        let Some(start_index) = ctxt
            .blocks()
            .iter()
            .position(|block| !block.carry_is_empty())
        else {
            // No block has any carries, do nothing
            return;
        };
        self.partial_propagate_parallelized(ctxt, start_index);
    }
}
