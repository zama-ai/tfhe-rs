use std::ops::RangeBounds;

use rayon::prelude::*;

use crate::error::InvalidRangeError;
use crate::integer::server_key::radix::slice::{normalize_range, slice_oneblock_clear_unaligned};
use crate::integer::{RadixCiphertext, ServerKey};
use crate::prelude::{CastFrom, CastInto};

impl ServerKey {
    /// Extract a slice from a ciphertext. The size of the slice is a multiple of the block
    /// size but it is not aligned on block boundaries, so we need to mix block n and (n+1) to
    /// create a new block, using the lut function `slice_oneblock_clear_unaligned`.
    fn scalar_blockslice_unaligned_parallelized(
        &self,
        ctxt: &RadixCiphertext,
        start_block: usize,
        block_count: usize,
        offset: usize,
    ) -> RadixCiphertext {
        assert!(offset < (self.message_modulus().0.ilog2() as usize));
        assert!(start_block + block_count < ctxt.blocks.len());

        let mut out: RadixCiphertext = self.create_trivial_zero_radix(block_count);

        let lut = self
            .key
            .generate_lookup_table_bivariate(|current_block, next_block| {
                slice_oneblock_clear_unaligned(
                    current_block,
                    next_block,
                    offset,
                    self.message_modulus().0.ilog2() as usize,
                )
            });

        out.blocks
            .par_iter_mut()
            .enumerate()
            .for_each(|(idx, block)| {
                *block = self.key.apply_lookup_table_bivariate(
                    &ctxt.blocks[idx + start_block],
                    &ctxt.blocks[idx + start_block + 1],
                    &lut,
                );
            });

        out
    }

    /// Extract a slice of bits from a ciphertext.
    ///
    /// The result is returned as a new ciphertext. This function is more efficient
    /// if the range starts on a block boundary.
    ///
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
    /// let msg: u64 = 225;
    /// let start_bit = 3;
    /// let end_bit = 6;
    ///
    /// // Encrypt the message:
    /// let ct = cks.encrypt(msg);
    ///
    /// let ct_res = sks
    ///     .unchecked_scalar_bitslice_parallelized(&ct, start_bit..end_bit)
    ///     .unwrap();
    ///
    /// // Decrypt:
    /// let clear = cks.decrypt(&ct_res);
    /// assert_eq!((msg % (1 << end_bit)) >> start_bit, clear);
    /// ```
    pub fn unchecked_scalar_bitslice_parallelized<B, R>(
        &self,
        ctxt: &RadixCiphertext,
        range: R,
    ) -> Result<RadixCiphertext, InvalidRangeError>
    where
        R: RangeBounds<B>,
        B: CastFrom<usize> + CastInto<usize> + Copy,
    {
        let block_width = self.message_modulus().0.ilog2() as usize;
        let range = normalize_range(&range, block_width * ctxt.blocks.len())?;

        let slice_width = range.end - range.start;

        // If the starting bit is block aligned, we can do most of the slicing with block copies.
        // If it's not we must extract the bits with PBS. In either cases, we must extract the last
        // bits with a PBS if the slice size is not a multiple of the block size.
        let mut sliced = if range.start % block_width != 0 {
            let (mut sliced, maybe_last_block) = rayon::join(
                || {
                    self.scalar_blockslice_unaligned_parallelized(
                        ctxt,
                        range.start / block_width,
                        slice_width / block_width,
                        range.start % block_width,
                    )
                },
                || {
                    if slice_width % block_width != 0 {
                        Some(self.bitslice_remainder_unaligned(
                            ctxt,
                            range.start / block_width + slice_width / block_width,
                            range.start % block_width,
                            slice_width % block_width,
                        ))
                    } else {
                        None
                    }
                },
            );

            if let Some(last_block) = maybe_last_block {
                sliced.blocks.push(last_block);
            }
            sliced
        } else {
            let mut sliced = self.scalar_blockslice_aligned(
                ctxt,
                range.start / block_width,
                range.end / block_width,
            );
            if slice_width % block_width != 0 {
                let last_block = self.bitslice_remainder(
                    ctxt,
                    range.end / block_width,
                    slice_width % block_width,
                );
                sliced.blocks.push(last_block);
            }

            sliced
        };

        // Extend with trivial zeroes to return an integer of the same size as the input one.
        self.extend_radix_with_trivial_zero_blocks_msb_assign(&mut sliced, ctxt.blocks.len());
        Ok(sliced)
    }

    /// Extract a slice of bits from a ciphertext.
    ///
    /// The result is assigned to the input ciphertext. This function is more efficient
    /// if the range starts on a block boundary.
    ///
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
    /// let msg: u64 = 225;
    /// let start_bit = 3;
    /// let end_bit = 6;
    ///
    /// // Encrypt the message:
    /// let mut ct = cks.encrypt(msg);
    ///
    /// sks.unchecked_scalar_bitslice_assign_parallelized(&mut ct, start_bit..end_bit)
    ///     .unwrap();
    ///
    /// // Decrypt:
    /// let clear = cks.decrypt(&ct);
    /// assert_eq!((msg % (1 << end_bit)) >> start_bit, clear);
    /// ```
    pub fn unchecked_scalar_bitslice_assign_parallelized<B, R>(
        &self,
        ctxt: &mut RadixCiphertext,
        range: R,
    ) -> Result<(), InvalidRangeError>
    where
        R: RangeBounds<B>,
        B: CastFrom<usize> + CastInto<usize> + Copy,
    {
        *ctxt = self.unchecked_scalar_bitslice_parallelized(ctxt, range)?;
        Ok(())
    }

    /// Extract a slice of bits from a ciphertext.
    ///
    /// The result is returned as a new ciphertext. This function is more efficient
    /// if the range starts on a block boundary.
    ///
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
    /// let msg: u64 = 225;
    /// let start_bit = 3;
    /// let end_bit = 6;
    ///
    /// // Encrypt the message:
    /// let ct = cks.encrypt(msg);
    ///
    /// let ct_res = sks
    ///     .scalar_bitslice_parallelized(&ct, start_bit..end_bit)
    ///     .unwrap();
    ///
    /// // Decrypt:
    /// let clear = cks.decrypt(&ct_res);
    /// assert_eq!((msg % (1 << end_bit)) >> start_bit, clear);
    /// ```
    pub fn scalar_bitslice_parallelized<B, R>(
        &self,
        ctxt: &RadixCiphertext,
        range: R,
    ) -> Result<RadixCiphertext, InvalidRangeError>
    where
        R: RangeBounds<B>,
        B: CastFrom<usize> + CastInto<usize> + Copy,
    {
        if ctxt.block_carries_are_empty() {
            self.unchecked_scalar_bitslice_parallelized(ctxt, range)
        } else {
            let mut ctxt = ctxt.clone();
            self.full_propagate_parallelized(&mut ctxt);
            self.unchecked_scalar_bitslice_parallelized(&ctxt, range)
        }
    }

    /// Extract a slice of bits from a ciphertext.
    ///
    /// The result is assigned to the input ciphertext. This function is more efficient
    /// if the range starts on a block boundary.
    ///
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
    /// let msg: u64 = 225;
    /// let start_bit = 3;
    /// let end_bit = 6;
    ///
    /// // Encrypt the message:
    /// let mut ct = cks.encrypt(msg);
    ///
    /// sks.scalar_bitslice_assign_parallelized(&mut ct, start_bit..end_bit)
    ///     .unwrap();
    ///
    /// // Decrypt:
    /// let clear = cks.decrypt(&ct);
    /// assert_eq!((msg % (1 << end_bit)) >> start_bit, clear);
    /// ```
    pub fn scalar_bitslice_assign_parallelized<B, R>(
        &self,
        ctxt: &mut RadixCiphertext,
        range: R,
    ) -> Result<(), InvalidRangeError>
    where
        R: RangeBounds<B>,
        B: CastFrom<usize> + CastInto<usize> + Copy,
    {
        if !ctxt.block_carries_are_empty() {
            self.full_propagate_parallelized(ctxt);
        }

        self.unchecked_scalar_bitslice_assign_parallelized(ctxt, range)
    }

    /// Extract a slice of bits from a ciphertext.
    ///
    /// The result is returned as a new ciphertext. This function is more efficient
    /// if the range starts on a block boundary.
    ///
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
    /// let msg: u64 = 225;
    /// let start_bit = 3;
    /// let end_bit = 6;
    ///
    /// // Encrypt the message:
    /// let mut ct = cks.encrypt(msg);
    ///
    /// let ct_res = sks
    ///     .smart_scalar_bitslice_parallelized(&mut ct, start_bit..end_bit)
    ///     .unwrap();
    ///
    /// // Decrypt:
    /// let clear = cks.decrypt(&ct_res);
    /// assert_eq!((msg % (1 << end_bit)) >> start_bit, clear);
    /// ```
    pub fn smart_scalar_bitslice_parallelized<B, R>(
        &self,
        ctxt: &mut RadixCiphertext,
        range: R,
    ) -> Result<RadixCiphertext, InvalidRangeError>
    where
        R: RangeBounds<B>,
        B: CastFrom<usize> + CastInto<usize> + Copy,
    {
        if !ctxt.block_carries_are_empty() {
            self.full_propagate_parallelized(ctxt);
        }

        self.unchecked_scalar_bitslice_parallelized(ctxt, range)
    }

    /// Extract a slice of bits from a ciphertext.
    ///
    /// The result is assigned to the input ciphertext. This function is more efficient
    /// if the range starts on a block boundary.
    ///
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
    /// let msg: u64 = 225;
    /// let start_bit = 3;
    /// let end_bit = 6;
    ///
    /// // Encrypt the message:
    /// let mut ct = cks.encrypt(msg);
    ///
    /// sks.smart_scalar_bitslice_assign(&mut ct, start_bit..end_bit)
    ///     .unwrap();
    ///
    /// // Decrypt:
    /// let clear = cks.decrypt(&ct);
    /// assert_eq!((msg % (1 << end_bit)) >> start_bit, clear);
    /// ```
    pub fn smart_scalar_bitslice_assign_parallelized<B, R>(
        &self,
        ctxt: &mut RadixCiphertext,
        range: R,
    ) -> Result<(), InvalidRangeError>
    where
        R: RangeBounds<B>,
        B: CastFrom<usize> + CastInto<usize> + Copy,
    {
        if !ctxt.block_carries_are_empty() {
            self.full_propagate_parallelized(ctxt);
        }

        self.unchecked_scalar_bitslice_assign_parallelized(ctxt, range)
    }
}
