use std::ops::{Bound, Range, RangeBounds};

use crate::error::InvalidRangeError;
use crate::integer::{RadixCiphertext, ServerKey};
use crate::prelude::{CastFrom, CastInto};
use crate::shortint;

/// Normalize a rust RangeBound object into an Exclusive Range, and check that it is valid for the
/// source integer.
pub(crate) fn normalize_range<B, R>(
    range: &R,
    nb_bits: usize,
) -> Result<Range<usize>, InvalidRangeError>
where
    R: RangeBounds<B>,
    B: CastFrom<usize> + CastInto<usize> + Copy,
{
    let start = match range.start_bound() {
        Bound::Included(inc) => (*inc).cast_into(),
        Bound::Excluded(excl) => (*excl).cast_into() + 1,
        Bound::Unbounded => 0,
    };

    let end = match range.end_bound() {
        Bound::Included(inc) => (*inc).cast_into() + 1,
        Bound::Excluded(excl) => (*excl).cast_into(),
        Bound::Unbounded => nb_bits,
    };

    if end > nb_bits {
        Err(InvalidRangeError::SliceTooBig)
    } else if start > end {
        Err(InvalidRangeError::WrongOrder)
    } else {
        Ok(Range { start, end })
    }
}

/// This is the operation to extract a non-aligned block, on the clear.
/// For example, with a 2x4bits integer: |abcd|efgh|, extracting the block
/// at offset 2 will return |cdef|. This function should be used inside a LUT.
pub(in crate::integer) fn slice_oneblock_clear_unaligned(
    cur_block: u64,
    next_block: u64,
    offset: usize,
    block_size: usize,
) -> u64 {
    (cur_block >> (offset)) | ((next_block << (block_size - offset)) % (1 << block_size))
}

impl ServerKey {
    /// Extract a slice of blocks from a ciphertext.
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
    /// let msg: u64 = 225;
    /// let start_block = 1;
    /// let end_block = 2;
    ///
    /// // Encrypt the message:
    /// let ct = cks.encrypt(msg);
    ///
    /// let ct_res = sks.scalar_blockslice(&ct, start_block..end_block).unwrap();
    ///
    /// let blocksize = cks.parameters().message_modulus().0.ilog2() as u64;
    /// let start_bit = (start_block as u64) * blocksize;
    /// let end_bit = (end_block as u64) * blocksize;
    ///
    /// // Decrypt:
    /// let clear = cks.decrypt(&ct_res);
    /// assert_eq!((msg % (1 << end_bit)) >> start_bit, clear);
    /// ```
    pub fn scalar_blockslice<B, R>(
        &self,
        ctxt: &RadixCiphertext,
        range: R,
    ) -> Result<RadixCiphertext, InvalidRangeError>
    where
        R: RangeBounds<B>,
        B: CastFrom<usize> + CastInto<usize> + Copy,
    {
        let range = normalize_range(&range, ctxt.blocks.len())?;
        Ok(self.scalar_blockslice_aligned(ctxt, range.start, range.end))
    }

    /// Extract a slice of blocks from a ciphertext.
    ///
    /// The result is assigned in the input ciphertext.
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
    /// let start_block = 1;
    /// let end_block = 2;
    ///
    /// // Encrypt the message:
    /// let mut ct = cks.encrypt(msg);
    ///
    /// sks.scalar_blockslice_assign(&mut ct, start_block, end_block);
    ///
    /// let blocksize = cks.parameters().message_modulus().0.ilog2() as u64;
    /// let start_bit = (start_block as u64) * blocksize;
    /// let end_bit = (end_block as u64) * blocksize;
    ///
    /// // Decrypt:
    /// let clear = cks.decrypt(&ct);
    /// assert_eq!((msg % (1 << end_bit)) >> start_bit, clear);
    /// ```
    pub fn scalar_blockslice_assign(
        &self,
        ctxt: &mut RadixCiphertext,
        start_block: usize,
        end_block: usize,
    ) {
        *ctxt = self.scalar_blockslice_aligned(ctxt, start_block, end_block);
    }

    /// Return the unaligned remainder of a slice after all the unaligned full blocks have been
    /// extracted. This is similar to what [`slice_interblock`] does on each block except that the
    /// remainder is not a full block, so it will be truncated to `count` bits.
    pub(in crate::integer) fn bitslice_remainder_unaligned(
        &self,
        ctxt: &RadixCiphertext,
        block_idx: usize,
        offset: usize,
        count: usize,
    ) -> shortint::Ciphertext {
        let lut = self
            .key
            .generate_lookup_table_bivariate(|current_block, next_block| {
                slice_oneblock_clear_unaligned(
                    current_block,
                    next_block,
                    offset,
                    self.message_modulus().0.ilog2() as usize,
                ) % (1 << count)
            });

        self.key.apply_lookup_table_bivariate(
            &ctxt.blocks[block_idx],
            &ctxt
                .blocks
                .get(block_idx + 1)
                .cloned()
                .unwrap_or_else(|| self.key.create_trivial(0)),
            &lut,
        )
    }

    /// Returnsthe remainder of a slice after all the full blocks have been extracted. This will
    /// simply truncate the block value to `count` bits.
    pub(in crate::integer) fn bitslice_remainder(
        &self,
        ctxt: &RadixCiphertext,
        block_idx: usize,
        count: usize,
    ) -> shortint::Ciphertext {
        let lut = self.key.generate_lookup_table(|block| block % (1 << count));

        self.key.apply_lookup_table(&ctxt.blocks[block_idx], &lut)
    }

    /// Extract a slice from a ciphertext. The size of the slice is a multiple of the block
    /// size and is aligned on block boundaries, so we can simply copy blocks.
    pub(in crate::integer) fn scalar_blockslice_aligned(
        &self,
        ctxt: &RadixCiphertext,
        start_block: usize,
        end_block: usize,
    ) -> RadixCiphertext {
        let limit = end_block - start_block;

        let mut result: RadixCiphertext = self.create_trivial_zero_radix(limit);

        for (res_i, c_i) in result.blocks[..limit]
            .iter_mut()
            .zip(ctxt.blocks[start_block..].iter())
        {
            res_i.clone_from(c_i);
        }

        result
    }

    /// Extract a slice from a ciphertext. The size of the slice is a multiple of the block
    /// size but it is not aligned on block boundaries, so we need to mix block n and (n+1) toG
    /// create a new block, using the lut function `slice_oneblock_clear_unaligned`.
    fn scalar_blockslice_unaligned(
        &self,
        ctxt: &RadixCiphertext,
        start_block: usize,
        block_count: usize,
        offset: usize,
    ) -> RadixCiphertext {
        let mut blocks = Vec::new();

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

        for idx in 0..block_count {
            let block = self.key.apply_lookup_table_bivariate(
                &ctxt.blocks[idx + start_block],
                &ctxt.blocks[idx + start_block + 1],
                &lut,
            );

            blocks.push(block);
        }

        RadixCiphertext::from(blocks)
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
    ///     .unchecked_scalar_bitslice(&ct, start_bit..end_bit)
    ///     .unwrap();
    ///
    /// // Decrypt:
    /// let clear = cks.decrypt(&ct_res);
    /// assert_eq!((msg % (1 << end_bit)) >> start_bit, clear);
    /// ```
    pub fn unchecked_scalar_bitslice<B, R>(
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
            let mut sliced = self.scalar_blockslice_unaligned(
                ctxt,
                range.start / block_width,
                slice_width / block_width,
                range.start % block_width,
            );

            if slice_width % block_width != 0 {
                let last_block = self.bitslice_remainder_unaligned(
                    ctxt,
                    range.start / block_width + slice_width / block_width,
                    range.start % block_width,
                    slice_width % block_width,
                );
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
    /// sks.unchecked_scalar_bitslice_assign(&mut ct, start_bit..end_bit)
    ///     .unwrap();
    ///
    /// // Decrypt:
    /// let clear = cks.decrypt(&ct);
    /// assert_eq!((msg % (1 << end_bit)) >> start_bit, clear);
    /// ```
    pub fn unchecked_scalar_bitslice_assign<B, R>(
        &self,
        ctxt: &mut RadixCiphertext,
        range: R,
    ) -> Result<(), InvalidRangeError>
    where
        R: RangeBounds<B>,
        B: CastFrom<usize> + CastInto<usize> + Copy,
    {
        *ctxt = self.unchecked_scalar_bitslice(ctxt, range)?;
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
    /// let ct_res = sks.scalar_bitslice(&ct, start_bit..end_bit).unwrap();
    ///
    /// // Decrypt:
    /// let clear = cks.decrypt(&ct_res);
    /// assert_eq!((msg % (1 << end_bit)) >> start_bit, clear);
    /// ```
    pub fn scalar_bitslice<B, R>(
        &self,
        ctxt: &RadixCiphertext,
        range: R,
    ) -> Result<RadixCiphertext, InvalidRangeError>
    where
        R: RangeBounds<B>,
        B: CastFrom<usize> + CastInto<usize> + Copy,
    {
        if ctxt.block_carries_are_empty() {
            self.unchecked_scalar_bitslice(ctxt, range)
        } else {
            let mut ctxt = ctxt.clone();
            self.full_propagate(&mut ctxt);
            self.unchecked_scalar_bitslice(&ctxt, range)
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
    /// let ct = cks.encrypt(msg);
    ///
    /// let ct_res = sks.scalar_bitslice(&ct, start_bit..end_bit).unwrap();
    ///
    /// // Decrypt:
    /// let clear = cks.decrypt(&ct_res);
    /// assert_eq!((msg % (1 << end_bit)) >> start_bit, clear);
    /// ```
    pub fn scalar_bitslice_assign<B, R>(
        &self,
        ctxt: &mut RadixCiphertext,
        range: R,
    ) -> Result<(), InvalidRangeError>
    where
        R: RangeBounds<B>,
        B: CastFrom<usize> + CastInto<usize> + Copy,
    {
        if !ctxt.block_carries_are_empty() {
            self.full_propagate(ctxt);
        }

        self.unchecked_scalar_bitslice_assign(ctxt, range)
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
    ///     .smart_scalar_bitslice(&mut ct, start_bit..end_bit)
    ///     .unwrap();
    ///
    /// // Decrypt:
    /// let clear = cks.decrypt(&ct_res);
    /// assert_eq!((msg % (1 << end_bit)) >> start_bit, clear);
    /// ```
    pub fn smart_scalar_bitslice<B, R>(
        &self,
        ctxt: &mut RadixCiphertext,
        range: R,
    ) -> Result<RadixCiphertext, InvalidRangeError>
    where
        R: RangeBounds<B>,
        B: CastFrom<usize> + CastInto<usize> + Copy,
    {
        if !ctxt.block_carries_are_empty() {
            self.full_propagate(ctxt);
        }

        self.unchecked_scalar_bitslice(ctxt, range)
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
    pub fn smart_scalar_bitslice_assign<B, R>(
        &self,
        ctxt: &mut RadixCiphertext,
        range: R,
    ) -> Result<(), InvalidRangeError>
    where
        R: RangeBounds<B>,
        B: CastFrom<usize> + CastInto<usize> + Copy,
    {
        if !ctxt.block_carries_are_empty() {
            self.full_propagate(ctxt);
        }

        self.unchecked_scalar_bitslice_assign(ctxt, range)
    }
}
