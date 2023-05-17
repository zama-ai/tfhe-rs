/// BitBlockDecomposer
///
/// This struct allows to decompose the bytes of values of any type
/// into sub blocks with the desired number of bits.
///
/// This will return None when all bytes of the input value
/// have been decomposed.
pub struct BitBlockDecomposer<T> {
    byte_iterator: T,

    // Buffer where we will copy bytes that are
    // fetched from the source
    block_buffer: u64,
    // Used to track when we need to re-fetched
    // bytes from the byte_iterator into the buffer
    num_valid_bits: u32,

    bits_per_block: u8,
    bit_mask: u64,
}

impl<'a> BitBlockDecomposer<LittleEndianByteIter<'a>> {
    pub fn new_little_endian<T: bytemuck::NoUninit>(value: &'a T, bits_per_block: u8) -> Self {
        let a = LittleEndianByteIter::new(value);
        Self::with_iter(a, bits_per_block)
    }
}

impl<T> BitBlockDecomposer<T>
where
    T: Iterator<Item = u8>,
{
    pub fn with_iter(byte_iterator: T, bits_per_block: u8) -> Self {
        assert!(bits_per_block < 64);
        let bit_mask = (1 << bits_per_block as u64) - 1;
        Self {
            byte_iterator,
            block_buffer: 0,
            num_valid_bits: 0,
            bits_per_block,
            bit_mask,
        }
    }

    // Fetch bytes from the source
    fn fetch_bytes(&mut self) -> (u64, u32) {
        let num_bytes_to_fetch = (self.bits_per_block as u32 / u8::BITS) + 1;

        let mut output = 0;
        let mut byte_count = 0u32;
        while byte_count < num_bytes_to_fetch {
            let Some(byte) = self.byte_iterator.next() else {
                break;
            };
            output <<= u8::BITS;
            output += byte as u64;
            byte_count += 1;
        }

        (output, byte_count)
    }
}

impl<T> Iterator for BitBlockDecomposer<T>
where
    T: Iterator<Item = u8>,
{
    type Item = u64;

    fn next(&mut self) -> Option<Self::Item> {
        if self.num_valid_bits < self.bits_per_block as u32 {
            let (fetched, byte_count) = self.fetch_bytes();
            if byte_count == 0 && self.num_valid_bits == 0 {
                return None;
            } else if byte_count == 0 && self.num_valid_bits != 0 {
                // No more bytes to fetch from the source,
                // however, we still have some data that can be returned
                // before considering ourselves completely done
                let diff = self.bits_per_block as u32 - self.num_valid_bits;
                let ret = self.block_buffer & (self.bit_mask >> diff);
                self.block_buffer >>= self.num_valid_bits as u64;
                self.num_valid_bits = 0;
                return Some(ret);
            } else {
                self.block_buffer += fetched << self.num_valid_bits;
                self.num_valid_bits += byte_count * u8::BITS;
            }
        }

        let ret = self.block_buffer & self.bit_mask;
        self.block_buffer >>= self.bits_per_block as u64;
        self.num_valid_bits -= self.bits_per_block as u32;

        Some(ret)
    }
}

/// BitBlockRecomposer
///
/// This struct allows to recompose the bytes of values of any type
/// from sub blocks (generally acquired by using BitBlockDecomposer).
///
/// This will return None when all bytes of the output value
/// have been recomposed.
pub struct BitBlockRecomposer<T> {
    dest: T,

    // Buffer where we recompose bytes
    // from input blocks before writing into
    // the dest
    block_buffer: u64,
    // Used to track when we can write bytes
    // from the block_buffer into the dest
    num_valid_bits: u32,

    bits_per_blocks: u8,
    bit_mask: u64,
}

impl<'a> BitBlockRecomposer<LittleEndianByteIterMut<'a>> {
    pub fn new_little_endian<T: bytemuck::Pod>(value: &'a mut T, bits_per_blocks: u8) -> Self {
        let a = LittleEndianByteIterMut::new(value);
        Self::with_iter(a, bits_per_blocks)
    }
}

impl<'a, T> BitBlockRecomposer<T>
where
    T: Iterator<Item = &'a mut u8>,
{
    pub fn with_iter(dest: T, bits_per_blocks: u8) -> Self {
        assert!(bits_per_blocks < 64);
        let bit_mask = (1 << bits_per_blocks as u64) - 1;
        Self {
            dest,
            block_buffer: 0,
            num_valid_bits: 0,
            bits_per_blocks,
            bit_mask,
        }
    }

    fn send_byte(&mut self, byte: u8) -> Option<()> {
        let output_ref = self.dest.next()?;
        *output_ref = byte;
        Some(())
    }

    /// Takes into acocunt the block value without masking it,
    /// meaning it will also take into account bits that are
    /// above the expected number of bits per block.
    ///
    /// Useful to handle carry propagation while recomposing
    pub fn write_block_unmasked(&mut self, mut block_value: u64) -> Option<()> {
        block_value <<= self.num_valid_bits;
        self.block_buffer += block_value;
        self.num_valid_bits += self.bits_per_blocks as u32;

        if self.num_valid_bits >= u8::BITS {
            let byte = (self.block_buffer & u64::from(u8::MAX)) as u8;
            self.send_byte(byte)?;
            self.block_buffer >>= u8::BITS;
            self.num_valid_bits -= u8::BITS;
        }
        Some(())
    }

    /// Takes into account only the bits that are
    /// in the range of bits per block, others are ingnored
    ///
    /// Useful when you need to make sure any potention
    /// carry in block_value are discarded
    pub fn write_block(&mut self, block_value: u64) -> Option<()> {
        self.write_block_unmasked(block_value & self.bit_mask)
    }

    // flushes the last valid bits into the destination
    pub fn flush(&mut self) -> Option<()> {
        debug_assert!(self.num_valid_bits < u8::BITS);
        let mask = (1 << self.num_valid_bits) - 1;
        let byte = (self.block_buffer & mask) as u8;
        self.send_byte(byte)
    }
}

/// Iterator over the bytes of any T in Little Endian Order
///
/// This iterator allows to iterate over the bytes of
/// any type, in the Little Endian order
#[derive(Debug)]
pub struct LittleEndianByteIter<'a> {
    current_ptr: *const u8,
    end_ptr: *const u8,
    _marker: std::marker::PhantomData<&'a ()>,
}

impl<'a> LittleEndianByteIter<'a> {
    pub fn new<T: bytemuck::NoUninit>(value: &'a T) -> Self {
        let bytes = bytemuck::bytes_of(value);
        let std::ops::Range { start, end } = bytes.as_ptr_range();
        #[cfg(target_endian = "little")]
        {
            // the end ptr we got from the range is one past the end
            // which is what we want
            Self {
                current_ptr: start,
                end_ptr: end,
                _marker: Default::default(),
            }
        }
        #[cfg(target_endian = "big")]
        {
            // In Big endian, we swap the end and start,
            // and go back one  byte (as end it one past the end
            // and we want it to point to actual last byte
            // and start which becomes our end, has to be one before the beginning
            let current_ptr = end.wrapping_sub(1);
            let end_ptr = start.wrapping_sub(1);

            Self {
                current_ptr,
                end_ptr,
                _marker: Default::default(),
            }
        }
    }

    fn advance(&mut self) {
        #[cfg(target_endian = "little")]
        {
            self.current_ptr = self.current_ptr.wrapping_add(1);
        }
        #[cfg(target_endian = "big")]
        {
            self.current_ptr = self.current_ptr.wrapping_sub(1);
        }
    }

    fn is_current_ptr_valid(&self) -> bool {
        #[cfg(target_endian = "little")]
        {
            self.current_ptr < self.end_ptr
        }
        #[cfg(target_endian = "big")]
        {
            self.current_ptr > self.end_ptr
        }
    }
}

impl<'a> Iterator for LittleEndianByteIter<'a> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if self.is_current_ptr_valid() {
            unsafe {
                // SAFETY
                // The constructor guarantees current_ptr is initialized
                // within the allocated object bounds
                //
                // And end_ptr is guaranteed to be one byte past the
                // end / beginning.
                //
                // So the check done above guarantees that current_ptr is
                // still within the bounds of the allocated object
                // and so is safe to deref
                let value = *self.current_ptr;
                self.advance();
                Some(value)
            }
        } else {
            None
        }
    }
}

impl<'a> std::iter::FusedIterator for LittleEndianByteIter<'a> {}

/// Iterator over the mutable bytes of any T in Little Endian Order
///
/// This iterator allows to iterate over mutable ref to the bytes of
/// any type, in the Little Endian order
#[derive(Debug)]
pub struct LittleEndianByteIterMut<'a> {
    current_ptr: *mut u8,
    end_ptr: *mut u8,
    _marker: std::marker::PhantomData<&'a mut ()>,
}

impl<'a> LittleEndianByteIterMut<'a> {
    pub fn new<T: bytemuck::Pod>(value: &'a mut T) -> Self {
        // SAFETY
        //
        // The bytemuck::Pod trait bounds gives us the needed
        // safety guarantees. e.g, T is guaranteed to have
        // all bits pattern valid
        unsafe { Self::new_unchecked(value) }
    }

    /// SAFETY
    ///
    /// Prefer the safe `Self::new`, which won't compile
    /// if your type T is not valid to use here.
    ///
    /// You must make sure the value of bytes you are going
    /// to modify do not violate any condition of the underlying type.
    ///
    /// In other words, with this it is possible set the bytes
    /// to value / bit patterns that are not valid for the type T.
    ///
    ///
    /// For example, with this is it is possible to set an already
    /// constructed std::ptr::NonNull (so guarantees ptr is not null)
    /// to null, violating its invariant.
    ///
    /// ```ignore
    /// # fn main() {
    /// let mut a = 32i32;
    /// {
    ///     let ptr = &mut a as *mut i32;
    ///     assert!(!ptr.is_null());
    ///     let mut non_null_ptr = std::ptr::NonNull::new(ptr).unwrap();
    ///
    ///     let iter = unsafe { LittleEndianByteIterMut::new_unchecked(&mut non_null_ptr) };
    ///
    ///     for byte in iter {
    ///         *byte = 0;
    ///     }
    ///
    ///     // We effectily made the non null ptr null
    ///     let ptr = non_null_ptr.as_ptr();
    ///     assert!(ptr.is_null());
    ///     assert!(std::ptr::NonNull::new(ptr).is_none());
    /// }
    /// # }
    /// ```
    pub unsafe fn new_unchecked<T>(value: &'a mut T) -> Self {
        let ptr = value as *mut T as *mut u8;
        let num_bytes = std::mem::size_of::<T>();
        #[cfg(target_endian = "little")]
        {
            let current_ptr = ptr;
            let end_ptr = ptr.wrapping_add(num_bytes);

            Self {
                current_ptr,
                end_ptr,
                _marker: Default::default(),
            }
        }
        #[cfg(target_endian = "big")]
        {
            let current_ptr = ptr.wrapping_add(num_bytes - 1);
            let end_ptr = ptr.wrapping_sub(1);

            Self {
                current_ptr,
                end_ptr,
                _marker: Default::default(),
            }
        }
    }

    fn advance(&mut self) {
        #[cfg(target_endian = "little")]
        {
            self.current_ptr = self.current_ptr.wrapping_add(1);
        }
        #[cfg(target_endian = "big")]
        {
            self.current_ptr = self.current_ptr.wrapping_sub(1);
        }
    }

    fn is_current_ptr_valid(&self) -> bool {
        #[cfg(target_endian = "little")]
        {
            self.current_ptr < self.end_ptr
        }
        #[cfg(target_endian = "big")]
        {
            self.current_ptr > self.end_ptr
        }
    }
}

impl<'a> Iterator for LittleEndianByteIterMut<'a> {
    type Item = &'a mut u8;

    fn next(&mut self) -> Option<Self::Item> {
        if self.is_current_ptr_valid() {
            unsafe {
                // SAFETY
                // The constructor guarantees current_ptr is initialized
                // within the allocated object bounds
                //
                // And end_ptr is guaranteed to be one byte past the
                // end / beginning.
                //
                // So the check done above guarantees that current_ptr is
                // still within the bounds of the allocated object
                // and so is safe to deref
                let value = &mut *self.current_ptr;
                self.advance();
                Some(value)
            }
        } else {
            None
        }
    }
}

impl<'a> std::iter::FusedIterator for LittleEndianByteIterMut<'a> {}

#[cfg(test)]
mod tests {

    use super::*;
    #[test]
    fn test_little_endian_byte_iter() {
        let value = u16::MAX as u32;

        let expected = value.to_le_bytes();
        let got = LittleEndianByteIter::new(&value).collect::<Vec<_>>();
        assert_eq!(got.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_little_endian_byte_iter_mut() {
        let mut value = 0u32;
        let num_bytes = std::mem::size_of::<u32>();

        LittleEndianByteIterMut::new(&mut value)
            .skip(num_bytes / 2)
            .for_each(|byte| *byte = u8::MAX);

        let expected = (u16::MAX as u32) << 16;

        assert_eq!(value, expected);
    }

    #[test]
    fn test_bit_block_decomposer() {
        let value = u16::MAX as u32;
        let bits_per_block = 2;
        let blocks =
            BitBlockDecomposer::new_little_endian(&value, bits_per_block as u8).collect::<Vec<_>>();
        let expected_blocks = vec![3, 3, 3, 3, 3, 3, 3, 3, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(expected_blocks, blocks);
    }

    #[test]
    fn test_bit_block_decomposer_recomposer_carry_handling_in_between() {
        let value = u16::MAX as u32;
        let bits_per_block = 2;
        let mut blocks =
            BitBlockDecomposer::new_little_endian(&value, bits_per_block).collect::<Vec<_>>();
        let expected_blocks = vec![3, 3, 3, 3, 3, 3, 3, 3, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(expected_blocks, blocks);

        // Now this block, which is not the last will have a 'carry'
        blocks[0] += 2;

        let mut output = 0u32;
        let mut recomposer = BitBlockRecomposer::new_little_endian(&mut output, bits_per_block);
        for block in blocks {
            recomposer.write_block_unmasked(block);
        }

        assert_eq!(output, value + 2);
    }

    #[test]
    fn test_bit_block_decomposer_zero_sized_type() {
        let value = std::marker::PhantomData::<u8>::default();
        assert_eq!(std::mem::size_of_val(&value), 0);

        let mut iter = LittleEndianByteIter::new(&value);
        assert!(iter.next().is_none()); // It must not be possible to even to 1 iter

        let bits_per_block = 2;
        let blocks =
            BitBlockDecomposer::new_little_endian(&value, bits_per_block).collect::<Vec<_>>();
        let expected_blocks: Vec<u64> = vec![];
        assert_eq!(expected_blocks, blocks);
    }

    #[test]
    fn test_bit_block_decomposer_round_trip_unsigned() {
        for i in 0..u32::BITS {
            let value = (u16::MAX as u32).rotate_left(i);
            let bits_per_block = 2;
            let blocks = BitBlockDecomposer::new_little_endian(&value, bits_per_block as u8)
                .collect::<Vec<_>>();

            let mut value_2 = 0u32;
            let mut recomposer =
                BitBlockRecomposer::new_little_endian(&mut value_2, bits_per_block as u8);
            for block in blocks {
                recomposer.write_block(block).unwrap();
            }
            assert_eq!(value_2, value);
        }
    }

    #[test]
    fn test_bit_block_decomposer_round_trip_signed() {
        for i in 0..i32::BITS {
            let value = (i16::MAX as i32).rotate_left(i);
            let bits_per_block = 2;
            let blocks = BitBlockDecomposer::new_little_endian(&value, bits_per_block as u8)
                .collect::<Vec<_>>();

            let mut value_2 = 0i32;
            let mut recomposer =
                BitBlockRecomposer::new_little_endian(&mut value_2, bits_per_block as u8);
            for block in blocks {
                recomposer.write_block(block).unwrap();
            }
            assert_eq!(value_2, value);
        }
    }

    /// Test that when the bits per block is not a multiple of the number of bytes
    /// we can decompose and recompose
    #[test]
    fn test_bit_block_decomposer_round_trip_non_multiple_bits_per_block() {
        for i in 0..u32::BITS {
            let value = (u16::MAX as u32).rotate_left(i);
            let bits_per_block = 3;
            let blocks = BitBlockDecomposer::new_little_endian(&value, bits_per_block as u8)
                .collect::<Vec<_>>();

            let mut value_2 = 0u32;
            let mut recomposer =
                BitBlockRecomposer::new_little_endian(&mut value_2, bits_per_block as u8);
            for block in blocks {
                recomposer.write_block(block).unwrap();
            }
            assert_eq!(value_2, value);
        }
    }
}
