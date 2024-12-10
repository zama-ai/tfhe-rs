use crate::integer::{BooleanBlock, IntegerRadixCiphertext, ServerKey};

impl ServerKey {
    /// Returns an encryption of true if the value is even
    ///
    /// ct is not required to have clean carries
    pub fn unchecked_is_even<T>(&self, ct: &T) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
    {
        ct.blocks().first().map_or_else(
            || {
                // Interpret empty as being 0, which is even
                self.create_trivial_boolean_block(true)
            },
            |first_block| {
                let lut = self
                    .key
                    .generate_lookup_table(|block| u64::from((block & 1) == 0));
                let result = self.key.apply_lookup_table(first_block, &lut);
                BooleanBlock::new_unchecked(result)
            },
        )
    }

    /// Returns an encryption of true if the value is odd
    //
    /// ct is not required to have clean carries
    pub fn unchecked_is_odd<T>(&self, ct: &T) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
    {
        ct.blocks().first().map_or_else(
            || {
                // Interpret empty as being 0, which is not odd
                self.create_trivial_boolean_block(false)
            },
            |first_block| {
                let result = self.key.unchecked_scalar_bitand(first_block, 1);
                BooleanBlock::new_unchecked(result)
            },
        )
    }

    /// Returns an encryption of true if the value is even
    #[allow(unused_mut)]
    pub fn smart_is_even_parallelized<T>(&self, ct: &mut T) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
    {
        self.unchecked_is_even(ct)
    }

    /// Returns an encryption of true if the value is odd
    #[allow(unused_mut)]
    pub fn smart_is_odd_parallelized<T>(&self, ct: &mut T) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
    {
        self.unchecked_is_odd(ct)
    }

    /// Returns an encryption of true if the value is even
    pub fn is_even_parallelized<T>(&self, ct: &T) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
    {
        // Since the check happens on the first bit of the first block
        // no need to worry about carries
        self.unchecked_is_even(ct)
    }

    /// Returns an encryption of true if the value is odd
    pub fn is_odd_parallelized<T>(&self, ct: &T) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
    {
        // Since the check happens on the first bit of the first block
        // no need to worry about carries
        self.unchecked_is_odd(ct)
    }
}
