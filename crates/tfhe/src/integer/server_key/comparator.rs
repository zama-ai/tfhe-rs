use super::ServerKey;
use crate::integer::ciphertext::boolean_value::BooleanBlock;
use crate::integer::ciphertext::IntegerRadixCiphertext;
use crate::shortint::ciphertext::Degree;
use crate::shortint::server_key::LookupTableOwned;
use crate::shortint::Ciphertext;

/// Used for compare_blocks_with_zero
#[derive(Clone, Copy)]
pub(crate) enum ZeroComparisonType {
    // We want to compare with zeros for equality (==)
    Equality,
    // We want to compare with zeros for difference (!=)
    Difference,
}

/// Simple enum to select whether we are looking for the min or the max
#[derive(Clone, Copy)]
enum MinMaxSelector {
    Max,
    Min,
}

/// This function encodes how to reduce the ordering of two blocks.
///
/// It is used to generate the necessary lookup table.
///
/// `x` is actually two ordering values packed
/// where in the first 2 lsb bits there is the ordering value of the less significant block,
/// and the 2 msb bits of x contains the ordering of the more significant block.
fn reduce_two_orderings_function(x: u64) -> u64 {
    let msb = (x >> 2) & 3;
    let lsb = x & 3;

    if msb == Comparator::IS_EQUAL {
        lsb
    } else {
        msb
    }
}

/// struct to compare integers
///
/// This struct keeps in memory the LUTs that are used
/// during the comparisons and min/max algorithms
pub struct Comparator<'a> {
    pub(crate) server_key: &'a ServerKey,
    // lut to get the sign of (a - b), used as the backbone of comparisons
    sign_lut: LookupTableOwned,
    // lut used to reduce 2 comparison blocks into 1
    comparison_reduction_lut: LookupTableOwned,
    comparison_result_to_offset_lut: LookupTableOwned,
    lhs_lut: LookupTableOwned,
    rhs_lut: LookupTableOwned,
}

impl<'a> Comparator<'a> {
    pub(crate) const IS_INFERIOR: u64 = 0;
    const IS_EQUAL: u64 = 1;
    pub(crate) const IS_SUPERIOR: u64 = 2;

    /// Creates a new Comparator for the given ServerKey
    ///
    /// # Panics
    ///
    /// panics if the message space + carry space is inferior to 4 bits
    pub fn new(server_key: &'a ServerKey) -> Self {
        assert!(
            server_key.key.message_modulus.0 * server_key.key.carry_modulus.0 >= 16,
            "At least 4 bits of space (message + carry) are required to be able to do comparisons"
        );

        let message_modulus = server_key.key.message_modulus.0;
        let sign_lut = server_key.key.generate_lookup_table(|x| u64::from(x != 0));

        let comparison_reduction_lut = server_key
            .key
            .generate_lookup_table(reduce_two_orderings_function);

        let comparison_result_to_offset_lut = server_key.key.generate_lookup_table(|sign| {
            if sign == Self::IS_INFERIOR {
                message_modulus
            } else {
                0
            }
        });

        let lhs_lut = server_key
            .key
            .generate_lookup_table(|x| if x < message_modulus { x } else { 0 });

        let rhs_lut = server_key
            .key
            .generate_lookup_table(|x| x.saturating_sub(message_modulus));

        Self {
            server_key,
            sign_lut,
            comparison_reduction_lut,
            comparison_result_to_offset_lut,
            lhs_lut,
            rhs_lut,
        }
    }

    /// This function is used to compare two blocks
    /// of two signed radix ciphertext which hold the 'sign' bit
    /// (so the two most significant blocks).
    ///
    /// As for the blocks which holds the sign bit, the comparison
    /// is different than for regular blocks.
    fn compare_blocks_with_sign_bit(
        &self,
        lhs_block: &crate::shortint::Ciphertext,
        rhs_block: &crate::shortint::Ciphertext,
    ) -> crate::shortint::Ciphertext {
        let sign_bit_pos = self.server_key.key.message_modulus.0.ilog2() - 1;
        let lut = self.server_key.key.generate_lookup_table_bivariate(|x, y| {
            let x_sign_bit = x >> sign_bit_pos;
            let y_sign_bit = y >> sign_bit_pos;
            // The block that has its sign bit set is going
            // to be ordered as 'greater' by the cmp fn.
            // However, we are dealing with signed number,
            // so in reality, it is the smaller of the two.
            // i.e the cmp result is inversed
            if x_sign_bit == y_sign_bit {
                // Both have either sign bit set or unset,
                // cmp will give correct result
                match x.cmp(&y) {
                    std::cmp::Ordering::Less => Self::IS_INFERIOR,
                    std::cmp::Ordering::Equal => Self::IS_EQUAL,
                    std::cmp::Ordering::Greater => Self::IS_SUPERIOR,
                }
            } else {
                match x.cmp(&y) {
                    std::cmp::Ordering::Less => Self::IS_SUPERIOR,
                    std::cmp::Ordering::Equal => Self::IS_EQUAL,
                    std::cmp::Ordering::Greater => Self::IS_INFERIOR,
                }
            }
        });

        self.server_key
            .key
            .unchecked_apply_lookup_table_bivariate(lhs_block, rhs_block, &lut)
    }

    /// Takes a chunk of 2 ciphertexts and packs them together in a new ciphertext
    ///
    /// The first element of the chunk are the low bits, the second are the high bits
    ///
    /// This requires the block parameters to have enough room for two ciphertexts,
    /// so at least as many carry modulus as the message modulus
    ///
    /// Expects the carry buffer to be empty
    fn pack_block_chunk(
        &self,
        chunk: &[crate::shortint::Ciphertext],
    ) -> crate::shortint::Ciphertext {
        self.server_key.pack_block_chunk(chunk)
    }

    // lhs will be assigned
    // - 0 if lhs < rhs
    // - 1 if lhs == rhs
    // - 2 if lhs > rhs
    fn compare_block_assign(
        &self,
        lhs: &mut crate::shortint::Ciphertext,
        rhs: &crate::shortint::Ciphertext,
    ) {
        // When rhs > lhs, the subtraction will overflow, and the bit of padding will be set to 1
        // meaning that the output of the pbs will be the negative (modulo message space)
        //
        // Example:
        // lhs: 1, rhs: 3, message modulus: 4, carry modulus 4
        // lhs - rhs = -2 % (4 * 4) = 14 = 1|1110 (padding_bit|b4b3b2b1)
        // Since there was an overflow the bit of padding is 1 and not 0.
        // When applying the LUT for an input value of 14 we would expect 1,
        // but since the bit of padding is 1, we will get -1 modulus our message space,
        // so (-1) % (4 * 4) = 15 = 1|1111
        // We then add one and get 0 = 0|0000

        // Here we need the true lwe sub, not the one that comes from shortint.
        crate::core_crypto::algorithms::lwe_ciphertext_sub_assign(&mut lhs.ct, &rhs.ct);
        lhs.set_noise_level(
            lhs.noise_level() + rhs.noise_level(),
            self.server_key.key.max_noise_level,
        );
        self.server_key
            .key
            .apply_lookup_table_assign(lhs, &self.sign_lut);

        // Here Lhs can have the following values: (-1) % (message modulus * carry modulus), 0, 1
        // So the output values after the addition will be: 0, 1, 2
        self.server_key.key.unchecked_scalar_add_assign(lhs, 1);
    }

    fn reduce_two_sign_blocks_assign(
        &self,
        msb_sign: &mut crate::shortint::Ciphertext,
        lsb_sign: &crate::shortint::Ciphertext,
    ) {
        // We don't use pack_block_assign as the offset '4' does not depend on params
        self.server_key.key.unchecked_scalar_mul_assign(msb_sign, 4);
        self.server_key.key.unchecked_add_assign(msb_sign, lsb_sign);

        self.server_key
            .key
            .apply_lookup_table_assign(msb_sign, &self.comparison_reduction_lut);
    }

    /// Reduces a vec containing shortint blocks that encrypts a sign
    /// (inferior, equal, superior) to one single shortint block containing the
    /// final sign
    fn reduce_signs<F>(
        &self,
        mut sign_blocks: Vec<Ciphertext>,
        sign_result_handler_fn: F,
    ) -> Ciphertext
    where
        F: Fn(u64) -> u64,
    {
        while sign_blocks.len() > 2 {
            let mut sign_blocks_2: Vec<_> = sign_blocks
                .chunks_exact(2)
                .map(|chunk| {
                    let (low, high) = (&chunk[0], &chunk[1]);
                    let mut high = high.clone();
                    self.reduce_two_sign_blocks_assign(&mut high, low);
                    high
                })
                .collect();

            if (sign_blocks.len() % 2) == 1 {
                sign_blocks_2.push(sign_blocks[sign_blocks.len() - 1].clone());
            }

            std::mem::swap(&mut sign_blocks_2, &mut sign_blocks);
        }

        if sign_blocks.len() == 2 {
            let final_lut = self.server_key.key.generate_lookup_table(|x| {
                let final_sign = reduce_two_orderings_function(x);
                sign_result_handler_fn(final_sign)
            });
            // We don't use pack_block_assign as the offset '4' does not depend on params
            let mut result = self.server_key.key.unchecked_scalar_mul(&sign_blocks[1], 4);
            self.server_key
                .key
                .unchecked_add_assign(&mut result, &sign_blocks[0]);
            self.server_key
                .key
                .apply_lookup_table_assign(&mut result, &final_lut);
            result
        } else {
            let final_lut = self.server_key.key.generate_lookup_table(|x| {
                // sign blocks have values in the set {0, 1, 2}
                // here we force apply that modulus explicitly
                // so that generate_lookup_table has the correct
                // degree estimation
                let final_sign = x % 3;
                sign_result_handler_fn(final_sign)
            });
            self.server_key
                .key
                .apply_lookup_table(&sign_blocks[0], &final_lut)
        }
    }

    /// returns:
    ///
    /// - 0 if lhs < rhs
    /// - 1 if lhs == rhs
    /// - 2 if lhs > rhs
    ///
    /// Expects the carry buffers to be empty
    ///
    /// Requires that the RadixCiphertext block have 4 bits minimum (carry + message)
    fn unchecked_compare<T, F>(
        &self,
        lhs: &T,
        rhs: &T,
        sign_result_handler_fn: F,
    ) -> crate::shortint::Ciphertext
    where
        T: IntegerRadixCiphertext,
        F: Fn(u64) -> u64,
    {
        assert_eq!(lhs.blocks().len(), rhs.blocks().len());

        // false positive as compare_blocks does not mean the same in both branches
        #[allow(clippy::branches_sharing_code)]
        let compare_blocks_fn = if lhs.blocks()[0].carry_modulus.0
            < lhs.blocks()[0].message_modulus.0
        {
            fn compare_blocks(
                comparator: &Comparator,
                lhs_blocks: &[crate::shortint::Ciphertext],
                rhs_blocks: &[crate::shortint::Ciphertext],
                out_comparisons: &mut Vec<crate::shortint::Ciphertext>,
            ) {
                out_comparisons.reserve(lhs_blocks.len());
                for i in 0..lhs_blocks.len() {
                    let mut lhs = lhs_blocks[i].clone();
                    let rhs = &rhs_blocks[i];

                    comparator.compare_block_assign(&mut lhs, rhs);
                    out_comparisons.push(lhs);
                }
            }
            compare_blocks
        } else {
            fn compare_blocks(
                comparator: &Comparator,
                lhs_blocks: &[crate::shortint::Ciphertext],
                rhs_blocks: &[crate::shortint::Ciphertext],
                out_comparisons: &mut Vec<crate::shortint::Ciphertext>,
            ) {
                let identity = comparator.server_key.key.generate_lookup_table(|x| x);
                let mut lhs_chunks_iter = lhs_blocks.chunks_exact(2);
                let mut rhs_chunks_iter = rhs_blocks.chunks_exact(2);
                out_comparisons.reserve(lhs_chunks_iter.len() + lhs_chunks_iter.remainder().len());

                for (lhs_chunk, rhs_chunk) in lhs_chunks_iter.by_ref().zip(rhs_chunks_iter.by_ref())
                {
                    let mut packed_lhs = comparator.pack_block_chunk(lhs_chunk);
                    let mut packed_rhs = comparator.pack_block_chunk(rhs_chunk);
                    comparator
                        .server_key
                        .key
                        .apply_lookup_table_assign(&mut packed_lhs, &identity);
                    comparator
                        .server_key
                        .key
                        .apply_lookup_table_assign(&mut packed_rhs, &identity);
                    comparator.compare_block_assign(&mut packed_lhs, &packed_rhs);
                    out_comparisons.push(packed_lhs);
                }

                if let ([last_lhs_block], [last_rhs_block]) =
                    (lhs_chunks_iter.remainder(), rhs_chunks_iter.remainder())
                {
                    let mut last_lhs_block = last_lhs_block.clone();
                    comparator
                        .server_key
                        .key
                        .apply_lookup_table_assign(&mut last_lhs_block, &identity);
                    comparator.compare_block_assign(&mut last_lhs_block, last_rhs_block);
                    out_comparisons.push(last_lhs_block);
                }
            }

            compare_blocks
        };

        let mut comparisons = Vec::new();
        if T::IS_SIGNED {
            let (lhs_last_block, lhs_ls_blocks) = lhs.blocks().split_last().unwrap();
            let (rhs_last_block, rhs_ls_blocks) = rhs.blocks().split_last().unwrap();
            compare_blocks_fn(self, lhs_ls_blocks, rhs_ls_blocks, &mut comparisons);
            let last_block_cmp = self.compare_blocks_with_sign_bit(lhs_last_block, rhs_last_block);

            comparisons.push(last_block_cmp);
        } else {
            compare_blocks_fn(self, lhs.blocks(), rhs.blocks(), &mut comparisons);
        }

        self.reduce_signs(comparisons, sign_result_handler_fn)
    }

    fn smart_compare<T, F>(
        &self,
        lhs: &mut T,
        rhs: &mut T,
        sign_result_handler_fn: F,
    ) -> crate::shortint::Ciphertext
    where
        T: IntegerRadixCiphertext,
        F: Fn(u64) -> u64,
    {
        if !lhs.block_carries_are_empty() {
            self.server_key.full_propagate(lhs);
        }
        if !rhs.block_carries_are_empty() {
            self.server_key.full_propagate(rhs);
        }
        self.unchecked_compare(lhs, rhs, sign_result_handler_fn)
    }

    /// Expects the carry buffers to be empty
    fn unchecked_min_or_max<T>(&self, lhs: &T, rhs: &T, selector: MinMaxSelector) -> T
    where
        T: IntegerRadixCiphertext,
    {
        let (lhs_lut, rhs_lut) = match selector {
            MinMaxSelector::Max => (&self.lhs_lut, &self.rhs_lut),
            MinMaxSelector::Min => (&self.rhs_lut, &self.lhs_lut),
        };
        let num_block = lhs.blocks().len();

        let mut offset = self.unchecked_compare(lhs, rhs, |x| x);
        self.server_key
            .key
            .apply_lookup_table_assign(&mut offset, &self.comparison_result_to_offset_lut);

        let mut result = Vec::with_capacity(num_block);
        for i in 0..num_block {
            let lhs_block = self.server_key.key.unchecked_add(&lhs.blocks()[i], &offset);
            let rhs_block = self.server_key.key.unchecked_add(&rhs.blocks()[i], &offset);

            let maybe_lhs = self.server_key.key.apply_lookup_table(&lhs_block, lhs_lut);
            let maybe_rhs = self.server_key.key.apply_lookup_table(&rhs_block, rhs_lut);
            let mut r = self.server_key.key.unchecked_add(&maybe_lhs, &maybe_rhs);
            // Either maybe_lhs or maybe_rhs is zero, which means that the degree is tighter.
            r.degree = Degree::new(self.server_key.message_modulus().0 - 1);
            result.push(r);
        }

        T::from_blocks(result)
    }

    fn smart_min_or_max<T>(&self, lhs: &mut T, rhs: &mut T, selector: MinMaxSelector) -> T
    where
        T: IntegerRadixCiphertext,
    {
        if !lhs.block_carries_are_empty() {
            self.server_key.full_propagate_parallelized(lhs);
        }
        if !rhs.block_carries_are_empty() {
            self.server_key.full_propagate_parallelized(rhs);
        }
        self.unchecked_min_or_max(lhs, rhs, selector)
    }

    //======================================
    // Unchecked Single-Threaded operations
    //======================================

    pub fn unchecked_gt<T>(&self, lhs: &T, rhs: &T) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
    {
        let sign_result_handler_fn = |x| u64::from(x == Self::IS_SUPERIOR);
        let comparison = self.unchecked_compare(lhs, rhs, sign_result_handler_fn);
        BooleanBlock::new_unchecked(comparison)
    }

    pub fn unchecked_ge<T>(&self, lhs: &T, rhs: &T) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
    {
        let sign_result_handler_fn = |x| u64::from(x == Self::IS_EQUAL || x == Self::IS_SUPERIOR);
        let comparison = self.unchecked_compare(lhs, rhs, sign_result_handler_fn);
        BooleanBlock::new_unchecked(comparison)
    }

    pub fn unchecked_lt<T>(&self, lhs: &T, rhs: &T) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
    {
        let sign_result_handler_fn = |x| u64::from(x == Self::IS_INFERIOR);
        let comparison = self.unchecked_compare(lhs, rhs, sign_result_handler_fn);
        BooleanBlock::new_unchecked(comparison)
    }

    pub fn unchecked_le<T>(&self, lhs: &T, rhs: &T) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
    {
        let sign_result_handler_fn = |x| u64::from(x == Self::IS_EQUAL || x == Self::IS_INFERIOR);
        let comparison = self.unchecked_compare(lhs, rhs, sign_result_handler_fn);
        BooleanBlock::new_unchecked(comparison)
    }

    pub fn unchecked_max<T>(&self, lhs: &T, rhs: &T) -> T
    where
        T: IntegerRadixCiphertext,
    {
        self.unchecked_min_or_max(lhs, rhs, MinMaxSelector::Max)
    }

    pub fn unchecked_min<T>(&self, lhs: &T, rhs: &T) -> T
    where
        T: IntegerRadixCiphertext,
    {
        self.unchecked_min_or_max(lhs, rhs, MinMaxSelector::Min)
    }

    //======================================
    // Smart Single-Threaded operations
    //======================================

    pub fn smart_gt<T>(&self, lhs: &mut T, rhs: &mut T) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
    {
        let sign_result_handler_fn = |x| u64::from(x == Self::IS_SUPERIOR);
        let comparison = self.smart_compare(lhs, rhs, sign_result_handler_fn);
        BooleanBlock::new_unchecked(comparison)
    }

    pub fn smart_ge<T>(&self, lhs: &mut T, rhs: &mut T) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
    {
        let sign_result_handler_fn = |x| u64::from(x == Self::IS_EQUAL || x == Self::IS_SUPERIOR);
        let comparison = self.smart_compare(lhs, rhs, sign_result_handler_fn);
        BooleanBlock::new_unchecked(comparison)
    }

    pub fn smart_lt<T>(&self, lhs: &mut T, rhs: &mut T) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
    {
        let sign_result_handler_fn = |x| u64::from(x == Self::IS_INFERIOR);
        let comparison = self.smart_compare(lhs, rhs, sign_result_handler_fn);
        BooleanBlock::new_unchecked(comparison)
    }

    pub fn smart_le<T>(&self, lhs: &mut T, rhs: &mut T) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
    {
        let sign_result_handler_fn = |x| u64::from(x == Self::IS_EQUAL || x == Self::IS_INFERIOR);
        let comparison = self.smart_compare(lhs, rhs, sign_result_handler_fn);
        BooleanBlock::new_unchecked(comparison)
    }

    pub fn smart_max<T>(&self, lhs: &mut T, rhs: &mut T) -> T
    where
        T: IntegerRadixCiphertext,
    {
        self.smart_min_or_max(lhs, rhs, MinMaxSelector::Max)
    }

    pub fn smart_min<T>(&self, lhs: &mut T, rhs: &mut T) -> T
    where
        T: IntegerRadixCiphertext,
    {
        self.smart_min_or_max(lhs, rhs, MinMaxSelector::Min)
    }
}
