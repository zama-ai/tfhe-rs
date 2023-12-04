// use itertools::Itertools;
use super::ServerKey;

use crate::integer::block_decomposition::{BlockDecomposer, DecomposableInto};
use crate::integer::ciphertext::IntegerRadixCiphertext;
use crate::integer::server_key::comparator::{Comparator, ZeroComparisonType};
use crate::shortint::server_key::LookupTableOwned;
use crate::shortint::Ciphertext;

use crate::integer::ciphertext::boolean_value::BooleanBlock;
use rayon::prelude::*;

impl ServerKey {
    /// Returns whether the clear scalar is outside of the
    /// value range the ciphertext can hold.
    ///
    /// - Returns None if the scalar is in the range of values that the ciphertext can represent
    ///
    /// - Returns Some(ordering) when the scalar is out of representable range of the ciphertext.
    ///     - Equal will never be returned
    ///     - Less means the scalar is less than the min value representable by the ciphertext
    ///     - Greater means the scalar is greater that the max value representable by the ciphertext
    pub(crate) fn is_scalar_out_of_bounds<T, Scalar>(
        &self,
        ct: &T,
        scalar: Scalar,
    ) -> Option<std::cmp::Ordering>
    where
        T: IntegerRadixCiphertext,
        Scalar: DecomposableInto<u64>,
    {
        let scalar_blocks =
            BlockDecomposer::with_early_stop_at_zero(scalar, self.key.message_modulus.0.ilog2())
                .iter_as::<u64>()
                .collect::<Vec<_>>();

        if T::IS_SIGNED {
            let sign_bit_pos = self.key.message_modulus.0.ilog2() - 1;
            let sign_bit_is_set = scalar_blocks
                .get(ct.blocks().len() - 1)
                .map_or(false, |block| (block >> sign_bit_pos) == 1);

            if scalar > Scalar::ZERO
                && (scalar_blocks.len() > ct.blocks().len()
                    || (scalar_blocks.len() == ct.blocks().len() && sign_bit_is_set))
            {
                // If scalar is positive and that any bits above the ct's n-1 bits is set
                // it means scalar is bigger.
                //
                // This is checked in two step
                // - If there a more scalar blocks than ct blocks then ct is trivially bigger
                // - If there are the same number of blocks but the "sign bit" / msb of st scalar is
                //   set then, the scalar is trivially bigger
                return Some(std::cmp::Ordering::Greater);
            } else if scalar < Scalar::ZERO {
                // If scalar is negative, and that any bits above the ct's n-1 bits is not set
                // it means scalar is smaller.

                // (returns false for empty iter)
                let at_least_one_block_is_not_full_of_1s = scalar_blocks[ct.blocks().len()..]
                    .iter()
                    .any(|&scalar_block| scalar_block != (self.key.message_modulus.0 as u64 - 1));

                let sign_bit_pos = self.key.message_modulus.0.ilog2() - 1;
                let sign_bit_is_unset = scalar_blocks
                    .get(ct.blocks().len() - 1)
                    .map_or(false, |block| (block >> sign_bit_pos) == 0);

                if at_least_one_block_is_not_full_of_1s || sign_bit_is_unset {
                    // Scalar is smaller than lowest value of T
                    return Some(std::cmp::Ordering::Less);
                }
            }
        } else {
            // T is unsigned
            if scalar < Scalar::ZERO {
                // ct represent an unsigned (always >= 0)
                return Some(std::cmp::Ordering::Less);
            } else if scalar > Scalar::ZERO {
                // scalar is obviously bigger if it has non-zero
                // blocks  after lhs's last block
                let is_scalar_obviously_bigger = scalar_blocks
                    .get(ct.blocks().len()..)
                    .is_some_and(|sub_slice| {
                        sub_slice.iter().any(|&scalar_block| scalar_block != 0)
                    });
                if is_scalar_obviously_bigger {
                    return Some(std::cmp::Ordering::Greater);
                }
            }
        }

        None
    }

    /// Takes a chunk of 2 ciphertexts and packs them together in a new ciphertext
    ///
    /// The first element of the chunk are the low bits, the second are the high bits
    ///
    /// This requires the block parameters to have enough room for two ciphertexts,
    /// so at least as many carry modulus as the message modulus
    ///
    /// Expects the carry buffer to be empty
    pub(crate) fn pack_block_chunk(
        &self,
        chunk: &[crate::shortint::Ciphertext],
    ) -> crate::shortint::Ciphertext {
        debug_assert!(chunk.len() <= 2);

        if chunk.len() == 1 {
            return chunk[0].clone();
        }

        let low = &chunk[0];
        let mut high = chunk[1].clone();

        self.pack_block_assign(low, &mut high);
        high
    }

    /// Packs the low ciphertext in the message parts of the high ciphertext
    /// and moves the high ciphertext into the carry part.
    ///
    /// This requires the block parameters to have enough room for two ciphertexts,
    /// so at least as many carry modulus as the message modulus
    ///
    /// Expects the carry buffer to be empty
    pub(crate) fn pack_block_assign(
        &self,
        low: &crate::shortint::Ciphertext,
        high: &mut crate::shortint::Ciphertext,
    ) {
        debug_assert!(high.degree.get() < high.message_modulus.0);

        self.key
            .unchecked_scalar_mul_assign(high, high.message_modulus.0 as u8);
        self.key.unchecked_add_assign(high, low);
    }

    /// This takes a Vec of shortint blocks, where each block is
    /// either 0 or 1.
    ///
    /// It return a shortint block encrypting 1 if all input blocks are 1
    /// otherwise the block encrypts 0
    ///
    /// if the vec is empty, a trivial 1 is returned
    pub(crate) fn are_all_comparisons_block_true(
        &self,
        mut block_comparisons: Vec<Ciphertext>,
    ) -> Ciphertext {
        if block_comparisons.is_empty() {
            return self.key.create_trivial(1);
        }

        let message_modulus = self.key.message_modulus.0;
        let carry_modulus = self.key.carry_modulus.0;
        let total_modulus = message_modulus * carry_modulus;
        let max_value = total_modulus - 1;

        let is_max_value = self
            .key
            .generate_lookup_table(|x| u64::from(x == max_value as u64));

        while block_comparisons.len() > 1 {
            // Since all blocks encrypt either 0 or 1, we can sum max_value of them
            // as in the worst case we will be adding `max_value` ones
            block_comparisons = block_comparisons
                .par_chunks(max_value)
                .map(|blocks| {
                    let mut sum = blocks[0].clone();
                    for other_block in &blocks[1..] {
                        self.key.unchecked_add_assign(&mut sum, other_block);
                    }

                    if blocks.len() == max_value {
                        self.key.apply_lookup_table(&sum, &is_max_value)
                    } else {
                        let is_equal_to_num_blocks = self
                            .key
                            .generate_lookup_table(|x| u64::from(x == blocks.len() as u64));
                        self.key.apply_lookup_table(&sum, &is_equal_to_num_blocks)
                    }
                })
                .collect::<Vec<_>>();
        }

        block_comparisons
            .into_iter()
            .next()
            .expect("one block was expected")
    }

    /// This takes a Vec of shortint blocks, where each block is
    /// either 0 or 1.
    ///
    /// It return a shortint block encrypting 1 if at least input blocks is 1
    /// otherwise the block encrypts 0 (all blocks encrypts 0)
    ///
    /// if the vec is empty, a trivial 1 is returned
    pub(crate) fn is_at_least_one_comparisons_block_true(
        &self,
        mut block_comparisons: Vec<Ciphertext>,
    ) -> Ciphertext {
        if block_comparisons.is_empty() {
            return self.key.create_trivial(1);
        }

        let message_modulus = self.key.message_modulus.0;
        let carry_modulus = self.key.carry_modulus.0;
        let total_modulus = message_modulus * carry_modulus;
        let max_value = total_modulus - 1;

        let is_not_zero = self.key.generate_lookup_table(|x| u64::from(x != 0));

        while block_comparisons.len() > 1 {
            block_comparisons = block_comparisons
                .par_chunks(max_value)
                .map(|blocks| {
                    let mut sum = blocks[0].clone();
                    for other_block in &blocks[1..] {
                        self.key.unchecked_add_assign(&mut sum, other_block);
                    }

                    self.key.apply_lookup_table(&sum, &is_not_zero)
                })
                .collect::<Vec<_>>();
        }

        block_comparisons
            .into_iter()
            .next()
            .expect("one block was expected")
    }

    /// This takes an input slice of blocks.
    ///
    /// Each block can encrypt any value as long as its < message_modulus.
    ///
    /// It will compare blocks with 0, for either equality or difference.
    ///
    /// This returns a Vec of block, where each block encrypts 1 or 0
    /// depending of if all blocks matched with the comparison type with 0.
    ///
    /// E.g. For ZeroComparisonType::Equality, if all input blocks are zero
    /// than all returned block will encrypt 1
    ///
    /// The returned Vec will have less block than the number of input blocks.
    /// The returned blocks potentially needs to be 'reduced' to one block
    /// with eg are_all_comparisons_block_true.
    ///
    /// This function exists because sometimes it is faster to concatenate
    /// multiple vec of 'boolean' shortint block before reducing them with
    /// are_all_comparisons_block_true
    pub(crate) fn compare_blocks_with_zero(
        &self,
        lhs: &[Ciphertext],
        comparison_type: ZeroComparisonType,
    ) -> Vec<Ciphertext> {
        if lhs.is_empty() {
            return vec![];
        }

        debug_assert!(lhs.iter().all(Ciphertext::carry_is_empty));

        let message_modulus = self.key.message_modulus.0;
        let carry_modulus = self.key.carry_modulus.0;
        let total_modulus = message_modulus * carry_modulus;
        let message_max = message_modulus - 1;

        // The idea is that we will sum chunks of blocks until carries are full
        // then we compare the sum with 0.
        //
        // If all blocks were 0, the sum will be zero
        // If at least one bock was not zero, the sum won't be zero
        let num_elements_to_fill_carry = (total_modulus - 1) / message_max;
        let is_equal_to_zero = self.key.generate_lookup_table(|x| {
            if matches!(comparison_type, ZeroComparisonType::Equality) {
                u64::from((x % total_modulus as u64) == 0)
            } else {
                u64::from((x % total_modulus as u64) != 0)
            }
        });

        lhs.par_chunks(num_elements_to_fill_carry)
            .map(|chunk| {
                let mut sum = chunk[0].clone();
                for other_block in &chunk[1..] {
                    self.key.unchecked_add_assign(&mut sum, other_block);
                }

                self.key
                    .apply_lookup_table_assign(&mut sum, &is_equal_to_zero);
                sum
            })
            .collect::<Vec<_>>()
    }

    /// Given a slice of scalar values, and a total_modulus
    /// where  each scalar value is < total_modulus
    ///
    /// This will return a vector of size `total_modulus`,
    /// where for each index, the vec contains either
    /// - `None` if fhe scalar was not present in the slice,
    /// - or `Some` lookuptable that allows to compare a shortint block to the scalar value at this
    ///  index
    ///
    ///
    ///  E.g.
    ///  - input slice: [0, 2],
    ///  - total_modulus: 4,
    ///  returns -> [Some(LUT(|x| x == 0)), None, Some(LUT(|x| x == 2), None]
    fn create_scalar_comparison_luts<F>(
        &self,
        scalar_blocks: &[u8],
        total_modulus: usize,
        comparison_fn: F,
    ) -> Vec<Option<LookupTableOwned>>
    where
        F: Fn(u8, u8) -> bool + Sync,
    {
        // One lut per scalar block
        // And only generate a lut for scalar block
        // actually present
        let mut scalar_comp_luts = vec![None; total_modulus];
        for scalar_block in scalar_blocks.iter().copied() {
            if scalar_comp_luts[scalar_block as usize].is_some() {
                // The LUT for this scalar has already been generated
                continue;
            }
            let lut = self
                .key
                .generate_lookup_table(|x| u64::from(comparison_fn(x as u8, scalar_block)));
            scalar_comp_luts[scalar_block as usize] = Some(lut);
        }
        scalar_comp_luts
    }

    /// Compares for equality a ciphertexts and a clear value
    ///
    /// Returns a ciphertext containing 1 if lhs == rhs, otherwise 0
    ///
    /// Requires carry bits to be empty
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let size = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size);
    ///
    /// let msg1 = 14u64;
    /// let msg2 = 97u64;
    ///
    /// let ct1 = cks.encrypt(msg1);
    ///
    /// let ct_res = sks.unchecked_scalar_eq_parallelized(&ct1, msg2);
    ///
    /// // Decrypt:
    /// let dec_result = cks.decrypt_bool(&ct_res);
    /// assert_eq!(dec_result, msg1 == msg2);
    /// ```
    pub fn unchecked_scalar_eq_parallelized<T, Scalar>(&self, lhs: &T, rhs: Scalar) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
        Scalar: DecomposableInto<u64>,
    {
        debug_assert!(lhs.block_carries_are_empty());

        if T::IS_SIGNED {
            match self.is_scalar_out_of_bounds(lhs, rhs) {
                Some(std::cmp::Ordering::Greater | std::cmp::Ordering::Less) => {
                    // Scalar is not within bounds so it cannot be equal
                    return self.create_trivial_boolean_block(false);
                }
                Some(std::cmp::Ordering::Equal) => {
                    unreachable!("Internal error: is_scalar_out_of_bounds returned Ordering::Equal")
                }
                None => {
                    let trivial = self.create_trivial_radix(rhs, lhs.blocks().len());
                    return self.unchecked_eq_parallelized(lhs, &trivial);
                }
            }
        }

        // Starting From here, we know lhs (T) is an unsigned ciphertext
        if rhs < Scalar::ZERO {
            return self.create_trivial_boolean_block(false);
        }

        let message_modulus = self.key.message_modulus.0;
        let carry_modulus = self.key.carry_modulus.0;
        let total_modulus = message_modulus * carry_modulus;
        let max_value = total_modulus - 1;

        assert!(carry_modulus >= message_modulus);
        u8::try_from(max_value).unwrap();

        let num_blocks = lhs.blocks().len();
        let num_blocks_halved = (num_blocks / 2) + (num_blocks % 2);

        let mut scalar_blocks =
            BlockDecomposer::with_early_stop_at_zero(rhs, total_modulus.ilog2())
                .iter_as::<u64>()
                .map(|x| x as u8)
                .collect::<Vec<_>>();

        // If we have more scalar blocks than lhs.blocks
        // and that any of these additional blocks is != 0
        // then lhs != rhs
        let is_scalar_obviously_bigger = scalar_blocks
            .get(num_blocks_halved..) // We may have less scalar blocks
            .is_some_and(|sub_slice| sub_slice.iter().any(|&scalar_block| scalar_block != 0));
        if is_scalar_obviously_bigger {
            return self.create_trivial_boolean_block(false);
        }
        // If we are sill here, that means scalar_blocks above
        // num_blocks_halved are 0s, we can remove them
        // as we will handle them separately.
        // (truncate can be called even if scalar_blocks.len() < num_blocks_halved);
        scalar_blocks.truncate(num_blocks_halved);

        let scalar_comp_luts =
            self.create_scalar_comparison_luts(&scalar_blocks, total_modulus, |x, y| x == y);

        // scalar_blocks.len() is known to be <= to num_blocks_halved
        // but num_blocks_halved takes into account the non-even num_blocks case
        let split_index = num_blocks.min(scalar_blocks.len() * 2);
        let (least_significant_blocks, most_significant_blocks) =
            lhs.blocks().split_at(split_index);

        let (mut cmp_1, mut cmp_2) = rayon::join(
            || {
                let scalar_block_iter = scalar_blocks.into_par_iter();

                let mut packed_blocks = Vec::with_capacity(num_blocks_halved);
                least_significant_blocks
                    .par_chunks(2)
                    .zip(scalar_block_iter)
                    .map(|(two_blocks, scalar_block)| {
                        let lut = scalar_comp_luts[scalar_block as usize]
                            .as_ref()
                            .expect("internal error, missing scalar comparison lut");
                        let mut packed_block = self.pack_block_chunk(two_blocks);
                        self.key.apply_lookup_table_assign(&mut packed_block, lut);
                        packed_block
                    })
                    .collect_into_vec(&mut packed_blocks);

                packed_blocks
            },
            || self.compare_blocks_with_zero(most_significant_blocks, ZeroComparisonType::Equality),
        );
        cmp_1.append(&mut cmp_2);
        let is_equal_result = self.are_all_comparisons_block_true(cmp_1);
        BooleanBlock::new_unchecked(is_equal_result)
    }

    pub fn unchecked_scalar_ne_parallelized<T, Scalar>(&self, lhs: &T, rhs: Scalar) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
        Scalar: DecomposableInto<u64>,
    {
        debug_assert!(lhs.block_carries_are_empty());

        if T::IS_SIGNED {
            match self.is_scalar_out_of_bounds(lhs, rhs) {
                Some(std::cmp::Ordering::Greater | std::cmp::Ordering::Less) => {
                    // Scalar is not within bounds so its not equal
                    return self.create_trivial_boolean_block(true);
                }
                Some(std::cmp::Ordering::Equal) => unreachable!("Internal error: invalid value"),
                None => {
                    let trivial = self.create_trivial_radix(rhs, lhs.blocks().len());
                    return self.unchecked_ne_parallelized(lhs, &trivial);
                }
            }
        }

        if rhs < Scalar::ZERO {
            return self.create_trivial_boolean_block(true);
        }

        let message_modulus = self.key.message_modulus.0;
        let carry_modulus = self.key.carry_modulus.0;
        let total_modulus = message_modulus * carry_modulus;
        let max_value = total_modulus - 1;

        assert!(carry_modulus >= message_modulus);
        u8::try_from(max_value).unwrap();

        let num_blocks = lhs.blocks().len();
        let num_blocks_halved = (num_blocks / 2) + (num_blocks % 2);

        let mut scalar_blocks =
            BlockDecomposer::with_early_stop_at_zero(rhs, total_modulus.ilog2())
                .iter_as::<u64>()
                .map(|x| x as u8)
                .collect::<Vec<_>>();

        // If we have more scalar blocks than lhs.blocks
        // and that any of these block additional blocks is != 0
        // then lhs != rhs
        let is_scalar_obviously_bigger = scalar_blocks
            .get(num_blocks_halved..) // We may have less scalar blocks
            .is_some_and(|sub_slice| sub_slice.iter().any(|&scalar_block| scalar_block != 0));
        if is_scalar_obviously_bigger {
            return self.create_trivial_boolean_block(true);
        }
        // If we are sill here, that means scalar_blocks above
        // num_blocks_halved are 0s, we can remove them
        // as we will handle them separately.
        // (truncate can be called even if scalar_blocks.len() < num_blocks_halved);
        scalar_blocks.truncate(num_blocks_halved);

        let scalar_comp_luts =
            self.create_scalar_comparison_luts(&scalar_blocks, total_modulus, |x, y| x != y);

        // scalar_blocks.len() is known to be <= to num_blocks_halved
        // but num_blocks_halved takes into account the non-even num_blocks case
        let split_index = num_blocks.min(scalar_blocks.len() * 2);
        let (least_significant_blocks, most_significant_blocks) =
            lhs.blocks().split_at(split_index);

        let (mut cmp_1, mut cmp_2) = rayon::join(
            || {
                let scalar_block_iter = scalar_blocks.into_par_iter();

                let mut packed_blocks = Vec::with_capacity(num_blocks_halved);
                least_significant_blocks
                    .par_chunks(2)
                    .zip(scalar_block_iter)
                    .map(|(two_blocks, scalar_block)| {
                        let lut = scalar_comp_luts[scalar_block as usize]
                            .as_ref()
                            .expect("internal error, missing scalar comparison lut");
                        let mut packed_block = self.pack_block_chunk(two_blocks);
                        self.key.apply_lookup_table_assign(&mut packed_block, lut);
                        packed_block
                    })
                    .collect_into_vec(&mut packed_blocks);

                packed_blocks
            },
            || {
                self.compare_blocks_with_zero(
                    most_significant_blocks,
                    ZeroComparisonType::Difference,
                )
            },
        );
        cmp_1.append(&mut cmp_2);
        let is_equal_result = self.is_at_least_one_comparisons_block_true(cmp_1);
        BooleanBlock::new_unchecked(is_equal_result)
    }

    pub fn smart_scalar_eq_parallelized<T, Scalar>(&self, lhs: &mut T, rhs: Scalar) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
        Scalar: DecomposableInto<u64>,
    {
        if !lhs.block_carries_are_empty() {
            self.full_propagate_parallelized(lhs);
        }
        self.unchecked_scalar_eq_parallelized(lhs, rhs)
    }

    pub fn scalar_eq_parallelized<T, Scalar>(&self, lhs: &T, rhs: Scalar) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
        Scalar: DecomposableInto<u64>,
    {
        let mut tmp_lhs;
        let lhs = if lhs.block_carries_are_empty() {
            lhs
        } else {
            tmp_lhs = lhs.clone();
            self.full_propagate_parallelized(&mut tmp_lhs);
            &tmp_lhs
        };
        self.unchecked_scalar_eq_parallelized(lhs, rhs)
    }

    pub fn smart_scalar_ne_parallelized<T, Scalar>(&self, lhs: &mut T, rhs: Scalar) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
        Scalar: DecomposableInto<u64>,
    {
        if !lhs.block_carries_are_empty() {
            self.full_propagate_parallelized(lhs);
        }
        self.unchecked_scalar_ne_parallelized(lhs, rhs)
    }

    pub fn scalar_ne_parallelized<T, Scalar>(&self, lhs: &T, rhs: Scalar) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
        Scalar: DecomposableInto<u64>,
    {
        let mut tmp_lhs;
        let lhs = if lhs.block_carries_are_empty() {
            lhs
        } else {
            tmp_lhs = lhs.clone();
            self.full_propagate_parallelized(&mut tmp_lhs);
            &tmp_lhs
        };
        self.unchecked_scalar_ne_parallelized(lhs, rhs)
    }

    //===========================================================
    // Unchecked <, >, <=, >=, min, max
    //===========================================================

    pub fn unchecked_scalar_gt_parallelized<T, Scalar>(&self, lhs: &T, rhs: Scalar) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
        Scalar: DecomposableInto<u64>,
    {
        Comparator::new(self).unchecked_scalar_gt_parallelized(lhs, rhs)
    }

    pub fn unchecked_scalar_ge_parallelized<T, Scalar>(&self, lhs: &T, rhs: Scalar) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
        Scalar: DecomposableInto<u64>,
    {
        Comparator::new(self).unchecked_scalar_ge_parallelized(lhs, rhs)
    }

    pub fn unchecked_scalar_lt_parallelized<T, Scalar>(&self, lhs: &T, rhs: Scalar) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
        Scalar: DecomposableInto<u64>,
    {
        Comparator::new(self).unchecked_scalar_lt_parallelized(lhs, rhs)
    }

    pub fn unchecked_scalar_le_parallelized<T, Scalar>(&self, lhs: &T, rhs: Scalar) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
        Scalar: DecomposableInto<u64>,
    {
        Comparator::new(self).unchecked_scalar_le_parallelized(lhs, rhs)
    }

    pub fn unchecked_scalar_max_parallelized<T, Scalar>(&self, lhs: &T, rhs: Scalar) -> T
    where
        T: IntegerRadixCiphertext,
        Scalar: DecomposableInto<u64>,
    {
        Comparator::new(self).unchecked_scalar_max_parallelized(lhs, rhs)
    }

    pub fn unchecked_scalar_min_parallelized<T, Scalar>(&self, lhs: &T, rhs: Scalar) -> T
    where
        T: IntegerRadixCiphertext,
        Scalar: DecomposableInto<u64>,
    {
        Comparator::new(self).unchecked_scalar_min_parallelized(lhs, rhs)
    }

    //===========================================================
    // Smart <, >, <=, >=, min, max
    //===========================================================

    pub fn smart_scalar_gt_parallelized<T, Scalar>(&self, lhs: &mut T, rhs: Scalar) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
        Scalar: DecomposableInto<u64>,
    {
        Comparator::new(self).smart_scalar_gt_parallelized(lhs, rhs)
    }

    pub fn smart_scalar_ge_parallelized<T, Scalar>(&self, lhs: &mut T, rhs: Scalar) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
        Scalar: DecomposableInto<u64>,
    {
        Comparator::new(self).smart_scalar_ge_parallelized(lhs, rhs)
    }

    pub fn smart_scalar_lt_parallelized<T, Scalar>(&self, lhs: &mut T, rhs: Scalar) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
        Scalar: DecomposableInto<u64>,
    {
        Comparator::new(self).smart_scalar_lt_parallelized(lhs, rhs)
    }

    pub fn smart_scalar_le_parallelized<T, Scalar>(&self, lhs: &mut T, rhs: Scalar) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
        Scalar: DecomposableInto<u64>,
    {
        Comparator::new(self).smart_scalar_le_parallelized(lhs, rhs)
    }

    pub fn smart_scalar_max_parallelized<T, Scalar>(&self, lhs: &mut T, rhs: Scalar) -> T
    where
        T: IntegerRadixCiphertext,
        Scalar: DecomposableInto<u64>,
    {
        Comparator::new(self).smart_scalar_max_parallelized(lhs, rhs)
    }

    pub fn smart_scalar_min_parallelized<T, Scalar>(&self, lhs: &mut T, rhs: Scalar) -> T
    where
        T: IntegerRadixCiphertext,
        Scalar: DecomposableInto<u64>,
    {
        Comparator::new(self).smart_scalar_min_parallelized(lhs, rhs)
    }

    //===========================================================
    // Default <, >, <=, >=, min, max
    //===========================================================

    pub fn scalar_gt_parallelized<T, Scalar>(&self, lhs: &T, rhs: Scalar) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
        Scalar: DecomposableInto<u64>,
    {
        Comparator::new(self).scalar_gt_parallelized(lhs, rhs)
    }

    pub fn scalar_ge_parallelized<T, Scalar>(&self, lhs: &T, rhs: Scalar) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
        Scalar: DecomposableInto<u64>,
    {
        Comparator::new(self).scalar_ge_parallelized(lhs, rhs)
    }

    pub fn scalar_lt_parallelized<T, Scalar>(&self, lhs: &T, rhs: Scalar) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
        Scalar: DecomposableInto<u64>,
    {
        Comparator::new(self).scalar_lt_parallelized(lhs, rhs)
    }

    pub fn scalar_le_parallelized<T, Scalar>(&self, lhs: &T, rhs: Scalar) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
        Scalar: DecomposableInto<u64>,
    {
        Comparator::new(self).scalar_le_parallelized(lhs, rhs)
    }

    pub fn scalar_max_parallelized<T, Scalar>(&self, lhs: &T, rhs: Scalar) -> T
    where
        T: IntegerRadixCiphertext,
        Scalar: DecomposableInto<u64>,
    {
        Comparator::new(self).scalar_max_parallelized(lhs, rhs)
    }

    pub fn scalar_min_parallelized<T, Scalar>(&self, lhs: &T, rhs: Scalar) -> T
    where
        T: IntegerRadixCiphertext,
        Scalar: DecomposableInto<u64>,
    {
        Comparator::new(self).scalar_min_parallelized(lhs, rhs)
    }
}
