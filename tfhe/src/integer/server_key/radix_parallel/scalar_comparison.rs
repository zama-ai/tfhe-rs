use super::ServerKey;
use crate::core_crypto::prelude::{lwe_ciphertext_sub_assign, Numeric};
use crate::integer::block_decomposition::{BlockDecomposer, DecomposableInto};
use crate::integer::ciphertext::boolean_value::BooleanBlock;
use crate::integer::ciphertext::IntegerRadixCiphertext;
use crate::integer::server_key::comparator::ZeroComparisonType;
use crate::integer::server_key::radix_parallel::comparison::{
    is_x_less_than_y_given_input_borrow, ComparisonKind, PreparedSignedCheck,
};
use crate::shortint::ciphertext::Degree;
use crate::shortint::server_key::LookupTableOwned;
use crate::shortint::{Ciphertext, MessageModulus};
use rayon::prelude::*;

impl ServerKey {
    /// Returns whether the clear scalar is outside of the
    /// value range the ciphertext can hold.
    ///
    /// - Returns an ordering:
    ///   - Equal means the scalar is in the range of values that the ciphertext can represent
    ///   - Less means the scalar is less than the min value representable by the ciphertext
    ///   - Greater means the scalar is greater that the max value representable by the ciphertext
    pub(crate) fn is_scalar_out_of_bounds<T, Scalar>(
        &self,
        ct: &T,
        scalar: Scalar,
    ) -> std::cmp::Ordering
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
                .is_some_and(|block| (block >> sign_bit_pos) == 1);

            if scalar > Scalar::ZERO
                && (scalar_blocks.len() > ct.blocks().len()
                    || (scalar_blocks.len() == ct.blocks().len() && sign_bit_is_set))
            {
                // If scalar is positive and that any bits above the ct's n-1 bits is set
                // it means scalar is bigger.
                //
                // This is checked in two step
                // - If there a more scalar blocks than ct blocks then scalar is trivially bigger
                // - If there are the same number of blocks but the "sign bit" / msb of st scalar is
                //   set then, the scalar is trivially bigger
                return std::cmp::Ordering::Greater;
            } else if scalar < Scalar::ZERO {
                // If scalar is negative, and that any bits above the ct's n-1 bits is not set
                // it means scalar is smaller.

                if ct.blocks().len() > scalar_blocks.len() {
                    // Ciphertext has more blocks, the scalar may be in range
                    return std::cmp::Ordering::Equal;
                }

                // (returns false for empty iter)
                let at_least_one_block_is_not_full_of_1s = scalar_blocks[ct.blocks().len()..]
                    .iter()
                    .any(|&scalar_block| scalar_block != (self.key.message_modulus.0 - 1));

                let sign_bit_pos = self.key.message_modulus.0.ilog2() - 1;
                let sign_bit_is_unset = scalar_blocks
                    .get(ct.blocks().len() - 1)
                    .is_some_and(|block| (block >> sign_bit_pos) == 0);

                if at_least_one_block_is_not_full_of_1s || sign_bit_is_unset {
                    // Scalar is smaller than lowest value of T
                    return std::cmp::Ordering::Less;
                }
            }
        } else {
            // T is unsigned
            if scalar < Scalar::ZERO {
                // ct represent an unsigned (always >= 0)
                return std::cmp::Ordering::Less;
            } else if scalar > Scalar::ZERO {
                // scalar is obviously bigger if it has non-zero
                // blocks  after lhs's last block
                let is_scalar_obviously_bigger = scalar_blocks
                    .get(ct.blocks().len()..)
                    .is_some_and(|sub_slice| {
                        sub_slice.iter().any(|&scalar_block| scalar_block != 0)
                    });
                if is_scalar_obviously_bigger {
                    return std::cmp::Ordering::Greater;
                }
            }
        }

        std::cmp::Ordering::Equal
    }

    /// If two blocks can be packed by calling [`Self::pack_block_chunk`] this will return the
    /// [`Ok`] variant containing the chunk that can be packed to be able to chain map operators,
    /// otherwise it returns the error that occurred.
    pub(crate) fn can_pack_block_chunk<'data>(
        &self,
        chunk: &'data [crate::shortint::Ciphertext],
    ) -> crate::Result<&'data [crate::shortint::Ciphertext]> {
        match chunk.len() {
            0 | 1 => Ok(chunk),
            2 => {
                if self.carry_modulus().0 < self.message_modulus().0 {
                    return Err(crate::error!(
                        "Cannot pack if carry modulus is smaller than message modulus"
                    ));
                }

                let low = &chunk[0];
                let high = &chunk[1];

                let carries_ok = low.carry_is_empty() && high.carry_is_empty();
                if !carries_ok {
                    return Err(crate::error!(
                        "Cannot pack blocks: need both carries to be empty."
                    ));
                }

                let final_noise = high.noise_level() * self.message_modulus().0 + low.noise_level();
                self.key
                    .max_noise_level
                    .validate(final_noise)
                    .map_err(|e| crate::error!("{}", e))
                    .map(|_| chunk)
            }
            _ => Err(crate::error!("Cannot pack chunk with len > 2")),
        }
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

    pub(crate) fn are_all_blocks_zero(&self, ciphertexts: &[Ciphertext]) -> Ciphertext {
        let block_comparisons =
            self.compare_blocks_with_zero(ciphertexts, ZeroComparisonType::Equality);
        self.are_all_comparisons_block_true(block_comparisons)
    }

    /// This takes a Vec of shortint blocks, where each block is
    /// either 0 or 1.
    ///
    /// It returns a shortint block encrypting 1 if all input blocks are 1
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

        let max_sum_size = self.max_sum_size(Degree::new(1));
        let is_max_value = self
            .key
            .generate_lookup_table(|x| u64::from(x == max_sum_size as u64));

        while block_comparisons.len() > 1 {
            // Since all blocks encrypt either 0 or 1, we can sum max_value of them
            // as in the worst case we will be adding `max_value` ones
            block_comparisons = block_comparisons
                .par_chunks(max_sum_size)
                .map(|blocks| {
                    let mut sum = blocks[0].clone();
                    for other_block in &blocks[1..] {
                        self.key.unchecked_add_assign(&mut sum, other_block);
                    }

                    if blocks.len() == max_sum_size {
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
    /// It returns a shortint block encrypting 1 if at least input blocks is 1
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

        let is_not_zero = self.key.generate_lookup_table(|x| u64::from(x != 0));
        let mut block_comparisons_2 = Vec::with_capacity(block_comparisons.len() / 2);
        let max_sum_size = self.max_sum_size(Degree::new(1));

        while block_comparisons.len() > 1 {
            block_comparisons
                .par_chunks(max_sum_size)
                .map(|blocks| {
                    let mut sum = blocks[0].clone();
                    for other_block in &blocks[1..] {
                        self.key.unchecked_add_assign(&mut sum, other_block);
                    }
                    self.key.apply_lookup_table(&sum, &is_not_zero)
                })
                .collect_into_vec(&mut block_comparisons_2);
            std::mem::swap(&mut block_comparisons_2, &mut block_comparisons);
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
    /// depending on if all blocks matched with the comparison type with 0.
    ///
    /// E.g. For ZeroComparisonType::Equality, if all input blocks are zero
    /// than all returned block will encrypt 1
    ///
    /// The returned Vec will have less block than the number of input blocks.
    /// The returned blocks potentially needs to be 'reduced' to one block
    /// with e.g. are_all_comparisons_block_true.
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

        let possible_copy;
        let num_trivial_0 = lhs.iter().filter(|block| block.degree.get() == 0).count();
        let lhs = if num_trivial_0 == lhs.len() {
            return match comparison_type {
                ZeroComparisonType::Equality => {
                    vec![self.key.create_trivial(1)]
                }
                ZeroComparisonType::Difference => {
                    vec![self.key.create_trivial(0)]
                }
            };
        } else if num_trivial_0 != 0 {
            possible_copy = lhs
                .iter()
                .filter(|block| block.degree.get() != 0)
                .cloned()
                .collect::<Vec<_>>();
            possible_copy.as_slice()
        } else {
            lhs
        };

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
                u64::from((x % total_modulus) == 0)
            } else {
                u64::from((x % total_modulus) != 0)
            }
        });

        lhs.par_chunks(num_elements_to_fill_carry as usize)
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
    ///   index
    ///
    ///
    ///  E.g.
    ///  - input slice: [0, 2],
    ///  - total_modulus: 4, returns -> [Some(LUT(|x| x == 0)), None, Some(LUT(|x| x == 2), None]
    fn create_scalar_comparison_luts<F>(
        &self,
        scalar_blocks: &[u8],
        total_modulus: u64,
        comparison_fn: F,
    ) -> Vec<Option<LookupTableOwned>>
    where
        F: Fn(u8, u8) -> bool + Sync,
    {
        // One lut per scalar block
        // And only generate a lut for scalar block
        // actually present
        let mut scalar_comp_luts = vec![None; total_modulus as usize];
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
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    ///
    /// let size = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, size);
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
            return match self.is_scalar_out_of_bounds(lhs, rhs) {
                std::cmp::Ordering::Greater | std::cmp::Ordering::Less => {
                    // Scalar is not within bounds so it cannot be equal
                    self.create_trivial_boolean_block(false)
                }
                std::cmp::Ordering::Equal => {
                    let trivial = self.create_trivial_radix(rhs, lhs.blocks().len());
                    self.unchecked_eq_parallelized(lhs, &trivial)
                }
            };
        }

        // Starting From here, we know lhs (T) is an unsigned ciphertext
        if rhs < Scalar::ZERO {
            return self.create_trivial_boolean_block(false);
        }

        let message_modulus = self.key.message_modulus.0;
        let carry_modulus = self.key.carry_modulus.0;
        let total_modulus = message_modulus * carry_modulus;
        let max_sum_size = self.max_sum_size(Degree::new(1));

        assert!(carry_modulus >= message_modulus);
        u8::try_from(max_sum_size).unwrap();

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
            return match self.is_scalar_out_of_bounds(lhs, rhs) {
                std::cmp::Ordering::Greater | std::cmp::Ordering::Less => {
                    // Scalar is not within bounds so its not equal
                    self.create_trivial_boolean_block(true)
                }
                std::cmp::Ordering::Equal => {
                    let trivial = self.create_trivial_radix(rhs, lhs.blocks().len());
                    self.unchecked_ne_parallelized(lhs, &trivial)
                }
            };
        }

        if rhs < Scalar::ZERO {
            return self.create_trivial_boolean_block(true);
        }

        let message_modulus = self.key.message_modulus.0;
        let carry_modulus = self.key.carry_modulus.0;
        let total_modulus = message_modulus * carry_modulus;
        let max_sum_size = self.max_sum_size(Degree::new(1));

        assert!(carry_modulus >= message_modulus);
        u8::try_from(max_sum_size).unwrap();

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

    /// This implements all comparisons (<, <=, >, >=) for both signed and unsigned
    ///
    /// * inputs must have the same number of blocks
    /// * block carries of both inputs must be empty
    /// * carry modulus == message modulus
    fn scalar_compare<T, Scalar>(&self, a: &T, b: Scalar, compare: ComparisonKind) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
        Scalar: Numeric + DecomposableInto<u64>,
    {
        assert!(a.block_carries_are_empty(), "Block carries must be empty");
        assert_eq!(
            self.carry_modulus().0,
            self.message_modulus().0,
            "The carry modulus must be == to the message modulus"
        );

        if a.blocks().is_empty() {
            // We interpret empty as 0
            return match compare {
                ComparisonKind::Less => self.create_trivial_boolean_block(Scalar::ZERO < b),
                ComparisonKind::LessOrEqual => self.create_trivial_boolean_block(Scalar::ZERO <= b),
                ComparisonKind::Greater => self.create_trivial_boolean_block(Scalar::ZERO > b),
                ComparisonKind::GreaterOrEqual => {
                    self.create_trivial_boolean_block(Scalar::ZERO >= b)
                }
            };
        }

        match self.is_scalar_out_of_bounds(a, b) {
            std::cmp::Ordering::Less => {
                // We have that `b < a` trivially
                return match compare {
                    ComparisonKind::Less | ComparisonKind::LessOrEqual => {
                        // So `a < b` and `a <= b` are false
                        self.create_trivial_boolean_block(false)
                    }
                    ComparisonKind::Greater | ComparisonKind::GreaterOrEqual => {
                        // So `a > b` and `a >= b` are true
                        self.create_trivial_boolean_block(true)
                    }
                };
            }
            std::cmp::Ordering::Greater => {
                // We have that `b > a` trivially
                return match compare {
                    ComparisonKind::Less | ComparisonKind::LessOrEqual => {
                        // So `a < b` and `a <= b` are true
                        self.create_trivial_boolean_block(true)
                    }
                    ComparisonKind::Greater | ComparisonKind::GreaterOrEqual => {
                        // So `a > b` and `a >= b` are false
                        self.create_trivial_boolean_block(false)
                    }
                };
            }
            // We have to do the homomorphic algorithm
            std::cmp::Ordering::Equal => {}
        }

        // Some shortcuts for comparison with zero
        if T::IS_SIGNED && b == Scalar::ZERO {
            match compare {
                ComparisonKind::Less => {
                    return if self.message_modulus().0 > 2 {
                        let sign_bit_lut = self.key.generate_lookup_table(|last_block| {
                            let modulus = self.key.message_modulus.0;
                            (last_block % modulus) / (modulus / 2)
                        });
                        let sign_bit = self
                            .key
                            .apply_lookup_table(a.blocks().last().unwrap(), &sign_bit_lut);
                        BooleanBlock::new_unchecked(sign_bit)
                    } else {
                        BooleanBlock::new_unchecked(a.blocks().last().cloned().unwrap())
                    }
                }
                ComparisonKind::GreaterOrEqual => {
                    let mut sign_bit = if self.message_modulus().0 > 2 {
                        let sign_bit_lut = self.key.generate_lookup_table(|last_block| {
                            let modulus = self.key.message_modulus.0;
                            (last_block % modulus) / (modulus / 2)
                        });
                        let sign_bit = self
                            .key
                            .apply_lookup_table(a.blocks().last().unwrap(), &sign_bit_lut);
                        BooleanBlock::new_unchecked(sign_bit)
                    } else {
                        BooleanBlock::new_unchecked(a.blocks().last().cloned().unwrap())
                    };
                    self.boolean_bitnot_assign(&mut sign_bit);
                    return sign_bit;
                }
                ComparisonKind::LessOrEqual | ComparisonKind::Greater => {}
            }
        } else if !T::IS_SIGNED && b == Scalar::ZERO {
            match compare {
                ComparisonKind::Less => return self.create_trivial_boolean_block(false),
                ComparisonKind::GreaterOrEqual => return self.create_trivial_boolean_block(true),
                ComparisonKind::LessOrEqual | ComparisonKind::Greater => {}
            }
        }

        let packed_modulus = self.key.message_modulus.0 * self.key.message_modulus.0;

        // We have that `a < b` <=> `does_sub_overflows(a, b)` and we know how to do this.
        // Now, to have other comparisons, we will re-express them as less than (`<`)
        // with some potential boolean negation
        //
        // Note that for signed ciphertext it's not the overflowing sub that is used,
        // but it's still something that is based on the subtraction
        //
        // For both signed and unsigned, a subtraction with borrow is used
        // (as opposed to adding the negation)
        let num_block_is_even = (a.blocks().len() & 1) == 0;
        let a = a
            .blocks()
            .chunks(2)
            .map(|chunk_of_two| self.pack_block_chunk(chunk_of_two))
            .collect::<Vec<_>>();

        let mut b_blocks = BlockDecomposer::with_block_count(b, packed_modulus.ilog2(), a.len())
            .iter_as::<u64>()
            .collect::<Vec<_>>();

        if !num_block_is_even && b < Scalar::ZERO {
            let last_index = b_blocks.len() - 1;
            // We blindly padded with the ones, but as the num block is not even
            // the last packed block high part shall be 0 not 1s (i.e. no padding)
            b_blocks[last_index] %= self.message_modulus().0;
        }

        let b = b_blocks;
        let block_modulus = packed_modulus;
        let num_bits_in_block = block_modulus.ilog2();
        let grouping_size = num_bits_in_block as usize;

        let mut first_grouping_luts = Vec::with_capacity(grouping_size);
        let (invert_operands, invert_subtraction_result) = match compare {
            // The easiest case, nothing changes
            ComparisonKind::Less => (false, false),
            //     `a <= b`
            // <=> `not(b < a)`
            // <=> `not(does_sub_overflows(b, a))`
            ComparisonKind::LessOrEqual => (true, true),
            //     `a > b`
            // <=> `b < a`
            // <=> `does_sub_overflows(b, a)`
            ComparisonKind::Greater => (true, false),
            //     `a >= b`
            // <=> `b <= a`
            // <=> `not(a < b)`
            // <=> `not(does_sub_overflows(a, b))`
            ComparisonKind::GreaterOrEqual => (false, true),
        };

        // There is 1 packed block (i.e. there was at most 2 blocks originally)
        // we can take shortcut here
        if a.len() == 1 {
            let lut = if T::IS_SIGNED {
                let modulus = if num_block_is_even {
                    MessageModulus(packed_modulus)
                } else {
                    self.message_modulus()
                };
                self.key.generate_lookup_table(|x| {
                    let (x, y) = if invert_operands {
                        (b[0], x)
                    } else {
                        (x, b[0])
                    };

                    u64::from(invert_subtraction_result)
                        ^ is_x_less_than_y_given_input_borrow(x, y, 0, modulus)
                })
            } else {
                self.key.generate_lookup_table(|x| {
                    let (x, y) = if invert_operands {
                        (b[0], x)
                    } else {
                        (x, b[0])
                    };
                    let overflowed = x < y;
                    u64::from(invert_subtraction_result ^ overflowed)
                })
            };
            let result = self.key.apply_lookup_table(&a[0], &lut);
            return BooleanBlock::new_unchecked(result);
        }

        // Save some values for later
        let first_scalar_block = b[0];
        let last_scalar_block = b[b.len() - 1];

        let b: Vec<_> = b
            .into_iter()
            .map(|v| self.key.unchecked_create_trivial(v))
            .collect();

        let mut sub_blocks =
            if invert_operands {
                first_grouping_luts.push(self.key.generate_lookup_table(|first_block| {
                    u64::from(first_scalar_block < first_block)
                }));

                b.iter()
                    .zip(a.iter())
                    .map(|(lhs_b, rhs_b)| {
                        let mut result = lhs_b.clone();
                        // We don't want the correcting term
                        lwe_ciphertext_sub_assign(&mut result.ct, &rhs_b.ct);
                        result
                    })
                    .collect::<Vec<_>>()
            } else {
                first_grouping_luts.push(self.key.generate_lookup_table(|first_block| {
                    u64::from(first_block < first_scalar_block)
                }));

                a.iter()
                    .zip(b.iter())
                    .map(|(lhs_b, rhs_b)| {
                        let mut result = lhs_b.clone();
                        // We don't want the correcting term
                        lwe_ciphertext_sub_assign(&mut result.ct, &rhs_b.ct);
                        result
                    })
                    .collect::<Vec<_>>()
            };

        // The first lut, needs the encrypted block of `a`, not the subtraction
        // of `a[0]` and `b[0]`
        sub_blocks[0].clone_from(&a[0]);

        // We are going to group blocks and compute how each group propagates/generates a borrow
        //
        // Again, in unsigned representation the output borrow of the whole operation (i.e. the
        // borrow generated by the last group) tells us the result of the comparison. For signed
        // representation we need to XOR the overflow flag and the sign bit of the result.
        let block_states = {
            for i in 1..grouping_size {
                let state_fn = |block| {
                    let r = u64::MAX * u64::from(block != 0);
                    (r << (i - 1)) % (packed_modulus * 2)
                };
                first_grouping_luts.push(self.key.generate_lookup_table(state_fn));
            }

            let other_block_state_luts = (0..grouping_size)
                .map(|i| {
                    let state_fn = |block| {
                        let r = u64::MAX * u64::from(block != 0);
                        (r << i) % (packed_modulus * 2)
                    };
                    self.key.generate_lookup_table(state_fn)
                })
                .collect::<Vec<_>>();

            let block_states =
                // With unsigned ciphertexts as, overflow (i.e. does the last block needs to borrow)
                // directly translates to lhs < rhs we compute the blocks states for all the blocks
                //
                // For signed numbers, we need to do something more specific with the last block
                // thus, we don't compute the last block state
                sub_blocks[..sub_blocks.len() - usize::from(T::IS_SIGNED)]
                    .par_iter()
                    .enumerate()
                    .map(|(index, block)| {
                        let grouping_index = index / grouping_size;
                        let is_in_first_grouping = grouping_index == 0;
                        let index_in_grouping = index % (grouping_size);

                        let (luts, corrector) = if is_in_first_grouping {
                            (
                                &first_grouping_luts[index_in_grouping],
                                if index_in_grouping == 0 { 0 } else { 1 << (index_in_grouping - 1)}
                            )
                        } else {
                            (&other_block_state_luts[index_in_grouping], 1 << (index_in_grouping))
                        };

                        let mut result = self.key.apply_lookup_table(block, luts);
                        if index > 0 {
                            self.key.unchecked_scalar_add_assign(&mut result, corrector);
                        }
                        result
                    })
                    .collect::<Vec<_>>();

            block_states
        };

        // group borrows and simulator of last block
        let (
            (group_borrows, use_sequential_algorithm_to_resolve_grouping_carries),
            maybe_prepared_signed_check,
        ) = rayon::join(
            || {
                self.compute_group_borrow_state(
                    // May only invert if T is not signed
                    // As when there is only one group, in the unsigned case since overflow
                    // directly translate to lhs < rhs, we can ask the LUT used to do the
                    // inversion for us.
                    //
                    // In signed case as it's a bit more complex, we never want to
                    !T::IS_SIGNED && invert_subtraction_result,
                    grouping_size,
                    block_states,
                )
            },
            || {
                // When the ciphertexts are signed, finding whether lhs < rhs by doing a sub
                // is less direct than in unsigned where we can check for overflow.
                if T::IS_SIGNED && self.message_modulus().0 > 2 {
                    // Luckily, when the blocks have 4 bits, we can precompute and store in a block
                    // the 2 possible values for `lhs < rhs` depending on whether the last block
                    // will be borrowed from.
                    let modulus = if num_block_is_even {
                        MessageModulus(packed_modulus)
                    } else {
                        self.message_modulus()
                    };
                    let lut = self.key.generate_lookup_table(|last_block| {
                        let (x, y) = if invert_operands {
                            (last_scalar_block, last_block)
                        } else {
                            (last_block, last_scalar_block)
                        };
                        let b0 = is_x_less_than_y_given_input_borrow(x, y, 0, modulus);
                        let b1 = is_x_less_than_y_given_input_borrow(x, y, 1, modulus);
                        ((b1 << 1) | b0) << 2
                    });

                    Some(PreparedSignedCheck::Unified(
                        self.key.apply_lookup_table(a.last().unwrap(), &lut),
                    ))
                } else if T::IS_SIGNED {
                    let modulus = if num_block_is_even {
                        MessageModulus(packed_modulus)
                    } else {
                        self.message_modulus()
                    };
                    Some(PreparedSignedCheck::Split(rayon::join(
                        || {
                            let lut = self.key.generate_lookup_table(|last_block| {
                                let (x, y) = if invert_operands {
                                    (last_scalar_block, last_block)
                                } else {
                                    (last_block, last_scalar_block)
                                };
                                is_x_less_than_y_given_input_borrow(x, y, 1, modulus)
                            });
                            self.key.apply_lookup_table(a.last().unwrap(), &lut)
                        },
                        || {
                            let lut = self.key.generate_lookup_table(|last_block| {
                                let (x, y) = if invert_operands {
                                    (last_scalar_block, last_block)
                                } else {
                                    (last_block, last_scalar_block)
                                };
                                is_x_less_than_y_given_input_borrow(x, y, 0, modulus)
                            });
                            self.key.apply_lookup_table(a.last().unwrap(), &lut)
                        },
                    )))
                } else {
                    None
                }
            },
        );

        self.finish_comparison(
            group_borrows,
            grouping_size,
            use_sequential_algorithm_to_resolve_grouping_carries,
            maybe_prepared_signed_check,
            invert_subtraction_result,
        )
    }

    pub fn unchecked_scalar_gt_parallelized<T, Scalar>(&self, lhs: &T, rhs: Scalar) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
        Scalar: DecomposableInto<u64>,
    {
        self.scalar_compare(lhs, rhs, ComparisonKind::Greater)
    }

    pub fn unchecked_scalar_ge_parallelized<T, Scalar>(&self, lhs: &T, rhs: Scalar) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
        Scalar: DecomposableInto<u64>,
    {
        self.scalar_compare(lhs, rhs, ComparisonKind::GreaterOrEqual)
    }

    pub fn unchecked_scalar_lt_parallelized<T, Scalar>(&self, lhs: &T, rhs: Scalar) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
        Scalar: DecomposableInto<u64>,
    {
        self.scalar_compare(lhs, rhs, ComparisonKind::Less)
    }

    pub fn unchecked_scalar_le_parallelized<T, Scalar>(&self, lhs: &T, rhs: Scalar) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
        Scalar: DecomposableInto<u64>,
    {
        self.scalar_compare(lhs, rhs, ComparisonKind::LessOrEqual)
    }

    pub fn unchecked_scalar_max_parallelized<T, Scalar>(&self, lhs: &T, rhs: Scalar) -> T
    where
        T: IntegerRadixCiphertext,
        Scalar: DecomposableInto<u64>,
    {
        let is_superior = self.unchecked_scalar_gt_parallelized(lhs, rhs);
        let luts = BlockDecomposer::with_block_count(
            rhs,
            self.message_modulus().0.ilog2(),
            lhs.blocks().len(),
        )
        .iter_as::<u64>()
        .map(|scalar_block| {
            self.key
                .generate_lookup_table_bivariate(|is_superior, block| {
                    if is_superior == 1 {
                        block
                    } else {
                        scalar_block
                    }
                })
        })
        .collect::<Vec<_>>();

        let new_blocks = lhs
            .blocks()
            .par_iter()
            .zip(luts.par_iter())
            .map(|(block, lut)| {
                self.key
                    .unchecked_apply_lookup_table_bivariate(&is_superior.0, block, lut)
            })
            .collect::<Vec<_>>();

        T::from(new_blocks)
    }

    pub fn unchecked_scalar_min_parallelized<T, Scalar>(&self, lhs: &T, rhs: Scalar) -> T
    where
        T: IntegerRadixCiphertext,
        Scalar: DecomposableInto<u64>,
    {
        let is_inferior = self.unchecked_scalar_lt_parallelized(lhs, rhs);
        let luts = BlockDecomposer::with_block_count(
            rhs,
            self.message_modulus().0.ilog2(),
            lhs.blocks().len(),
        )
        .iter_as::<u64>()
        .map(|scalar_block| {
            self.key
                .generate_lookup_table_bivariate(|is_inferior, block| {
                    if is_inferior == 1 {
                        block
                    } else {
                        scalar_block
                    }
                })
        })
        .collect::<Vec<_>>();

        let new_blocks = lhs
            .blocks()
            .par_iter()
            .zip(luts.par_iter())
            .map(|(block, lut)| {
                self.key
                    .unchecked_apply_lookup_table_bivariate(&is_inferior.0, block, lut)
            })
            .collect::<Vec<_>>();

        T::from(new_blocks)
    }

    //===========================================================
    // Smart <, >, <=, >=, min, max
    //===========================================================

    pub fn smart_scalar_gt_parallelized<T, Scalar>(&self, lhs: &mut T, rhs: Scalar) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
        Scalar: DecomposableInto<u64>,
    {
        if !lhs.block_carries_are_empty() {
            self.full_propagate_parallelized(lhs);
        }

        self.unchecked_scalar_gt_parallelized(lhs, rhs)
    }

    pub fn smart_scalar_ge_parallelized<T, Scalar>(&self, lhs: &mut T, rhs: Scalar) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
        Scalar: DecomposableInto<u64>,
    {
        if !lhs.block_carries_are_empty() {
            self.full_propagate_parallelized(lhs);
        }

        self.unchecked_scalar_ge_parallelized(lhs, rhs)
    }

    pub fn smart_scalar_lt_parallelized<T, Scalar>(&self, lhs: &mut T, rhs: Scalar) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
        Scalar: DecomposableInto<u64>,
    {
        if !lhs.block_carries_are_empty() {
            self.full_propagate_parallelized(lhs);
        }

        self.unchecked_scalar_lt_parallelized(lhs, rhs)
    }

    pub fn smart_scalar_le_parallelized<T, Scalar>(&self, lhs: &mut T, rhs: Scalar) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
        Scalar: DecomposableInto<u64>,
    {
        if !lhs.block_carries_are_empty() {
            self.full_propagate_parallelized(lhs);
        }

        self.unchecked_scalar_le_parallelized(lhs, rhs)
    }

    pub fn smart_scalar_max_parallelized<T, Scalar>(&self, lhs: &mut T, rhs: Scalar) -> T
    where
        T: IntegerRadixCiphertext,
        Scalar: DecomposableInto<u64>,
    {
        if !lhs.block_carries_are_empty() {
            self.full_propagate_parallelized(lhs);
        }

        self.unchecked_scalar_max_parallelized(lhs, rhs)
    }

    pub fn smart_scalar_min_parallelized<T, Scalar>(&self, lhs: &mut T, rhs: Scalar) -> T
    where
        T: IntegerRadixCiphertext,
        Scalar: DecomposableInto<u64>,
    {
        if !lhs.block_carries_are_empty() {
            self.full_propagate_parallelized(lhs);
        }

        self.unchecked_scalar_min_parallelized(lhs, rhs)
    }

    //===========================================================
    // Default <, >, <=, >=, min, max
    //===========================================================

    pub fn scalar_gt_parallelized<T, Scalar>(&self, lhs: &T, rhs: Scalar) -> BooleanBlock
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
        self.unchecked_scalar_gt_parallelized(lhs, rhs)
    }

    pub fn scalar_ge_parallelized<T, Scalar>(&self, lhs: &T, rhs: Scalar) -> BooleanBlock
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
        self.unchecked_scalar_ge_parallelized(lhs, rhs)
    }

    pub fn scalar_lt_parallelized<T, Scalar>(&self, lhs: &T, rhs: Scalar) -> BooleanBlock
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
        self.unchecked_scalar_lt_parallelized(lhs, rhs)
    }

    pub fn scalar_le_parallelized<T, Scalar>(&self, lhs: &T, rhs: Scalar) -> BooleanBlock
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
        self.unchecked_scalar_le_parallelized(lhs, rhs)
    }

    pub fn scalar_max_parallelized<T, Scalar>(&self, lhs: &T, rhs: Scalar) -> T
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
        self.unchecked_scalar_max_parallelized(lhs, rhs)
    }

    pub fn scalar_min_parallelized<T, Scalar>(&self, lhs: &T, rhs: Scalar) -> T
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
        self.unchecked_scalar_min_parallelized(lhs, rhs)
    }
}
