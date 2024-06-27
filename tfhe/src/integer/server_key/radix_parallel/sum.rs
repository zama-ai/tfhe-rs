use crate::integer::ciphertext::IntegerRadixCiphertext;
use crate::integer::{BooleanBlock, IntegerCiphertext, RadixCiphertext, ServerKey};
use crate::shortint::Ciphertext;
use rayon::prelude::*;
use std::ops::RangeInclusive;

impl ServerKey {
    /// Computes the sum of the ciphertexts in parallel.
    ///
    /// Returns a result that has non propagated carries
    pub(crate) fn unchecked_partial_sum_ciphertexts_vec_parallelized<T>(
        &self,
        terms: Vec<T>,
    ) -> Option<T>
    where
        T: IntegerRadixCiphertext,
    {
        if terms.is_empty() {
            return None;
        }

        if terms.len() == 1 {
            return Some(terms.into_iter().next().unwrap());
        }

        let num_blocks = terms[0].blocks().len();
        assert!(
            terms[1..].iter().all(|ct| ct.blocks().len() == num_blocks),
            "Not all ciphertexts have the same number of blocks"
        );

        if terms.len() == 2 {
            return Some(self.add_parallelized(&terms[0], &terms[1]));
        }

        assert!(
            terms
                .iter()
                .all(IntegerRadixCiphertext::block_carries_are_empty),
            "All ciphertexts must have empty carries"
        );

        // Pre-conditions and easy path are met, start the real work
        let message_modulus = self.key.message_modulus.0;
        let carry_modulus = self.key.carry_modulus.0;
        let total_modulus = message_modulus * carry_modulus;
        let message_max = message_modulus - 1;

        let num_elements_to_fill_carry = (total_modulus - 1) / message_max;

        // Re-organize radix terms into columns of blocks
        let mut columns = vec![vec![]; num_blocks];
        for term in terms {
            for (i, block) in term.into_blocks().into_iter().enumerate() {
                if block.degree.get() != 0 {
                    columns[i].push(block);
                }
            }
        }

        if columns.iter().all(Vec::is_empty) {
            return Some(self.create_trivial_radix(0, num_blocks));
        }

        let num_columns = columns.len();
        // Buffer in which we will store resulting columns after an iteration
        let mut columns_buffer = Vec::with_capacity(num_columns);
        let mut colum_output_buffer =
            vec![Vec::<(Ciphertext, Option<Ciphertext>)>::new(); num_blocks];

        let at_least_one_column_has_enough_elements = |columns: &[Vec<Ciphertext>]| {
            columns.iter().any(|c| c.len() > num_elements_to_fill_carry)
        };

        while at_least_one_column_has_enough_elements(&columns) {
            columns
                .par_drain(..)
                .zip(colum_output_buffer.par_iter_mut())
                .enumerate()
                .map(|(column_index, (mut column, out_buf))| {
                    if column.len() < num_elements_to_fill_carry {
                        return column;
                    }
                    column
                        .par_chunks_exact(num_elements_to_fill_carry)
                        .map(|chunk| {
                            let mut result = chunk[0].clone();
                            for c in &chunk[1..] {
                                self.key.unchecked_add_assign(&mut result, c);
                            }

                            if column_index < num_columns - 1 {
                                rayon::join(
                                    || self.key.message_extract(&result),
                                    || Some(self.key.carry_extract(&result)),
                                )
                            } else {
                                (self.key.message_extract(&result), None)
                            }
                        })
                        .collect_into_vec(out_buf);

                    let num_elem_in_rest = column.len() % num_elements_to_fill_carry;
                    column.rotate_right(num_elem_in_rest);
                    column.truncate(num_elem_in_rest);
                    column
                })
                .collect_into_vec(&mut columns_buffer);

            std::mem::swap(&mut columns, &mut columns_buffer);

            // Move resulting message and carry blocks where they belong
            for (i, column_output) in colum_output_buffer.iter_mut().enumerate() {
                for (msg, maybe_carry) in column_output.drain(..) {
                    columns[i].push(msg);

                    if let (Some(carry), true) = (maybe_carry, (i + 1) < columns.len()) {
                        columns[i + 1].push(carry);
                    }
                }
            }
        }

        // Reconstruct a radix from the columns
        let blocks = columns
            .into_iter()
            .map(|mut column| {
                if column.is_empty() {
                    self.key.create_trivial(0)
                } else {
                    let (first_block, other_blocks) =
                        column.as_mut_slice().split_first_mut().unwrap();
                    for other in other_blocks {
                        self.key.unchecked_add_assign(first_block, other);
                    }
                    column.swap_remove(0)
                }
            })
            .collect::<Vec<_>>();
        assert_eq!(blocks.len(), num_blocks);

        Some(T::from_blocks(blocks))
    }

    /// Computes the sum of the ciphertexts in parallel.
    ///
    /// - Returns None if ciphertexts is empty
    ///
    /// - Expects all ciphertexts to have empty carries
    /// - Expects all ciphertexts to have the same size
    pub fn unchecked_sum_ciphertexts_vec_parallelized<T>(&self, ciphertexts: Vec<T>) -> Option<T>
    where
        T: IntegerRadixCiphertext,
    {
        let mut result = self.unchecked_partial_sum_ciphertexts_vec_parallelized(ciphertexts)?;

        self.full_propagate_parallelized(&mut result);
        assert!(result.block_carries_are_empty());

        Some(result)
    }

    /// See [Self::unchecked_sum_ciphertexts_vec_parallelized]
    pub fn unchecked_sum_ciphertexts_parallelized<'a, T, C>(&self, ciphertexts: C) -> Option<T>
    where
        C: IntoIterator<Item = &'a T>,
        T: IntegerRadixCiphertext + 'a,
    {
        let ciphertexts = ciphertexts.into_iter().map(Clone::clone).collect();
        self.unchecked_sum_ciphertexts_vec_parallelized(ciphertexts)
    }

    /// Computes the sum of the ciphertexts in parallel.
    ///
    /// - Returns None if ciphertexts is empty
    ///
    /// See [Self::unchecked_sum_ciphertexts_parallelized] for constraints
    pub fn sum_ciphertexts_parallelized<'a, T, C>(&self, ciphertexts: C) -> Option<T>
    where
        C: IntoIterator<Item = &'a T>,
        T: IntegerRadixCiphertext + 'a,
    {
        let mut ciphertexts = ciphertexts
            .into_iter()
            .map(Clone::clone)
            .collect::<Vec<T>>();
        ciphertexts
            .par_iter_mut()
            .filter(|ct| ct.block_carries_are_empty())
            .for_each(|ct| {
                if !ct.block_carries_are_empty() {
                    self.full_propagate_parallelized(&mut *ct);
                }
            });

        self.unchecked_sum_ciphertexts_vec_parallelized(ciphertexts)
    }

    /// Computes the sum of the ciphertexts in parallel.
    ///
    /// - Returns None if ciphertexts is empty
    ///
    /// See [Self::unchecked_sum_ciphertexts_parallelized] for constraints
    pub fn smart_sum_ciphertexts_parallelized<T, C>(&self, mut ciphertexts: C) -> Option<T>
    where
        C: AsMut<[T]> + AsRef<[T]>,
        T: IntegerRadixCiphertext,
    {
        ciphertexts.as_mut().par_iter_mut().for_each(|ct| {
            if !ct.block_carries_are_empty() {
                self.full_propagate_parallelized(ct);
            }
        });

        self.unchecked_sum_ciphertexts_parallelized(ciphertexts.as_ref())
    }

    /// This sums all ciphertext contained in the chunk into the first element of the chunk
    /// i.e: [A, B, C] -> [A + B + C, B, C]
    /// and returns the inclusive range indicating the range of blocks which where addition were
    /// made that is, if the ciphertexts contains trailing (end or start) trivial zeros some
    /// addition will be skipped (as adding a bunch of zeros is not useful)
    fn unchecked_sum_ciphertext_chunk<T>(&self, chunk: &mut [T]) -> RangeInclusive<usize>
    where
        T: IntegerRadixCiphertext,
    {
        assert_ne!(chunk.len(), 0);
        if chunk.len() <= 1 {
            return 0..=0;
        }
        let num_blocks = chunk[0].blocks().len();
        let (s, rest) = chunk.split_first_mut().unwrap();
        let mut first_block_where_addition_happened = num_blocks - 1;
        let mut last_block_where_addition_happened = 0;
        for a in rest.iter() {
            let first_block_to_add = a
                .blocks()
                .iter()
                .position(|block| block.degree.get() != 0)
                .unwrap_or(num_blocks);
            first_block_where_addition_happened =
                first_block_where_addition_happened.min(first_block_to_add);
            let last_block_to_add = a
                .blocks()
                .iter()
                .rev()
                .position(|block| block.degree.get() != 0)
                .map_or(num_blocks - 1, |pos| num_blocks - pos - 1);
            last_block_where_addition_happened =
                last_block_where_addition_happened.max(last_block_to_add);
            for (ct_left_i, ct_right_i) in &mut s.blocks_mut()
                [first_block_to_add..last_block_to_add + 1]
                .iter_mut()
                .zip(a.blocks()[first_block_to_add..last_block_to_add + 1].iter())
            {
                self.key.unchecked_add_assign(ct_left_i, ct_right_i);
            }
        }

        first_block_where_addition_happened..=last_block_where_addition_happened
    }

    /// - Expects all ciphertexts to have empty carries
    /// - Expects all ciphertexts to have the same size
    pub fn unchecked_unsigned_overflowing_sum_ciphertexts_vec_parallelized(
        &self,
        mut ciphertexts: Vec<RadixCiphertext>,
    ) -> Option<(RadixCiphertext, BooleanBlock)> {
        if ciphertexts.is_empty() {
            return None;
        }

        if ciphertexts.len() == 1 {
            return Some((
                ciphertexts.pop().unwrap(),
                BooleanBlock::new_unchecked(self.key.create_trivial(0)),
            ));
        }

        let num_blocks = ciphertexts[0].blocks().len();
        assert!(
            ciphertexts[1..]
                .iter()
                .all(|ct| ct.blocks().len() == num_blocks),
            "Not all ciphertexts have the same number of blocks"
        );

        if ciphertexts.len() == 2 {
            return Some(
                self.unsigned_overflowing_add_parallelized(&ciphertexts[0], &ciphertexts[1]),
            );
        }

        assert!(
            ciphertexts
                .iter()
                .all(IntegerRadixCiphertext::block_carries_are_empty),
            "All ciphertexts must have empty carries"
        );

        let num_blocks = ciphertexts[0].blocks.len();
        assert!(
            ciphertexts[1..]
                .iter()
                .all(|ct| ct.blocks.len() == num_blocks),
            "Not all ciphertexts have the same number of blocks"
        );
        assert!(
            ciphertexts
                .iter()
                .all(RadixCiphertext::block_carries_are_empty),
            "All ciphertexts must have empty carries"
        );

        let message_modulus = self.key.message_modulus.0;
        let carry_modulus = self.key.carry_modulus.0;
        let total_modulus = message_modulus * carry_modulus;
        let message_max = message_modulus - 1;

        let num_elements_to_fill_carry = (total_modulus - 1) / message_max;

        let mut tmp_out = Vec::new();

        let mut carries = Vec::<Ciphertext>::new();
        while ciphertexts.len() > num_elements_to_fill_carry {
            let mut chunks_iter = ciphertexts.par_chunks_exact_mut(num_elements_to_fill_carry);
            let remainder_len = chunks_iter.remainder().len();

            chunks_iter
                .map(|chunk| {
                    let addition_range = self.unchecked_sum_ciphertext_chunk(chunk);
                    let s = &mut chunk[0];

                    let mut carry_ct = s.clone();
                    rayon::join(
                        || {
                            s.blocks[addition_range.clone()]
                                .par_iter_mut()
                                .for_each(|block| {
                                    self.key.message_extract_assign(block);
                                });
                        },
                        || {
                            // Contrary to non overflowing version we always extract all carries
                            // as we need to track overflows
                            carry_ct.blocks[addition_range.clone()]
                                .par_iter_mut()
                                .for_each(|block| {
                                    self.key.carry_extract_assign(block);
                                });
                            // Blocks for which we do not extract carries, means carry value is 0
                            for block in &mut carry_ct.blocks[..*addition_range.start()] {
                                self.key.create_trivial_assign(block, 0);
                            }
                            for block in &mut carry_ct.blocks[*addition_range.end() + 1..] {
                                self.key.create_trivial_assign(block, 0);
                            }
                        },
                    );

                    let out_carry = if *addition_range.end() == num_blocks - 1 {
                        let carry = carry_ct.blocks[num_blocks - 1].clone();
                        self.key
                            .create_trivial_assign(carry_ct.blocks.last_mut().unwrap(), 0);
                        carry
                    } else {
                        self.key.create_trivial(0)
                    };
                    carry_ct.blocks.rotate_right(1);

                    (s.clone(), carry_ct, out_carry)
                })
                .collect_into_vec(&mut tmp_out);

            // tmp_out elements are tuple of 3 elements (message, carry, last_block_carry)
            let num_ct_created = tmp_out.len() * 2;
            // Ciphertexts not treated in this iteration are at the end of ciphertexts vec.
            // the rotation will make them 'wrap around' and be placed at range index
            // (num_ct_created..remainder_len + num_ct_created)
            // We will then fill the indices in range (0..num_ct_created)
            ciphertexts.rotate_right(remainder_len + num_ct_created);

            // Drain elements out of tmp_out to replace them
            // at the beginning of the ciphertexts left to add
            for (i, (m, c, out_carry)) in tmp_out.drain(..).enumerate() {
                ciphertexts[i * 2] = m;
                ciphertexts[(i * 2) + 1] = c;
                carries.push(out_carry);
            }
            ciphertexts.truncate(num_ct_created + remainder_len);
        }

        // Now we will add the last chunk of terms
        // just as was done above, however we do it
        // we want to use an addition that leaves
        // the resulting ciphertext with empty carries
        let (result, rest) = ciphertexts.split_first_mut().unwrap();
        for term in rest.iter() {
            self.unchecked_add_assign(result, term);
        }

        let (message_blocks, carry_blocks) = rayon::join(
            || {
                result
                    .blocks
                    .par_iter()
                    .map(|block| self.key.message_extract(block))
                    .collect::<Vec<_>>()
            },
            || {
                let mut carry_blocks = Vec::with_capacity(num_blocks);
                result
                    .blocks
                    .par_iter()
                    .map(|block| self.key.carry_extract(block))
                    .collect_into_vec(&mut carry_blocks);
                carries.push(carry_blocks.pop().unwrap());
                carry_blocks.insert(0, self.key.create_trivial(0));
                carry_blocks
            },
        );

        let ((result, overflowed), any_sum_overflowed) = rayon::join(
            || {
                let mut result = RadixCiphertext::from(message_blocks);
                let carry = RadixCiphertext::from(carry_blocks);
                let overflowed =
                    self.unsigned_overflowing_add_assign_parallelized(&mut result, &carry);
                assert!(result.block_carries_are_empty());
                (result, overflowed)
            },
            || {
                let mut carries = RadixCiphertext::from(carries);
                carries.blocks.retain(|block| block.degree.get() != 0);
                self.scalar_ne_parallelized(&carries, 0)
            },
        );

        let overflowed = self.boolean_bitor(&overflowed, &any_sum_overflowed);

        Some((result, overflowed))
    }

    /// Computes the sum of the unsigned ciphertexts in parallel.
    /// Returns a boolean indicating if the sum overflowed, that is,
    /// the result did not fit in a ciphertext.
    ///
    /// See [Self::unchecked_sum_ciphertexts_vec_parallelized]
    pub fn unchecked_unsigned_overflowing_sum_ciphertexts_parallelized<'a, C>(
        &self,
        ciphertexts: C,
    ) -> Option<(RadixCiphertext, BooleanBlock)>
    where
        C: IntoIterator<Item = &'a RadixCiphertext>,
    {
        let ciphertexts = ciphertexts.into_iter().map(Clone::clone).collect();
        self.unchecked_unsigned_overflowing_sum_ciphertexts_vec_parallelized(ciphertexts)
    }

    /// Computes the sum of the unsigned ciphertexts in parallel.
    /// Returns a boolean indicating if the sum overflowed, that is,
    /// the result did not fit in a ciphertext.
    ///
    /// - Returns None if ciphertexts is empty
    ///
    /// See [Self::unchecked_sum_ciphertexts_parallelized] for constraints
    pub fn unsigned_overflowing_sum_ciphertexts_parallelized<'a, C>(
        &self,
        ciphertexts: C,
    ) -> Option<(RadixCiphertext, BooleanBlock)>
    where
        C: IntoIterator<Item = &'a RadixCiphertext>,
    {
        let mut ciphertexts = ciphertexts
            .into_iter()
            .map(Clone::clone)
            .collect::<Vec<_>>();
        ciphertexts
            .par_iter_mut()
            .filter(|ct| ct.block_carries_are_empty())
            .for_each(|ct| {
                if !ct.block_carries_are_empty() {
                    self.full_propagate_parallelized(&mut *ct);
                }
            });

        self.unchecked_unsigned_overflowing_sum_ciphertexts_vec_parallelized(ciphertexts)
    }

    /// Computes the sum of the unsigned ciphertexts in parallel.
    /// Returns a boolean indicating if the sum overflowed, that is,
    /// the result did not fit in a ciphertext.
    ///
    /// - Returns None if ciphertexts is empty
    ///
    /// See [Self::unchecked_sum_ciphertexts_parallelized] for constraints
    pub fn smart_unsigned_overflowing_sum_ciphertexts_parallelized<C>(
        &self,
        mut ciphertexts: C,
    ) -> Option<(RadixCiphertext, BooleanBlock)>
    where
        C: AsMut<[RadixCiphertext]> + AsRef<[RadixCiphertext]>,
    {
        ciphertexts.as_mut().par_iter_mut().for_each(|ct| {
            if !ct.block_carries_are_empty() {
                self.full_propagate_parallelized(ct);
            }
        });

        self.unchecked_unsigned_overflowing_sum_ciphertexts_parallelized(ciphertexts.as_ref())
    }
}
