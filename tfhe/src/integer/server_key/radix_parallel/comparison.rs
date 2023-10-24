use super::ServerKey;

use crate::integer::ciphertext::IntegerRadixCiphertext;
use crate::integer::server_key::comparator::Comparator;

use crate::integer::ciphertext::boolean_value::BooleanBlock;
use rayon::prelude::*;

impl ServerKey {
    pub fn unchecked_eq_parallelized<T>(&self, lhs: &T, rhs: &T) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
    {
        // Even though the corresponding function
        // may already exist in self.key
        // we generate our own lut to do less allocations
        // one for all the threads as opposed to one per thread
        let lut = self
            .key
            .generate_lookup_table_bivariate(|x, y| u64::from(x == y));
        let mut block_comparisons = lhs.blocks().to_vec();
        block_comparisons
            .par_iter_mut()
            .zip(rhs.blocks().par_iter())
            .for_each(|(lhs_block, rhs_block)| {
                self.key
                    .unchecked_apply_lookup_table_bivariate_assign(lhs_block, rhs_block, &lut);
            });

        let is_equal_result = self.are_all_comparisons_block_true(block_comparisons);

        BooleanBlock::new_unchecked(is_equal_result)
    }

    pub fn unchecked_ne_parallelized<T>(&self, lhs: &T, rhs: &T) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
    {
        // Even though the corresponding function
        // may already exist in self.key
        // we generate our own lut to do less allocations
        // one for all the threads as opposed to one per thread
        let lut = self
            .key
            .generate_lookup_table_bivariate(|x, y| u64::from(x != y));
        let mut block_comparisons = lhs.blocks().to_vec();
        block_comparisons
            .par_iter_mut()
            .zip(rhs.blocks().par_iter())
            .for_each(|(lhs_block, rhs_block)| {
                self.key
                    .unchecked_apply_lookup_table_bivariate_assign(lhs_block, rhs_block, &lut);
            });

        let message_modulus = self.key.message_modulus.0;
        let carry_modulus = self.key.carry_modulus.0;
        let total_modulus = message_modulus * carry_modulus;
        let max_value = total_modulus - 1;

        let mut block_comparisons_2 = Vec::with_capacity(block_comparisons.len() / 2);
        let is_non_zero = self.key.generate_lookup_table(|x| u64::from(x != 0));

        while block_comparisons.len() > 1 {
            block_comparisons
                .par_chunks(max_value)
                .map(|blocks| {
                    let mut sum = blocks[0].clone();
                    for other_block in &blocks[1..] {
                        self.key.unchecked_add_assign(&mut sum, other_block);
                    }
                    self.key.apply_lookup_table(&sum, &is_non_zero)
                })
                .collect_into_vec(&mut block_comparisons_2);
            std::mem::swap(&mut block_comparisons_2, &mut block_comparisons);
        }

        BooleanBlock::new_unchecked(
            block_comparisons
                .into_iter()
                .next()
                .unwrap_or_else(|| self.key.create_trivial(0)),
        )
    }

    pub fn unchecked_gt_parallelized<T>(&self, lhs: &T, rhs: &T) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
    {
        Comparator::new(self).unchecked_gt_parallelized(lhs, rhs)
    }

    pub fn unchecked_ge_parallelized<T>(&self, lhs: &T, rhs: &T) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
    {
        Comparator::new(self).unchecked_ge_parallelized(lhs, rhs)
    }

    pub fn unchecked_lt_parallelized<T>(&self, lhs: &T, rhs: &T) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
    {
        Comparator::new(self).unchecked_lt_parallelized(lhs, rhs)
    }

    pub fn unchecked_le_parallelized<T>(&self, lhs: &T, rhs: &T) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
    {
        Comparator::new(self).unchecked_le_parallelized(lhs, rhs)
    }

    pub fn unchecked_max_parallelized<T>(&self, lhs: &T, rhs: &T) -> T
    where
        T: IntegerRadixCiphertext,
    {
        Comparator::new(self).unchecked_max_parallelized(lhs, rhs)
    }

    pub fn unchecked_min_parallelized<T>(&self, lhs: &T, rhs: &T) -> T
    where
        T: IntegerRadixCiphertext,
    {
        Comparator::new(self).unchecked_min_parallelized(lhs, rhs)
    }

    pub fn smart_eq_parallelized<T>(&self, lhs: &mut T, rhs: &mut T) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
    {
        rayon::join(
            || {
                if !lhs.block_carries_are_empty() {
                    self.full_propagate_parallelized(lhs);
                }
            },
            || {
                if !rhs.block_carries_are_empty() {
                    self.full_propagate_parallelized(rhs);
                }
            },
        );
        self.unchecked_eq_parallelized(lhs, rhs)
    }

    pub fn smart_ne_parallelized<T>(&self, lhs: &mut T, rhs: &mut T) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
    {
        rayon::join(
            || {
                if !lhs.block_carries_are_empty() {
                    self.full_propagate_parallelized(lhs);
                }
            },
            || {
                if !rhs.block_carries_are_empty() {
                    self.full_propagate_parallelized(rhs);
                }
            },
        );
        self.unchecked_ne_parallelized(lhs, rhs)
    }

    pub fn smart_gt_parallelized<T>(&self, lhs: &mut T, rhs: &mut T) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
    {
        Comparator::new(self).smart_gt_parallelized(lhs, rhs)
    }

    pub fn smart_ge_parallelized<T>(&self, lhs: &mut T, rhs: &mut T) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
    {
        Comparator::new(self).smart_ge_parallelized(lhs, rhs)
    }

    pub fn smart_lt_parallelized<T>(&self, lhs: &mut T, rhs: &mut T) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
    {
        Comparator::new(self).smart_lt_parallelized(lhs, rhs)
    }

    pub fn smart_le_parallelized<T>(&self, lhs: &mut T, rhs: &mut T) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
    {
        Comparator::new(self).smart_le_parallelized(lhs, rhs)
    }

    pub fn smart_max_parallelized<T>(&self, lhs: &mut T, rhs: &mut T) -> T
    where
        T: IntegerRadixCiphertext,
    {
        Comparator::new(self).smart_max_parallelized(lhs, rhs)
    }

    pub fn smart_min_parallelized<T>(&self, lhs: &mut T, rhs: &mut T) -> T
    where
        T: IntegerRadixCiphertext,
    {
        Comparator::new(self).smart_min_parallelized(lhs, rhs)
    }

    pub fn eq_parallelized<T>(&self, lhs: &T, rhs: &T) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
    {
        let mut tmp_lhs;
        let mut tmp_rhs;
        let (lhs, rhs) = match (lhs.block_carries_are_empty(), rhs.block_carries_are_empty()) {
            (true, true) => (lhs, rhs),
            (true, false) => {
                tmp_rhs = rhs.clone();
                self.full_propagate_parallelized(&mut tmp_rhs);
                (lhs, &tmp_rhs)
            }
            (false, true) => {
                tmp_lhs = lhs.clone();
                self.full_propagate_parallelized(&mut tmp_lhs);
                (&tmp_lhs, rhs)
            }
            (false, false) => {
                tmp_lhs = lhs.clone();
                tmp_rhs = rhs.clone();
                rayon::join(
                    || self.full_propagate_parallelized(&mut tmp_lhs),
                    || self.full_propagate_parallelized(&mut tmp_rhs),
                );
                (&tmp_lhs, &tmp_rhs)
            }
        };

        self.unchecked_eq_parallelized(lhs, rhs)
    }

    pub fn ne_parallelized<T>(&self, lhs: &T, rhs: &T) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
    {
        let mut tmp_lhs;
        let mut tmp_rhs;
        let (lhs, rhs) = match (lhs.block_carries_are_empty(), rhs.block_carries_are_empty()) {
            (true, true) => (lhs, rhs),
            (true, false) => {
                tmp_rhs = rhs.clone();
                self.full_propagate_parallelized(&mut tmp_rhs);
                (lhs, &tmp_rhs)
            }
            (false, true) => {
                tmp_lhs = lhs.clone();
                self.full_propagate_parallelized(&mut tmp_lhs);
                (&tmp_lhs, rhs)
            }
            (false, false) => {
                tmp_lhs = lhs.clone();
                tmp_rhs = rhs.clone();
                rayon::join(
                    || self.full_propagate_parallelized(&mut tmp_lhs),
                    || self.full_propagate_parallelized(&mut tmp_rhs),
                );
                (&tmp_lhs, &tmp_rhs)
            }
        };

        self.unchecked_ne_parallelized(lhs, rhs)
    }

    pub fn gt_parallelized<T>(&self, lhs: &T, rhs: &T) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
    {
        Comparator::new(self).gt_parallelized(lhs, rhs)
    }

    pub fn ge_parallelized<T>(&self, lhs: &T, rhs: &T) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
    {
        Comparator::new(self).ge_parallelized(lhs, rhs)
    }

    pub fn lt_parallelized<T>(&self, lhs: &T, rhs: &T) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
    {
        Comparator::new(self).lt_parallelized(lhs, rhs)
    }

    pub fn le_parallelized<T>(&self, lhs: &T, rhs: &T) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
    {
        Comparator::new(self).le_parallelized(lhs, rhs)
    }

    pub fn max_parallelized<T>(&self, lhs: &T, rhs: &T) -> T
    where
        T: IntegerRadixCiphertext,
    {
        Comparator::new(self).max_parallelized(lhs, rhs)
    }

    pub fn min_parallelized<T>(&self, lhs: &T, rhs: &T) -> T
    where
        T: IntegerRadixCiphertext,
    {
        Comparator::new(self).min_parallelized(lhs, rhs)
    }
}
