use super::ServerKey;

use crate::integer::ciphertext::RadixCiphertext;
use crate::integer::server_key::comparator::Comparator;
use crate::shortint::PBSOrderMarker;

use rayon::prelude::*;

impl ServerKey {
    pub fn unchecked_eq_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        lhs: &RadixCiphertext<PBSOrder>,
        rhs: &RadixCiphertext<PBSOrder>,
    ) -> RadixCiphertext<PBSOrder> {
        // Even though the corresponding function
        // may already exist in self.key
        // we generate our own lut to do less allocations
        // one for all the threads as opposed to one per thread
        let lut = self
            .key
            .generate_accumulator_bivariate(|x, y| u64::from(x == y));
        let mut block_comparisons = lhs.blocks.clone();
        block_comparisons
            .par_iter_mut()
            .zip(rhs.blocks.par_iter())
            .for_each(|(lhs_block, rhs_block)| {
                self.key
                    .unchecked_apply_lookup_table_bivariate_assign(lhs_block, rhs_block, &lut);
            });

        let is_equal_result = self.are_all_comparisons_block_true(block_comparisons);

        let mut blocks = Vec::with_capacity(lhs.blocks.len());
        blocks.push(is_equal_result);
        blocks.resize_with(lhs.blocks.len(), || self.key.create_trivial(0));

        RadixCiphertext { blocks }
    }

    pub fn unchecked_ne_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        lhs: &RadixCiphertext<PBSOrder>,
        rhs: &RadixCiphertext<PBSOrder>,
    ) -> RadixCiphertext<PBSOrder> {
        // Even though the corresponding function
        // may already exist in self.key
        // we generate our own lut to do less allocations
        // one for all the threads as opposed to one per thread
        let lut = self
            .key
            .generate_accumulator_bivariate(|x, y| u64::from(x != y));
        let mut block_comparisons = lhs.blocks.clone();
        block_comparisons
            .par_iter_mut()
            .zip(rhs.blocks.par_iter())
            .for_each(|(lhs_block, rhs_block)| {
                self.key
                    .unchecked_apply_lookup_table_bivariate_assign(lhs_block, rhs_block, &lut);
            });

        let message_modulus = self.key.message_modulus.0;
        let carry_modulus = self.key.carry_modulus.0;
        let total_modulus = message_modulus * carry_modulus;
        let max_value = total_modulus - 1;

        let mut block_comparisons_2 = Vec::with_capacity(block_comparisons.len() / 2);
        let is_non_zero = self.key.generate_accumulator(|x| u64::from(x != 0));

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

        block_comparisons.resize_with(lhs.blocks.len(), || self.key.create_trivial(0));

        RadixCiphertext {
            blocks: block_comparisons,
        }
    }

    pub fn unchecked_gt_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        lhs: &RadixCiphertext<PBSOrder>,
        rhs: &RadixCiphertext<PBSOrder>,
    ) -> RadixCiphertext<PBSOrder> {
        Comparator::new(self).unchecked_gt_parallelized(lhs, rhs)
    }

    pub fn unchecked_ge_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        lhs: &RadixCiphertext<PBSOrder>,
        rhs: &RadixCiphertext<PBSOrder>,
    ) -> RadixCiphertext<PBSOrder> {
        Comparator::new(self).unchecked_ge_parallelized(lhs, rhs)
    }

    pub fn unchecked_lt_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        lhs: &RadixCiphertext<PBSOrder>,
        rhs: &RadixCiphertext<PBSOrder>,
    ) -> RadixCiphertext<PBSOrder> {
        Comparator::new(self).unchecked_lt_parallelized(lhs, rhs)
    }

    pub fn unchecked_le_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        lhs: &RadixCiphertext<PBSOrder>,
        rhs: &RadixCiphertext<PBSOrder>,
    ) -> RadixCiphertext<PBSOrder> {
        Comparator::new(self).unchecked_le_parallelized(lhs, rhs)
    }

    pub fn unchecked_max_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        lhs: &RadixCiphertext<PBSOrder>,
        rhs: &RadixCiphertext<PBSOrder>,
    ) -> RadixCiphertext<PBSOrder> {
        Comparator::new(self).unchecked_max_parallelized(lhs, rhs)
    }

    pub fn unchecked_min_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        lhs: &RadixCiphertext<PBSOrder>,
        rhs: &RadixCiphertext<PBSOrder>,
    ) -> RadixCiphertext<PBSOrder> {
        Comparator::new(self).unchecked_min_parallelized(lhs, rhs)
    }

    pub fn smart_eq_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        lhs: &mut RadixCiphertext<PBSOrder>,
        rhs: &mut RadixCiphertext<PBSOrder>,
    ) -> RadixCiphertext<PBSOrder> {
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

    pub fn smart_ne_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        lhs: &mut RadixCiphertext<PBSOrder>,
        rhs: &mut RadixCiphertext<PBSOrder>,
    ) -> RadixCiphertext<PBSOrder> {
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

    pub fn smart_gt_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        lhs: &mut RadixCiphertext<PBSOrder>,
        rhs: &mut RadixCiphertext<PBSOrder>,
    ) -> RadixCiphertext<PBSOrder> {
        Comparator::new(self).smart_gt_parallelized(lhs, rhs)
    }

    pub fn smart_ge_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        lhs: &mut RadixCiphertext<PBSOrder>,
        rhs: &mut RadixCiphertext<PBSOrder>,
    ) -> RadixCiphertext<PBSOrder> {
        Comparator::new(self).smart_ge_parallelized(lhs, rhs)
    }

    pub fn smart_lt_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        lhs: &mut RadixCiphertext<PBSOrder>,
        rhs: &mut RadixCiphertext<PBSOrder>,
    ) -> RadixCiphertext<PBSOrder> {
        Comparator::new(self).smart_lt_parallelized(lhs, rhs)
    }

    pub fn smart_le_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        lhs: &mut RadixCiphertext<PBSOrder>,
        rhs: &mut RadixCiphertext<PBSOrder>,
    ) -> RadixCiphertext<PBSOrder> {
        Comparator::new(self).smart_le_parallelized(lhs, rhs)
    }

    pub fn smart_max_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        lhs: &mut RadixCiphertext<PBSOrder>,
        rhs: &mut RadixCiphertext<PBSOrder>,
    ) -> RadixCiphertext<PBSOrder> {
        Comparator::new(self).smart_max_parallelized(lhs, rhs)
    }

    pub fn smart_min_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        lhs: &mut RadixCiphertext<PBSOrder>,
        rhs: &mut RadixCiphertext<PBSOrder>,
    ) -> RadixCiphertext<PBSOrder> {
        Comparator::new(self).smart_min_parallelized(lhs, rhs)
    }

    pub fn eq_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        lhs: &RadixCiphertext<PBSOrder>,
        rhs: &RadixCiphertext<PBSOrder>,
    ) -> RadixCiphertext<PBSOrder> {
        let mut tmp_lhs: RadixCiphertext<PBSOrder>;
        let mut tmp_rhs: RadixCiphertext<PBSOrder>;
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

    pub fn ne_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        lhs: &RadixCiphertext<PBSOrder>,
        rhs: &RadixCiphertext<PBSOrder>,
    ) -> RadixCiphertext<PBSOrder> {
        let mut tmp_lhs: RadixCiphertext<PBSOrder>;
        let mut tmp_rhs: RadixCiphertext<PBSOrder>;
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

    pub fn gt_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        lhs: &RadixCiphertext<PBSOrder>,
        rhs: &RadixCiphertext<PBSOrder>,
    ) -> RadixCiphertext<PBSOrder> {
        Comparator::new(self).gt_parallelized(lhs, rhs)
    }

    pub fn ge_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        lhs: &RadixCiphertext<PBSOrder>,
        rhs: &RadixCiphertext<PBSOrder>,
    ) -> RadixCiphertext<PBSOrder> {
        Comparator::new(self).ge_parallelized(lhs, rhs)
    }

    pub fn lt_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        lhs: &RadixCiphertext<PBSOrder>,
        rhs: &RadixCiphertext<PBSOrder>,
    ) -> RadixCiphertext<PBSOrder> {
        Comparator::new(self).lt_parallelized(lhs, rhs)
    }

    pub fn le_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        lhs: &RadixCiphertext<PBSOrder>,
        rhs: &RadixCiphertext<PBSOrder>,
    ) -> RadixCiphertext<PBSOrder> {
        Comparator::new(self).le_parallelized(lhs, rhs)
    }

    pub fn max_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        lhs: &RadixCiphertext<PBSOrder>,
        rhs: &RadixCiphertext<PBSOrder>,
    ) -> RadixCiphertext<PBSOrder> {
        Comparator::new(self).max_parallelized(lhs, rhs)
    }

    pub fn min_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        lhs: &RadixCiphertext<PBSOrder>,
        rhs: &RadixCiphertext<PBSOrder>,
    ) -> RadixCiphertext<PBSOrder> {
        Comparator::new(self).min_parallelized(lhs, rhs)
    }
}
