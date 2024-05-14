use crate::integer::{BooleanBlock, IntegerRadixCiphertext, ServerKey};

use rayon::prelude::*;

impl ServerKey {
    /// Compares two slices containing ciphertexts and returns an encryption of `true` if all
    /// pairs are equal, otherwise, returns an encryption of `false`.
    ///
    /// - If slices do not have the same length, false is returned
    /// - If at least one  pair (`lhs[i]`, `rhs[i]`) do not have the same number of blocks, false is
    ///   returned
    pub fn unchecked_all_eq_slices_parallelized<T>(&self, lhs: &[T], rhs: &[T]) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
    {
        if lhs.len() != rhs.len() {
            return self.create_trivial_boolean_block(false);
        }

        if lhs
            .iter()
            .zip(rhs.iter())
            .any(|(l, r)| l.blocks().len() != r.blocks().len())
        {
            return self.create_trivial_boolean_block(false);
        }

        let block_equality_lut = self
            .key
            .generate_lookup_table_bivariate(|l, r| u64::from(l == r));

        let comparison_blocks = lhs
            .par_iter()
            .zip(rhs.par_iter())
            .flat_map(|(l, r)| {
                l.blocks()
                    .par_iter()
                    .zip(r.blocks().par_iter())
                    .map(|(lb, rb)| {
                        self.key
                            .unchecked_apply_lookup_table_bivariate(lb, rb, &block_equality_lut)
                    })
            })
            .collect::<Vec<_>>();

        let result = self.are_all_comparisons_block_true(comparison_blocks);
        BooleanBlock::new_unchecked(result)
    }

    /// Compares two slices containing ciphertexts and returns an encryption of `true` if all
    /// pairs are equal, otherwise, returns an encryption of `false`.
    ///
    /// - If slices do not have the same length, false is returned
    /// - If at least one  pair (`lhs[i]`, `rhs[i]`) do not have the same number of blocks, false is
    ///   returned
    pub fn smart_all_eq_slices_parallelized<T>(&self, lhs: &mut [T], rhs: &mut [T]) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
    {
        lhs.par_iter_mut()
            .chain(rhs.par_iter_mut())
            .filter(|ct| !ct.block_carries_are_empty())
            .for_each(|ct| self.full_propagate_parallelized(ct));
        self.unchecked_all_eq_slices_parallelized(lhs, rhs)
    }

    /// Compares two slices containing ciphertexts and returns an encryption of `true` if all
    /// pairs are equal, otherwise, returns an encryption of `false`.
    ///
    /// - If slices do not have the same length, false is returned
    /// - If at least one  pair (`lhs[i]`, `rhs[i]`) do not have the same number of blocks, false is
    ///   returned
    pub fn all_eq_slices_parallelized<T>(&self, lhs: &[T], rhs: &[T]) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
    {
        let mut lhs_clone = vec![];
        let mut rhs_clone = vec![];
        let (lhs, rhs) = rayon::join(
            || {
                if lhs.iter().any(|ct| !ct.block_carries_are_empty()) {
                    lhs_clone = lhs.to_vec();
                    lhs_clone
                        .par_iter_mut()
                        .filter(|ct| !ct.block_carries_are_empty())
                        .for_each(|ct| self.full_propagate_parallelized(ct));
                    &lhs_clone
                } else {
                    lhs
                }
            },
            || {
                if rhs.iter().any(|ct| !ct.block_carries_are_empty()) {
                    rhs_clone = rhs.to_vec();
                    rhs_clone
                        .par_iter_mut()
                        .filter(|ct| !ct.block_carries_are_empty())
                        .for_each(|ct| self.full_propagate_parallelized(ct));
                    &rhs_clone
                } else {
                    rhs
                }
            },
        );

        self.unchecked_all_eq_slices_parallelized(lhs, rhs)
    }

    /// Returns a boolean ciphertext encrypting `true` if `lhs` contains `rhs`, `false` otherwise
    pub fn unchecked_contains_sub_slice_parallelized<T>(&self, lhs: &[T], rhs: &[T]) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
    {
        if rhs.len() > lhs.len() {
            return self.create_trivial_boolean_block(false);
        }

        let windows_results = lhs
            .par_windows(rhs.len())
            .map(|lhs_sub_slice| {
                self.unchecked_all_eq_slices_parallelized(lhs_sub_slice, rhs)
                    .0
            })
            .collect::<Vec<_>>();

        BooleanBlock::new_unchecked(self.is_at_least_one_comparisons_block_true(windows_results))
    }

    /// Returns a boolean ciphertext encrypting `true` if `lhs` contains `rhs`, `false` otherwise
    pub fn smart_contains_sub_slice_parallelized<T>(
        &self,
        lhs: &mut [T],
        rhs: &mut [T],
    ) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
    {
        lhs.par_iter_mut()
            .chain(rhs.par_iter_mut())
            .filter(|radix| !radix.block_carries_are_empty())
            .for_each(|radix| {
                self.full_propagate_parallelized(radix);
            });

        self.unchecked_contains_sub_slice_parallelized(lhs, rhs)
    }

    /// Returns a boolean ciphertext encrypting `true` if `lhs` contains `rhs`, `false` otherwise
    pub fn contains_sub_slice_parallelized<T>(&self, lhs: &[T], rhs: &[T]) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
    {
        let full_propagate_slice = |slice: &mut [T]| {
            slice
                .par_iter_mut()
                .filter(|radix| !radix.block_carries_are_empty())
                .for_each(|radix| {
                    self.full_propagate_parallelized(radix);
                });
        };
        let mut tmp_lhs;
        let mut tmp_rhs;

        let lhs = if lhs.iter().all(T::block_carries_are_empty) {
            lhs
        } else {
            tmp_lhs = lhs.to_vec();
            full_propagate_slice(&mut tmp_lhs);
            tmp_lhs.as_slice()
        };

        let rhs = if rhs.iter().all(T::block_carries_are_empty) {
            rhs
        } else {
            tmp_rhs = rhs.to_vec();
            full_propagate_slice(&mut tmp_rhs);
            tmp_rhs.as_slice()
        };

        self.unchecked_contains_sub_slice_parallelized(lhs, rhs)
    }
}
