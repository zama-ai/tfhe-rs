use crate::core_crypto::prelude::UnsignedInteger;
use crate::integer::block_decomposition::{BlockDecomposer, Decomposable, DecomposableInto};
use crate::integer::{BooleanBlock, IntegerRadixCiphertext, RadixCiphertext, ServerKey};
use crate::prelude::CastInto;
use crate::shortint::Ciphertext;
use itertools::Itertools;
use rayon::prelude::*;
use std::collections::HashSet;
use std::hash::Hash;
use std::ops::Range;

/// MatchValues for the `match_value_parallelized` family of function
///
/// This ensures the uniqueness of the inputs
///
/// Outputs are not required to be unique
/// Input values are not required to span all possible values that
/// ` ct` could hold.
#[derive(Debug)]
pub struct MatchValues<Clear>(Vec<(Clear, Clear)>);

impl<Clear> MatchValues<Clear> {
    /// Builds a `MatchValues` from a Vec of tuple where in each tuple element,
    /// the index `.0` is the input and index `.1` is the associated output.
    ///
    /// This checks that all `.0` elements are unique
    pub fn new(matches: Vec<(Clear, Clear)>) -> crate::Result<Self>
    where
        Clear: Eq + Hash,
    {
        let mut set = HashSet::with_capacity(matches.len());
        for (input, _) in &matches {
            if !set.insert(input) {
                return Err(crate::Error::new(
                    "Input values in a MatchValues must be unique".to_string(),
                ));
            }
        }

        Ok(Self(matches))
    }

    /// Builds a `MatchValues` by applying the given function over the given range
    pub fn from_fn_and_range<F>(func: F, range: Range<Clear>) -> Self
    where
        Clear: Copy,
        Range<Clear>: Iterator<Item = Clear>,
        F: Fn(Clear) -> Clear,
    {
        let matches = range.map(|input| (input, func(input))).collect();
        Self(matches)
    }
    // Public method to access the private field
    pub fn get_values(&self) -> &Vec<(Clear, Clear)> {
        &self.0
    }
}

impl ServerKey {
    /// `match` an input value to an output value
    ///
    /// - Input values are not required to span all possible values that `ct` could hold.
    ///
    /// - The output radix has a number of blocks that depends on the maximum possible output value
    ///   from the `MatchValues`
    ///
    /// Returns a boolean block that encrypts `true` if the input `ct`
    /// matched one of the possible inputs
    pub fn unchecked_match_value_parallelized<Clear>(
        &self,
        ct: &RadixCiphertext,
        matches: &MatchValues<Clear>,
    ) -> (RadixCiphertext, BooleanBlock)
    where
        Clear: UnsignedInteger + DecomposableInto<u64> + CastInto<usize>,
    {
        if matches.0.is_empty() {
            return (
                self.create_trivial_radix(0, 1),
                self.create_trivial_boolean_block(false),
            );
        }

        let selectors = self
            .compute_equality_selectors(ct, matches.0.par_iter().map(|(input, _output)| *input));
        let selectors2 = selectors.iter().map(|s| s.0.clone()).collect::<Vec<_>>();

        let max_output_value = matches
            .0
            .iter()
            .copied()
            .max_by(|(_, outputl), (_, outputr)| outputl.cmp(outputr))
            .expect("luts is not empty at this point")
            .1;

        let num_blocks_to_represent_values =
            self.num_blocks_to_represent_unsigned_value(max_output_value);

        let possible_results_to_be_aggregated = self.create_possible_results(
            num_blocks_to_represent_values,
            selectors
                .into_par_iter()
                .zip(matches.0.par_iter().map(|(_input, output)| *output)),
        );

        if max_output_value == Clear::ZERO {
            // If the max output value is zero, it means 0 is the only output possible
            // and in the case where none of the input matches the ct, the returned value is 0
            //
            // Thus, in that case, the returned value is always 0 regardless of ct's value,
            // but we still have to see if the input matched something
            (
                self.create_trivial_radix(0, num_blocks_to_represent_values),
                BooleanBlock::new_unchecked(
                    self.is_at_least_one_comparisons_block_true(selectors2),
                ),
            )
        } else {
            rayon::join(
                || {
                    let result: RadixCiphertext =
                        self.aggregate_and_unpack_one_hot_vector(possible_results_to_be_aggregated);
                    self.cast_to_unsigned(result, num_blocks_to_represent_values)
                },
                || {
                    BooleanBlock::new_unchecked(
                        self.is_at_least_one_comparisons_block_true(selectors2),
                    )
                },
            )
        }
    }

    /// `match` an input value to an output value
    ///
    /// - Input values are not required to span all possible values that `ct` could hold.
    ///
    /// - The output radix has a number of blocks that depends on the maximum possible output value
    ///   from the `MatchValues`
    ///
    /// Returns a boolean block that encrypts `true` if the input `ct`
    /// matched one of the possible inputs
    pub fn smart_match_value_parallelized<Clear>(
        &self,
        ct: &mut RadixCiphertext,
        matches: &MatchValues<Clear>,
    ) -> (RadixCiphertext, BooleanBlock)
    where
        Clear: UnsignedInteger + DecomposableInto<u64> + CastInto<usize>,
    {
        if !ct.block_carries_are_empty() {
            self.full_propagate_parallelized(ct);
        }

        self.unchecked_match_value_parallelized(ct, matches)
    }

    /// `match` an input value to an output value
    ///
    /// - Input values are not required to span all possible values that `ct` could hold.
    ///
    /// - The output radix has a number of blocks that depends on the maximum possible output value
    ///   from the `MatchValues`
    ///
    /// Returns a boolean block that encrypts `true` if the input `ct`
    /// matched one of the possible inputs
    pub fn match_value_parallelized<Clear>(
        &self,
        ct: &RadixCiphertext,
        matches: &MatchValues<Clear>,
    ) -> (RadixCiphertext, BooleanBlock)
    where
        Clear: UnsignedInteger + DecomposableInto<u64> + CastInto<usize>,
    {
        if ct.block_carries_are_empty() {
            self.unchecked_match_value_parallelized(ct, matches)
        } else {
            let mut clone = ct.clone();
            self.full_propagate_parallelized(&mut clone);
            self.unchecked_match_value_parallelized(&clone, matches)
        }
    }

    /// `match` an input value to an output value
    ///
    /// - Input values are not required to span all possible values that `ct` could hold.
    ///
    /// - The output radix has a number of blocks that depends on the maximum possible output value
    ///   from the `MatchValues`
    ///
    ///
    /// If none of the input matched the `ct` then, `ct` will encrypt the
    /// value given to `or_value`
    pub fn unchecked_match_value_or_parallelized<Clear>(
        &self,
        ct: &RadixCiphertext,
        matches: &MatchValues<Clear>,
        or_value: Clear,
    ) -> RadixCiphertext
    where
        Clear: UnsignedInteger + DecomposableInto<u64> + CastInto<usize>,
    {
        if matches.0.is_empty() {
            return self.create_trivial_radix(
                or_value,
                self.num_blocks_to_represent_unsigned_value(or_value),
            );
        }
        let (result, selected) = self.unchecked_match_value_parallelized(ct, matches);

        // The result must have as many block to represent either the result of the match or the
        // or_value
        let num_blocks_to_represent_or_value =
            self.num_blocks_to_represent_unsigned_value(or_value);
        let num_blocks = result.blocks.len().max(num_blocks_to_represent_or_value);
        let or_value = self.create_trivial_radix(or_value, num_blocks);
        let result = self.cast_to_unsigned(result, num_blocks);

        // Note, this could be slightly faster when we have scalar if then_else
        self.unchecked_if_then_else_parallelized(&selected, &result, &or_value)
    }

    /// `map` an input value to an output value
    ///
    /// - Input values are not required to span all possible values that `ct` could hold.
    ///
    /// - The output radix has a number of blocks that depends on the maximum possible output value
    ///   from the `MatchValues`
    ///
    /// If none of the input matched the `ct` then, `ct` will encrypt the
    /// value given to `or_value`
    pub fn smart_match_value_or_parallelized<Clear>(
        &self,
        ct: &mut RadixCiphertext,
        matches: &MatchValues<Clear>,
        or_value: Clear,
    ) -> RadixCiphertext
    where
        Clear: UnsignedInteger + DecomposableInto<u64> + CastInto<usize>,
    {
        if !ct.block_carries_are_empty() {
            self.full_propagate_parallelized(ct);
        }
        self.unchecked_match_value_or_parallelized(ct, matches, or_value)
    }

    /// `match` an input value to an output value
    ///
    /// - Input values are not required to span all possible values that `ct` could hold.
    ///
    /// - The output radix has a number of blocks that depends on the maximum possible output value
    ///   from the `MatchValues`
    ///
    /// If none of the input matched the `ct` then, `ct` will encrypt the
    /// value given to `or_value`
    pub fn match_value_or_parallelized<Clear>(
        &self,
        ct: &RadixCiphertext,
        matches: &MatchValues<Clear>,
        or_value: Clear,
    ) -> RadixCiphertext
    where
        Clear: UnsignedInteger + DecomposableInto<u64> + CastInto<usize>,
    {
        if ct.block_carries_are_empty() {
            self.unchecked_match_value_or_parallelized(ct, matches, or_value)
        } else {
            let mut clone = ct.clone();
            self.full_propagate_parallelized(&mut clone);
            self.unchecked_match_value_or_parallelized(&clone, matches, or_value)
        }
    }

    /// Returns an encrypted `true` if the encrypted `value` is found in the encrypted slice
    pub fn unchecked_contains_parallelized<T>(&self, cts: &[T], value: &T) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
    {
        if cts.is_empty() {
            return self.create_trivial_boolean_block(false);
        }
        let selectors = cts
            .par_iter()
            .map(|ct| self.eq_parallelized(ct, value).0)
            .collect::<Vec<_>>();
        BooleanBlock::new_unchecked(self.is_at_least_one_comparisons_block_true(selectors))
    }

    /// Returns an encrypted `true` if the encrypted `value` is found in the encrypted slice
    pub fn smart_contains_parallelized<T>(&self, cts: &mut [T], value: &mut T) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
    {
        if !value.block_carries_are_empty() {
            self.full_propagate_parallelized(value);
        }

        cts.par_iter_mut()
            .filter(|ct| !ct.block_carries_are_empty())
            .for_each(|ct| self.full_propagate_parallelized(ct));

        self.unchecked_contains_parallelized(cts, value)
    }

    /// Returns an encrypted `true` if the encrypted `value` is found in the encrypted slice
    pub fn contains_parallelized<T>(&self, cts: &[T], value: &T) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
    {
        let mut tmp_cts;
        let mut tmp_value;

        let cts = if cts.iter().any(|ct| !ct.block_carries_are_empty()) {
            tmp_cts = cts.to_vec();
            tmp_cts
                .par_iter_mut()
                .filter(|ct| !ct.block_carries_are_empty())
                .for_each(|ct| self.full_propagate_parallelized(ct));
            &tmp_cts
        } else {
            cts
        };

        let value = if value.block_carries_are_empty() {
            value
        } else {
            tmp_value = value.clone();
            self.full_propagate_parallelized(&mut tmp_value);
            &tmp_value
        };

        self.unchecked_contains_parallelized(cts, value)
    }

    /// Returns an encrypted `true` if the clear `value` is found in the encrypted slice
    pub fn unchecked_contains_clear_parallelized<T, Clear>(
        &self,
        cts: &[T],
        clear: Clear,
    ) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
        Clear: DecomposableInto<u64>,
    {
        if cts.is_empty() {
            return self.create_trivial_boolean_block(false);
        }
        let selectors = cts
            .par_iter()
            .map(|ct| self.scalar_eq_parallelized(ct, clear).0)
            .collect::<Vec<_>>();
        BooleanBlock::new_unchecked(self.is_at_least_one_comparisons_block_true(selectors))
    }

    /// Returns an encrypted `true` if the clear `value` is found in the encrypted slice
    pub fn smart_contains_clear_parallelized<T, Clear>(
        &self,
        cts: &mut [T],
        clear: Clear,
    ) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
        Clear: DecomposableInto<u64>,
    {
        let mut tmp_cts;

        let cts = if cts.iter().any(|ct| !ct.block_carries_are_empty()) {
            tmp_cts = cts.to_vec();
            tmp_cts
                .par_iter_mut()
                .filter(|ct| !ct.block_carries_are_empty())
                .for_each(|ct| self.full_propagate_parallelized(ct));
            tmp_cts.as_slice()
        } else {
            cts
        };

        self.unchecked_contains_clear_parallelized(cts, clear)
    }

    /// Returns an encrypted `true` if the clear `value` is found in the encrypted slice
    pub fn contains_clear_parallelized<T, Clear>(&self, cts: &[T], clear: Clear) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
        Clear: DecomposableInto<u64>,
    {
        if cts.is_empty() {
            return self.create_trivial_boolean_block(false);
        }
        let selectors = cts
            .par_iter()
            .map(|ct| self.scalar_eq_parallelized(ct, clear).0)
            .collect::<Vec<_>>();
        BooleanBlock::new_unchecked(self.is_at_least_one_comparisons_block_true(selectors))
    }

    /// Returns an encrypted `true` if the encrypted `value` is found in the clear slice
    pub fn unchecked_is_in_clears_parallelized<T, Clear>(
        &self,
        ct: &T,
        clears: &[Clear],
    ) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
        Clear: DecomposableInto<u64> + CastInto<usize>,
    {
        if clears.is_empty() {
            return self.create_trivial_boolean_block(false);
        }
        let selectors = self
            .compute_equality_selectors(ct, clears.par_iter().copied())
            .into_iter()
            .map(|x| x.0)
            .collect::<Vec<_>>();
        BooleanBlock::new_unchecked(self.is_at_least_one_comparisons_block_true(selectors))
    }

    /// Returns an encrypted `true` if the encrypted `value` is found in the clear slice
    pub fn smart_is_in_clears_parallelized<T, Clear>(
        &self,
        ct: &mut T,
        clears: &[Clear],
    ) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
        Clear: DecomposableInto<u64> + CastInto<usize>,
    {
        if !ct.block_carries_are_empty() {
            self.full_propagate_parallelized(ct);
        }
        self.unchecked_is_in_clears_parallelized(ct, clears)
    }

    /// Returns an encrypted `true` if the encrypted `value` is found in the clear slice
    pub fn is_in_clears_parallelized<T, Clear>(&self, ct: &T, clears: &[Clear]) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
        Clear: DecomposableInto<u64> + CastInto<usize>,
    {
        let mut tmp_ct;
        let ct = if ct.block_carries_are_empty() {
            ct
        } else {
            tmp_ct = ct.clone();
            self.full_propagate_parallelized(&mut tmp_ct);
            &tmp_ct
        };
        self.unchecked_is_in_clears_parallelized(ct, clears)
    }

    /// Returns the encrypted index of the encrypted `value` in the clear slice
    /// also returns an encrypted boolean that is `true` if the encrypted value was found.
    ///
    /// # Notes
    ///
    /// - clear values in the slice must be unique (otherwise use
    ///   [Self::unchecked_first_index_in_clears_parallelized])
    /// - If the encrypted value is not in the clear slice, the returned index is 0
    pub fn unchecked_index_in_clears_parallelized<T, Clear>(
        &self,
        ct: &T,
        clears: &[Clear],
    ) -> (RadixCiphertext, BooleanBlock)
    where
        T: IntegerRadixCiphertext,
        Clear: DecomposableInto<u64> + CastInto<usize>,
    {
        if clears.is_empty() {
            return (
                self.create_trivial_zero_radix(ct.blocks().len()),
                self.create_trivial_boolean_block(false),
            );
        }
        let selectors = self.compute_equality_selectors(ct, clears.par_iter().copied());
        self.compute_final_index_from_selectors(selectors)
    }

    /// Returns the encrypted index of the encrypted `value` in the clear slice
    /// also returns an encrypted boolean that is `true` if the encrypted value was found.
    ///
    /// # Notes
    ///
    /// - clear values in the slice must be unique (otherwise use
    ///   [Self::smart_first_index_in_clears_parallelized])
    /// - If the encrypted value is not in the clear slice, the returned index is 0
    pub fn smart_index_in_clears_parallelized<T, Clear>(
        &self,
        ct: &mut T,
        clears: &[Clear],
    ) -> (RadixCiphertext, BooleanBlock)
    where
        T: IntegerRadixCiphertext,
        Clear: DecomposableInto<u64> + CastInto<usize>,
    {
        if !ct.block_carries_are_empty() {
            self.full_propagate_parallelized(ct);
        }

        self.unchecked_index_in_clears_parallelized(ct, clears)
    }

    /// Returns the encrypted index of the encrypted `value` in the clear slice
    /// also returns an encrypted boolean that is `true` if the encrypted value was found.
    ///
    /// # Notes
    ///
    /// - clear values in the slice must be unique (otherwise use
    ///   [Self::index_in_clears_parallelized])
    /// - If the encrypted value is not in the clear slice, the returned index is 0
    pub fn index_in_clears_parallelized<T, Clear>(
        &self,
        ct: &T,
        clears: &[Clear],
    ) -> (RadixCiphertext, BooleanBlock)
    where
        T: IntegerRadixCiphertext,
        Clear: DecomposableInto<u64> + CastInto<usize>,
    {
        let mut tmp_ct;
        let ct = if ct.block_carries_are_empty() {
            ct
        } else {
            tmp_ct = ct.clone();
            self.full_propagate_parallelized(&mut tmp_ct);
            &tmp_ct
        };

        self.unchecked_index_in_clears_parallelized(ct, clears)
    }

    /// Returns the encrypted index of the _first_ occurrence of encrypted `value` in the clear
    /// slice also, it returns an encrypted boolean that is `true` if the encrypted value was
    /// found.
    ///
    /// # Notes
    ///
    /// - If the encrypted value is not in the clear slice, the returned index is 0
    pub fn unchecked_first_index_in_clears_parallelized<T, Clear>(
        &self,
        ct: &T,
        clears: &[Clear],
    ) -> (RadixCiphertext, BooleanBlock)
    where
        T: IntegerRadixCiphertext,
        Clear: DecomposableInto<u64> + CastInto<usize> + Hash,
    {
        if clears.is_empty() {
            return (
                self.create_trivial_zero_radix(ct.blocks().len()),
                self.create_trivial_boolean_block(false),
            );
        }
        let unique_clears = clears
            .iter()
            .copied()
            .enumerate()
            .unique_by(|&(_, value)| value)
            .collect::<Vec<_>>();
        let selectors = self.compute_equality_selectors(
            ct,
            unique_clears.par_iter().copied().map(|(_, value)| value),
        );
        let selectors2 = selectors.iter().cloned().map(|x| x.0).collect::<Vec<_>>();
        let num_blocks_result =
            (clears.len().ilog2() + 1).div_ceil(self.message_modulus().0.ilog2()) as usize;

        rayon::join(
            || {
                let possible_values = self.create_possible_results(
                    num_blocks_result,
                    selectors
                        .into_par_iter()
                        .zip(unique_clears.into_par_iter().map(|(index, _)| index as u64)),
                );
                self.aggregate_and_unpack_one_hot_vector(possible_values)
            },
            || BooleanBlock::new_unchecked(self.is_at_least_one_comparisons_block_true(selectors2)),
        )
    }

    /// Returns the encrypted index of the _first_ occurrence of encrypted `value` in the clear
    /// slice also, it returns an encrypted boolean that is `true` if the encrypted value was
    /// found.
    ///
    /// # Notes
    ///
    /// - If the encrypted value is not in the clear slice, the returned index is 0
    pub fn smart_first_index_in_clears_parallelized<T, Clear>(
        &self,
        ct: &mut T,
        clears: &[Clear],
    ) -> (RadixCiphertext, BooleanBlock)
    where
        T: IntegerRadixCiphertext,
        Clear: DecomposableInto<u64> + CastInto<usize> + Hash,
    {
        if !ct.block_carries_are_empty() {
            self.full_propagate_parallelized(ct);
        }

        self.unchecked_first_index_in_clears_parallelized(ct, clears)
    }

    /// Returns the encrypted index of the _first_ occurrence of encrypted `value` in the clear
    /// slice also, it returns an encrypted boolean that is `true` if the encrypted value was
    /// found.
    ///
    /// # Notes
    ///
    /// - If the encrypted value is not in the clear slice, the returned index is 0
    pub fn first_index_in_clears_parallelized<T, Clear>(
        &self,
        ct: &T,
        clears: &[Clear],
    ) -> (RadixCiphertext, BooleanBlock)
    where
        T: IntegerRadixCiphertext,
        Clear: DecomposableInto<u64> + CastInto<usize> + Hash,
    {
        let mut tmp_ct;
        let ct = if ct.block_carries_are_empty() {
            ct
        } else {
            tmp_ct = ct.clone();
            self.full_propagate_parallelized(&mut tmp_ct);
            &tmp_ct
        };

        self.unchecked_first_index_in_clears_parallelized(ct, clears)
    }

    /// Returns the encrypted index of the of encrypted `value` in the ciphertext slice
    /// also, it returns an encrypted boolean that is `true` if the encrypted value was found.
    ///
    /// # Notes
    ///
    /// - clear values in the slice must be unique (otherwise use
    ///   [Self::unchecked_first_index_of_parallelized])
    /// - If the encrypted value is not in the encrypted slice, the returned index is 0
    pub fn unchecked_index_of_parallelized<T>(
        &self,
        cts: &[T],
        value: &T,
    ) -> (RadixCiphertext, BooleanBlock)
    where
        T: IntegerRadixCiphertext,
    {
        if cts.is_empty() {
            return (
                self.create_trivial_zero_radix(value.blocks().len()),
                self.create_trivial_boolean_block(false),
            );
        }
        let selectors = cts
            .par_iter()
            .map(|ct| self.eq_parallelized(ct, value))
            .collect::<Vec<_>>();

        self.compute_final_index_from_selectors(selectors)
    }

    /// Returns the encrypted index of the of encrypted `value` in the ciphertext slice
    /// also, it returns an encrypted boolean that is `true` if the encrypted value was found.
    ///
    /// # Notes
    ///
    /// - clear values in the slice must be unique (otherwise use
    ///   [Self::smart_first_index_of_parallelized])
    /// - If the encrypted value is not in the encrypted slice, the returned index is 0
    pub fn smart_index_of_parallelized<T>(
        &self,
        cts: &mut [T],
        value: &mut T,
    ) -> (RadixCiphertext, BooleanBlock)
    where
        T: IntegerRadixCiphertext,
    {
        if !value.block_carries_are_empty() {
            self.full_propagate_parallelized(value);
        }

        cts.par_iter_mut()
            .filter(|ct| !ct.block_carries_are_empty())
            .for_each(|ct| self.full_propagate_parallelized(ct));

        self.unchecked_index_of_parallelized(cts, value)
    }

    /// Returns the encrypted index of the of encrypted `value` in the ciphertext slice
    /// also, it returns an encrypted boolean that is `true` if the encrypted value was found.
    ///
    /// # Notes
    ///
    /// - clear values in the slice must be unique (otherwise use
    ///   [Self::first_index_of_parallelized])
    /// - If the encrypted value is not in the encrypted slice, the returned index is 0
    pub fn index_of_parallelized<T>(&self, cts: &[T], value: &T) -> (RadixCiphertext, BooleanBlock)
    where
        T: IntegerRadixCiphertext,
    {
        let mut tmp_cts;
        let mut tmp_value;

        let cts = if cts.iter().any(|ct| !ct.block_carries_are_empty()) {
            tmp_cts = cts.to_vec();
            tmp_cts
                .par_iter_mut()
                .filter(|ct| !ct.block_carries_are_empty())
                .for_each(|ct| self.full_propagate_parallelized(ct));
            &tmp_cts
        } else {
            cts
        };

        let value = if value.block_carries_are_empty() {
            value
        } else {
            tmp_value = value.clone();
            self.full_propagate_parallelized(&mut tmp_value);
            &tmp_value
        };

        self.unchecked_index_of_parallelized(cts, value)
    }

    /// Returns the encrypted index of the of clear `value` in the ciphertext slice
    /// also, it returns an encrypted boolean that is `true` if the encrypted value was found.
    ///
    /// # Notes
    ///
    /// - clear values in the slice must be unique (otherwise use
    ///   [Self::unchecked_first_index_of_clear_parallelized])
    /// - If the clear value is not in the encrypted slice, the returned index is 0
    pub fn unchecked_index_of_clear_parallelized<T, Clear>(
        &self,
        cts: &[T],
        clear: Clear,
    ) -> (RadixCiphertext, BooleanBlock)
    where
        T: IntegerRadixCiphertext,
        Clear: DecomposableInto<u64> + CastInto<usize>,
    {
        if cts.is_empty() {
            return (
                self.create_trivial_zero_radix(1),
                self.create_trivial_boolean_block(false),
            );
        }
        let selectors = cts
            .par_iter()
            .map(|ct| self.scalar_eq_parallelized(ct, clear))
            .collect::<Vec<_>>();

        self.compute_final_index_from_selectors(selectors)
    }

    /// Returns the encrypted index of the of clear `value` in the ciphertext slice
    /// also, it returns an encrypted boolean that is `true` if the encrypted value was found.
    ///
    /// # Notes
    ///
    /// - clear values in the slice must be unique (otherwise use
    ///   [Self::smart_first_index_of_clear_parallelized])
    /// - If the clear value is not in the encrypted slice, the returned index is 0
    pub fn smart_index_of_clear_parallelized<T, Clear>(
        &self,
        cts: &mut [T],
        clear: Clear,
    ) -> (RadixCiphertext, BooleanBlock)
    where
        T: IntegerRadixCiphertext,
        Clear: DecomposableInto<u64> + CastInto<usize>,
    {
        cts.par_iter_mut()
            .filter(|ct| !ct.block_carries_are_empty())
            .for_each(|ct| self.full_propagate_parallelized(ct));

        self.unchecked_index_of_clear_parallelized(cts, clear)
    }

    /// Returns the encrypted index of the of clear `value` in the ciphertext slice
    /// also, it returns an encrypted boolean that is `true` if the encrypted value was found.
    ///
    /// # Notes
    ///
    /// - clear values in the slice must be unique (otherwise use
    ///   [Self::first_index_of_clear_parallelized])
    /// - If the clear value is not in the encrypted slice, the returned index is 0
    pub fn index_of_clear_parallelized<T, Clear>(
        &self,
        cts: &[T],
        clear: Clear,
    ) -> (RadixCiphertext, BooleanBlock)
    where
        T: IntegerRadixCiphertext,
        Clear: DecomposableInto<u64> + CastInto<usize>,
    {
        let mut tmp_cts;

        let cts = if cts.iter().any(|ct| !ct.block_carries_are_empty()) {
            tmp_cts = cts.to_vec();
            tmp_cts
                .par_iter_mut()
                .filter(|ct| !ct.block_carries_are_empty())
                .for_each(|ct| self.full_propagate_parallelized(ct));
            tmp_cts.as_slice()
        } else {
            cts
        };

        self.unchecked_index_of_clear_parallelized(cts, clear)
    }

    /// Returns the encrypted index of the _first_ occurrence of clear `value` in the ciphertext
    /// slice also, it returns an encrypted boolean that is `true` if the encrypted value was
    /// found.
    ///
    /// # Notes
    ///
    /// - If the clear value is not in the clear slice, the returned index is 0
    pub fn unchecked_first_index_of_clear_parallelized<T, Clear>(
        &self,
        cts: &[T],
        clear: Clear,
    ) -> (RadixCiphertext, BooleanBlock)
    where
        T: IntegerRadixCiphertext,
        Clear: DecomposableInto<u64> + CastInto<usize>,
    {
        if cts.is_empty() {
            return (
                self.create_trivial_zero_radix(1),
                self.create_trivial_boolean_block(false),
            );
        }
        let num_blocks_result =
            (cts.len().ilog2() + 1).div_ceil(self.message_modulus().0.ilog2()) as usize;

        let selectors = cts
            .par_iter()
            .map(|ct| self.scalar_eq_parallelized(ct, clear).0)
            .collect::<Vec<_>>();

        let selectors = self.only_keep_first_true(selectors);

        let selectors2 = selectors
            .iter()
            .cloned()
            .map(BooleanBlock::new_unchecked)
            .collect::<Vec<_>>();

        rayon::join(
            || {
                let possible_values = self.create_possible_results(
                    num_blocks_result,
                    selectors2
                        .into_par_iter()
                        .enumerate()
                        .map(|(i, v)| (v, i as u64)),
                );
                self.aggregate_and_unpack_one_hot_vector(possible_values)
            },
            || BooleanBlock::new_unchecked(self.is_at_least_one_comparisons_block_true(selectors)),
        )
    }

    /// Returns the encrypted index of the _first_ occurrence of clear `value` in the ciphertext
    /// slice also, it returns an encrypted boolean that is `true` if the encrypted value was
    /// found.
    ///
    /// # Notes
    ///
    /// - If the clear value is not in the clear slice, the returned index is 0
    pub fn smart_first_index_of_clear_parallelized<T, Clear>(
        &self,
        cts: &mut [T],
        clear: Clear,
    ) -> (RadixCiphertext, BooleanBlock)
    where
        T: IntegerRadixCiphertext,
        Clear: DecomposableInto<u64> + CastInto<usize>,
    {
        cts.par_iter_mut()
            .filter(|ct| !ct.block_carries_are_empty())
            .for_each(|ct| self.full_propagate_parallelized(ct));

        self.unchecked_first_index_of_clear_parallelized(cts, clear)
    }

    /// Returns the encrypted index of the _first_ occurrence of clear `value` in the ciphertext
    /// slice also, it returns an encrypted boolean that is `true` if the encrypted value was
    /// found.
    ///
    /// # Notes
    ///
    /// - If the clear value is not in the clear slice, the returned index is 0
    pub fn first_index_of_clear_parallelized<T, Clear>(
        &self,
        cts: &[T],
        clear: Clear,
    ) -> (RadixCiphertext, BooleanBlock)
    where
        T: IntegerRadixCiphertext,
        Clear: DecomposableInto<u64> + CastInto<usize>,
    {
        let mut tmp_cts;

        let cts = if cts.iter().any(|ct| !ct.block_carries_are_empty()) {
            tmp_cts = cts.to_vec();
            tmp_cts
                .par_iter_mut()
                .filter(|ct| !ct.block_carries_are_empty())
                .for_each(|ct| self.full_propagate_parallelized(ct));
            tmp_cts.as_slice()
        } else {
            cts
        };

        self.unchecked_first_index_of_clear_parallelized(cts, clear)
    }

    /// Returns the encrypted index of the _first_ occurrence of encrypted `value` in the ciphertext
    /// slice also, it returns an encrypted boolean that is `true` if the encrypted value was
    /// found.
    ///
    /// # Notes
    ///
    /// - If the encrypted value is not in the clear slice, the returned index is 0
    pub fn unchecked_first_index_of_parallelized<T>(
        &self,
        cts: &[T],
        value: &T,
    ) -> (RadixCiphertext, BooleanBlock)
    where
        T: IntegerRadixCiphertext,
    {
        if cts.is_empty() {
            return (
                self.create_trivial_zero_radix(value.blocks().len()),
                self.create_trivial_boolean_block(false),
            );
        }

        let num_blocks_result =
            (cts.len().ilog2() + 1).div_ceil(self.message_modulus().0.ilog2()) as usize;

        let selectors = cts
            .par_iter()
            .map(|ct| self.eq_parallelized(ct, value).0)
            .collect::<Vec<_>>();

        let selectors = self.only_keep_first_true(selectors);

        let selectors2 = selectors
            .iter()
            .cloned()
            .map(BooleanBlock::new_unchecked)
            .collect::<Vec<_>>();

        rayon::join(
            || {
                let possible_values = self.create_possible_results(
                    num_blocks_result,
                    selectors2
                        .into_par_iter()
                        .enumerate()
                        .map(|(i, v)| (v, i as u64)),
                );
                self.aggregate_and_unpack_one_hot_vector(possible_values)
            },
            || BooleanBlock::new_unchecked(self.is_at_least_one_comparisons_block_true(selectors)),
        )
    }

    /// Returns the encrypted index of the _first_ occurrence of encrypted `value` in the ciphertext
    /// slice also, it returns an encrypted boolean that is `true` if the encrypted value was
    /// found.
    ///
    /// # Notes
    ///
    /// - If the encrypted value is not in the clear slice, the returned index is 0
    pub fn smart_first_index_of_parallelized<T>(
        &self,
        cts: &mut [T],
        value: &mut T,
    ) -> (RadixCiphertext, BooleanBlock)
    where
        T: IntegerRadixCiphertext,
    {
        if !value.block_carries_are_empty() {
            self.full_propagate_parallelized(value);
        }

        cts.par_iter_mut()
            .filter(|ct| !ct.block_carries_are_empty())
            .for_each(|ct| self.full_propagate_parallelized(ct));

        self.unchecked_first_index_of_parallelized(cts, value)
    }

    /// Returns the encrypted index of the _first_ occurrence of encrypted `value` in the ciphertext
    /// slice also, it returns an encrypted boolean that is `true` if the encrypted value was
    /// found.
    ///
    /// # Notes
    ///
    /// - If the encrypted value is not in the clear slice, the returned index is 0
    pub fn first_index_of_parallelized<T>(
        &self,
        cts: &[T],
        value: &T,
    ) -> (RadixCiphertext, BooleanBlock)
    where
        T: IntegerRadixCiphertext,
    {
        let mut tmp_cts;
        let mut tmp_value;

        let cts = if cts.iter().any(|ct| !ct.block_carries_are_empty()) {
            tmp_cts = cts.to_vec();
            tmp_cts
                .par_iter_mut()
                .filter(|ct| !ct.block_carries_are_empty())
                .for_each(|ct| self.full_propagate_parallelized(ct));
            &tmp_cts
        } else {
            cts
        };

        let value = if value.block_carries_are_empty() {
            value
        } else {
            tmp_value = value.clone();
            self.full_propagate_parallelized(&mut tmp_value);
            &tmp_value
        };

        self.unchecked_first_index_of_parallelized(cts, value)
    }

    fn compute_final_index_from_selectors(
        &self,
        selectors: Vec<BooleanBlock>,
    ) -> (RadixCiphertext, BooleanBlock) {
        let num_blocks_result =
            (selectors.len().ilog2() + 1).div_ceil(self.message_modulus().0.ilog2()) as usize;

        let selectors2 = selectors.iter().cloned().map(|x| x.0).collect::<Vec<_>>();

        rayon::join(
            || {
                let possible_values = self.create_possible_results(
                    num_blocks_result,
                    selectors
                        .into_par_iter()
                        .enumerate()
                        .map(|(i, v)| (v, i as u64)),
                );
                self.aggregate_and_unpack_one_hot_vector(possible_values)
            },
            || BooleanBlock::new_unchecked(self.is_at_least_one_comparisons_block_true(selectors2)),
        )
    }

    /// Computes the vector of selectors from an input iterator of clear values and an encrypted
    /// value
    ///
    /// Given an iterator of clear values, and an encrypted radix ciphertext,
    /// this method will return a vector of encrypted boolean values where
    /// each value is either 1 if the ct is equal to the corresponding clear in the iterator
    /// otherwise it will be 0.
    ///
    /// Requires ct to have empty carries
    pub(crate) fn compute_equality_selectors<T, Iter, Clear>(
        &self,
        ct: &T,
        possible_input_values: Iter,
    ) -> Vec<BooleanBlock>
    where
        T: IntegerRadixCiphertext,
        Iter: ParallelIterator<Item = Clear>,
        Clear: Decomposable + CastInto<usize>,
    {
        assert!(
            ct.block_carries_are_empty(),
            "internal error: ciphertext carries must be empty"
        );
        assert!(
            self.carry_modulus().0 >= self.message_modulus().0,
            "This function uses many LUTs in a way that requires to have at least as much carry \
                space as message space ({:?} vs {:?})",
            self.carry_modulus(),
            self.message_modulus()
        );
        // Contains the LUTs used to compare a block with scalar block values
        // in many LUTs format for efficiency
        let luts = {
            let scalar_block_cmp_fns = (0..self.message_modulus().0)
                .map(|msg_value| move |block: u64| u64::from(block == msg_value))
                .collect::<Vec<_>>();

            let fns = scalar_block_cmp_fns
                .iter()
                .map(|func| func as &dyn Fn(u64) -> u64)
                .collect::<Vec<_>>();

            self.key.generate_many_lookup_table(fns.as_slice())
        };

        // Compute for each block all the possible scalar block equality
        let blocks_cmps = ct
            .blocks()
            .par_iter()
            .map(|block| self.key.apply_many_lookup_table(block, &luts))
            .collect::<Vec<_>>();

        let num_bits_in_message = self.message_modulus().0.ilog2();
        let num_blocks = ct.blocks().len();
        possible_input_values
            .map(|input_value| {
                let cmps = BlockDecomposer::new(input_value, num_bits_in_message)
                    .take(num_blocks)
                    .enumerate()
                    .map(|(block_index, block_value)| {
                        blocks_cmps[block_index][block_value.cast_into()].clone()
                    })
                    .collect::<Vec<_>>();

                BooleanBlock::new_unchecked(self.are_all_comparisons_block_true(cmps))
            })
            .collect::<Vec<_>>()
    }

    /// Creates a vector of radix ciphertext from an iterator that associates encrypted boolean
    /// values to clear values.
    ///
    /// The elements of the resulting vector are zero if the corresponding BooleanBlock encrypted 0,
    /// otherwise it encrypts the associated clear value.
    ///
    /// This is only really useful if only one of the boolean block is known to be non-zero.
    ///
    /// `num_blocks`: number of blocks (unpacked) needed to represent the biggest clear value
    ///
    /// - Resulting radix ciphertexts have their block packed, thus they will have ceil (numb_blocks
    ///   / 2) elements
    fn create_possible_results<T, Iter, Clear>(
        &self,
        num_blocks: usize,
        possible_outputs: Iter,
    ) -> Vec<T>
    where
        T: IntegerRadixCiphertext,
        Iter: ParallelIterator<Item = (BooleanBlock, Clear)>,
        Clear: Decomposable + CastInto<usize>,
    {
        assert!(
            self.carry_modulus().0 >= self.message_modulus().0,
            "As this function packs blocks, it requires to have at least as much carry \
                space as message space ({:?} vs {:?})",
            self.carry_modulus(),
            self.message_modulus()
        );
        // Vector of functions that returns function, that will be used to create LUTs later
        let scalar_block_cmp_fns = (0..(self.message_modulus().0 * self.message_modulus().0))
            .map(|packed_block_value| {
                move |is_selected: u64| {
                    if is_selected == 1 {
                        packed_block_value
                    } else {
                        0
                    }
                }
            })
            .collect::<Vec<_>>();

        // How "many LUTs" we can apply, since we are going to apply luts on boolean values
        // (Degree(1), Modulus(2))
        // Equivalent to (2^(msg_bits + carry_bits - 1)
        let max_num_many_luts = (self.message_modulus().0 * self.carry_modulus().0) / 2;

        let num_bits_in_message = self.message_modulus().0.ilog2();
        possible_outputs
            .map(|(selector, output_value)| {
                let decomposed_value = BlockDecomposer::new(output_value, 2 * num_bits_in_message)
                    .take(num_blocks.div_ceil(2))
                    .collect::<Vec<_>>();

                // Since there is a limit in the number of how many lut we can apply in one PBS
                // we pre-chunk LUTs according to that amount
                let blocks = decomposed_value
                    .par_chunks(max_num_many_luts as usize)
                    .flat_map(|chunk_of_packed_value| {
                        let fns = chunk_of_packed_value
                            .iter()
                            .map(|packed_value| {
                                &(scalar_block_cmp_fns[(*packed_value).cast_into()])
                                    as &dyn Fn(u64) -> u64
                            })
                            .collect::<Vec<_>>();
                        let luts = self.key.generate_many_lookup_table(fns.as_slice());
                        self.key.apply_many_lookup_table(&selector.0, &luts)
                    })
                    .collect::<Vec<_>>();

                T::from_blocks(blocks)
            })
            .collect::<Vec<_>>()
    }

    /// Aggregate/combines a vec of one-hot vector of radix ciphertexts
    /// (i.e. at most one of the vector element is non-zero) into single ciphertext
    /// containing the non-zero value.
    ///
    /// The elements in the one hot vector may have their block packed or not
    ///
    /// The returned result has non packed blocks
    pub(super) fn aggregate_and_unpack_one_hot_vector<T>(&self, one_hot_vector: Vec<T>) -> T
    where
        T: IntegerRadixCiphertext,
    {
        let result = self.partial_aggregate_one_hot_vector(one_hot_vector);

        let unpacked_blocks = result
            .blocks()
            .par_iter()
            .flat_map(|block| -> [Ciphertext; 2] {
                rayon::join(
                    || self.key.message_extract(block),
                    || self.key.carry_extract(block),
                )
                .into()
            })
            .collect::<Vec<_>>();

        T::from_blocks(unpacked_blocks)
    }

    /// Aggregate/combines a vec of one-hot vector of radix ciphertexts
    /// (i.e. at most one of the vector element is non-zero) into single ciphertext
    /// containing the non-zero value.
    ///
    /// * The returned result has block still packed if the input blocks where packed.
    pub(super) fn aggregate_one_hot_vector<T>(&self, one_hot_vector: Vec<T>) -> T
    where
        T: IntegerRadixCiphertext,
    {
        let mut result = self.partial_aggregate_one_hot_vector(one_hot_vector);

        result
            .blocks_mut()
            .par_iter_mut()
            .for_each(|block| self.key.message_extract_assign(block));

        result
    }

    /// Aggregate/combines a vec of one-hot vector of radix ciphertexts
    /// (i.e. at most one of the vector element is non-zero) into single ciphertext
    /// containing the non-zero value.
    ///
    /// * The elements in the one hot vector may have their block packed or not
    /// * The returned result has block still packed if the input blocks where packed.
    ///
    /// # Warning
    ///
    /// The returned value will need to be unpacked if the inputs where packed or
    /// if they were not, noise cleaning may still need to be done.
    fn partial_aggregate_one_hot_vector<T>(&self, mut one_hot_vector: Vec<T>) -> T
    where
        T: IntegerRadixCiphertext,
    {
        // Used to clean the noise
        let identity_lut = self.key.generate_lookup_table(|x| x);

        // Since all but one radix are zeros, the limiting factor
        // for additions is the noise level
        let chunk_size = self.key.max_noise_level.get() as usize;

        let (num_init_chunks, num_init_rest) = (
            one_hot_vector.len() / chunk_size,
            one_hot_vector.len() % chunk_size,
        );
        let mut workbench = Vec::with_capacity(num_init_chunks + num_init_rest);

        while one_hot_vector.len() > chunk_size {
            one_hot_vector
                .par_chunks_exact(chunk_size)
                .map(|chunk| {
                    let mut result = chunk[0].clone();
                    for r in &chunk[1..] {
                        self.unchecked_add_assign(&mut result, r);
                    }
                    result
                        .blocks_mut()
                        .par_iter_mut()
                        .for_each(|block| self.key.apply_lookup_table_assign(block, &identity_lut));
                    result
                })
                .collect_into_vec(&mut workbench);

            let start = one_hot_vector.len() - one_hot_vector.len() % chunk_size;
            workbench.extend(one_hot_vector.drain(start..));

            std::mem::swap(&mut workbench, &mut one_hot_vector);
        }

        let mut result = one_hot_vector[0].clone();
        if one_hot_vector.len() > 1 {
            for r in &one_hot_vector[1..] {
                self.unchecked_add_assign(&mut result, r);
            }
        }

        result
    }

    /// Only keeps at most one Ciphertext that encrypts 1
    ///
    /// Given a Vec of Ciphertexts where each Ciphertext encrypts 0 or 1
    /// This function will return a Vec of Ciphertext where at most one encryption of 1 is present
    ///
    /// The first encryption of one is kept
    fn only_keep_first_true(&self, mut values: Vec<Ciphertext>) -> Vec<Ciphertext> {
        if values.len() <= 1 {
            return values;
        }
        let does_not_have_enough_bits =
            self.message_modulus().0 < 3 || (self.carry_modulus().0 < self.message_modulus().0);

        if does_not_have_enough_bits {
            let mut true_already_seen = values[0].clone();
            let lut =
                self.key
                    .generate_lookup_table_bivariate(|current_block, true_already_seen| {
                        if true_already_seen == 1 {
                            0
                        } else {
                            current_block
                        }
                    });

            for block in &mut values[1..] {
                let new_true_already_seen = self.key.bitor(&true_already_seen, block);
                self.key
                    .apply_lookup_table_bivariate_assign(block, &mut true_already_seen, &lut);
                true_already_seen = new_true_already_seen;
            }

            values
        } else {
            const ALREADY_SEEN: u64 = 2;
            let lut_fn = self
                .key
                .generate_lookup_table_bivariate(|current, previous| {
                    if previous == 1 || previous == ALREADY_SEEN {
                        ALREADY_SEEN
                    } else {
                        current
                    }
                });
            let sum_function = |current: &mut Ciphertext, previous: &Ciphertext| {
                self.key
                    .unchecked_apply_lookup_table_bivariate_assign(current, previous, &lut_fn);
            };
            let mut values = self.compute_prefix_sum_hillis_steele(values, sum_function);
            let lut = self.key.generate_lookup_table(|x| {
                let x = x % self.message_modulus().0;
                if x == ALREADY_SEEN {
                    0
                } else {
                    x
                }
            });
            values
                .par_iter_mut()
                .for_each(|block| self.key.apply_lookup_table_assign(block, &lut));
            values
        }
    }
}
