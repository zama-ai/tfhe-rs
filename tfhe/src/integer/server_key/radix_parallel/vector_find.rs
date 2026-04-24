use crate::core_crypto::prelude::UnsignedInteger;
use crate::integer::block_decomposition::{BlockDecomposer, Decomposable, DecomposableInto};
use crate::integer::{BooleanBlock, IntegerRadixCiphertext, RadixCiphertext, ServerKey};
use crate::prelude::CastInto;
use crate::shortint::atomic_pattern::AtomicPattern;
use crate::shortint::server_key::generate_lookup_table_with_output_encoding;
use crate::shortint::{CarryModulus, Ciphertext, MaxNoiseLevel};
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
                    let output_clears = matches.0.iter().map(|x| x.1).collect_vec();
                    let result: RadixCiphertext = self
                        .unchecked_boolean_scalar_one_hot_dot_prod_parallelized(
                            &selectors,
                            &output_clears,
                            num_blocks_to_represent_values as u32,
                        );
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

        rayon::join(
            || {
                let indices = unique_clears
                    .into_par_iter()
                    .map(|(index, _)| index as u64)
                    .collect::<Vec<_>>();
                let max = indices.iter().copied().max().unwrap();
                let num_blocks_to_represent_values =
                    self.num_blocks_to_represent_unsigned_value(max);
                self.unchecked_boolean_scalar_one_hot_dot_prod_parallelized(
                    &selectors,
                    &indices,
                    num_blocks_to_represent_values as u32,
                )
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

        let selectors = cts
            .par_iter()
            .map(|ct| self.scalar_eq_parallelized(ct, clear).0)
            .collect::<Vec<_>>();

        let selectors = self.only_keep_first_true(selectors);

        // TODO avoid this copy
        let selectors2 = selectors
            .iter()
            .cloned()
            .map(BooleanBlock::new_unchecked)
            .collect::<Vec<_>>();

        self.compute_final_index_from_selectors(selectors2)
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

        let selectors = cts
            .par_iter()
            .map(|ct| self.eq_parallelized(ct, value).0)
            .collect::<Vec<_>>();

        let selectors = self.only_keep_first_true(selectors);

        // TODO avoid this copy
        let selectors2 = selectors
            .iter()
            .cloned()
            .map(BooleanBlock::new_unchecked)
            .collect::<Vec<_>>();

        self.compute_final_index_from_selectors(selectors2)
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
        let selectors2 = selectors.iter().cloned().map(|x| x.0).collect::<Vec<_>>();

        rayon::join(
            || {
                let indices = (0..selectors.len() as u32).collect::<Vec<_>>();
                let num_blocks_to_represent_values =
                    self.num_blocks_to_represent_unsigned_value(selectors.len() - 1);
                self.unchecked_boolean_scalar_one_hot_dot_prod_parallelized(
                    &selectors,
                    &indices,
                    num_blocks_to_represent_values as u32,
                )
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

    /// Aggregates the on_hot_vector into a single result
    ///
    /// the blocks inside the one hot vector must have their message
    /// pushed onto the carry part, and the message part must be empty.
    ///
    /// The output will be a regular radix with the message into the message_part
    pub(crate) fn aggregate_one_hot_vector_with_noise_trick<T>(
        &self,
        mut one_hot_vector: Vec<T>,
    ) -> T
    where
        T: IntegerRadixCiphertext,
    {
        let lut_size = self.key.atomic_pattern.lookup_table_size();

        // As the blocks have the message/data into the carry part
        // the is equivalent to blocks being encoded as no carry modulus
        // and only the message modulus.
        //
        // This allows to do more leveled additions before cleaning the noise,
        // and to clean the noise, we need to use a lookup table that respect
        // the proper encoding
        let identity_lut = generate_lookup_table_with_output_encoding(
            lut_size,
            self.key.ciphertext_modulus,
            self.message_modulus(),
            CarryModulus(1),
            self.message_modulus(),
            CarryModulus(1),
            |x| x,
        );

        let old_precision = self.message_modulus().0 * self.carry_modulus().0;
        let new_precision = self.message_modulus().0;
        let diff = old_precision / new_precision;
        let max_noise_level = MaxNoiseLevel::new(self.key.max_noise_level.get() * diff);
        let chunk_size = max_noise_level.get() as usize;
        let (num_init_chunks, num_init_rest) = (
            one_hot_vector.len() / chunk_size,
            one_hot_vector.len() % chunk_size,
        );
        let mut workbench = Vec::with_capacity(num_init_chunks + num_init_rest);

        fn unchecked_radix_add_assign(
            lhs: &mut impl IntegerRadixCiphertext,
            rhs: &impl IntegerRadixCiphertext,
            max_noise_level: crate::shortint::MaxNoiseLevel,
        ) {
            for (ct_left, ct_right) in lhs.blocks_mut().iter_mut().zip(rhs.blocks().iter()) {
                crate::core_crypto::prelude::lwe_ciphertext_add_assign(
                    &mut ct_left.ct,
                    &ct_right.ct,
                );
                ct_left.degree = crate::shortint::ciphertext::Degree::new(
                    ct_left.degree.get() + ct_right.degree.get(),
                );
                ct_left.set_noise_level(
                    ct_left.noise_level() + ct_right.noise_level(),
                    max_noise_level,
                );
            }
        }

        while one_hot_vector.len() > chunk_size {
            one_hot_vector
                .par_chunks_exact(chunk_size)
                .map(|chunk| {
                    let mut result = chunk[0].clone();
                    for r in &chunk[1..] {
                        // self.unchecked_add_assign(&mut result, r);
                        unchecked_radix_add_assign(&mut result, r, max_noise_level);
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
                unchecked_radix_add_assign(&mut result, r, max_noise_level);
                // self.unchecked_add_assign(&mut result, r);
            }
        }

        // The final LUT needs to change the encoding to the original one
        let encoding_change_lut = generate_lookup_table_with_output_encoding(
            lut_size,
            self.key.ciphertext_modulus,
            self.message_modulus(),
            CarryModulus(1),
            self.message_modulus(),
            self.carry_modulus(),
            |x| x,
        );
        result.blocks_mut().par_iter_mut().for_each(|block| {
            self.key
                .apply_lookup_table_assign(block, &encoding_change_lut);
        });

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
