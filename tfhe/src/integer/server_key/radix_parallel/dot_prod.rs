use crate::integer::{BooleanBlock, IntegerRadixCiphertext, ServerKey};
use crate::shortint::ciphertext::NoiseLevel;
use rayon::prelude::*;
use std::borrow::Cow;

impl ServerKey {
    /// Returns boolean blocks that are guaranteed clean (degree <= 1, nominal noise),
    /// borrowing the input when it is already clean and only cloning otherwise.
    pub(crate) fn cleaned_boolean_blocks<'a>(
        &self,
        boolean_blocks: &'a [BooleanBlock],
    ) -> Cow<'a, [BooleanBlock]> {
        let needs_cleaning =
            |b: &BooleanBlock| b.0.noise_level() > NoiseLevel::NOMINAL || b.0.degree.get() >= 2;

        if boolean_blocks.iter().any(needs_cleaning) {
            let id_lut = self.key.generate_lookup_table(|x| u64::from(x != 0));
            let mut cloned = boolean_blocks.to_vec();
            cloned
                .par_iter_mut()
                .filter(|b| needs_cleaning(b))
                .for_each(|b| self.key.apply_lookup_table_assign(&mut b.0, &id_lut));
            Cow::Owned(cloned)
        } else {
            Cow::Borrowed(boolean_blocks)
        }
    }

    /// Computes the dot product between encrypted booleans and encrypted values
    ///
    /// * `boolean_blocks` must be 'one-hot' i.e. at most 1 BooleanBlock can encrypt a `true`
    /// * `n_blocks` number of blocks in the resulting ciphertext
    ///
    /// # Panic
    ///
    /// * Panics if `boolean_blocks` and `radixes` do not have the same lengths
    /// * Panics if `boolean_blocks` or `radixes` is empty
    pub fn unchecked_boolean_one_hot_dot_prod<T>(
        &self,
        boolean_blocks: &[BooleanBlock],
        radixes: &[T],
    ) -> T
    where
        T: IntegerRadixCiphertext,
    {
        assert_eq!(
            boolean_blocks.len(),
            radixes.len(),
            "both operands must have the same number of elements"
        );

        assert!(!boolean_blocks.is_empty(), "operands must not be empty");

        let lut = self.key.generate_lookup_table(|x| {
            let cond = x & 1;
            let v = x >> 1;

            if cond == 1 {
                v * self.key.message_modulus.0
            } else {
                0
            }
        });
        let one_hot_vec_shifted = boolean_blocks
            .par_iter()
            .zip(radixes.par_iter())
            .map(|(boolean, radix)| {
                let mut result = radix.clone();
                result.blocks_mut().par_iter_mut().for_each(|block| {
                    self.key.unchecked_scalar_mul_assign(block, 2);
                    self.key.unchecked_add_assign(block, &boolean.0);
                    self.key.apply_lookup_table_assign(block, &lut);
                });
                result
            })
            .collect::<Vec<_>>();

        self.aggregate_one_hot_vector_with_noise_trick(one_hot_vec_shifted)
    }

    /// Computes the dot product between encrypted booleans and encrypted values
    ///
    /// * `boolean_blocks` must be 'one-hot' i.e. at most 1 BooleanBlock can encrypt a `true`
    ///
    /// # Panic
    ///
    /// * Panics if `boolean_blocks` and `radixes` do not have the same lengths
    /// * Panics if `boolean_blocks` or `radixes` is empty
    pub fn boolean_one_hot_dot_prod<T>(&self, boolean_blocks: &[BooleanBlock], radixes: &[T]) -> T
    where
        T: IntegerRadixCiphertext,
    {
        let boolean_blocks = self.cleaned_boolean_blocks(boolean_blocks);

        let radix_needs_cleaning = |r: &T| {
            !r.block_carries_are_empty()
                || r.blocks()
                    .iter()
                    .any(|b| b.noise_level() > NoiseLevel::NOMINAL)
        };

        let mut cloned_radixes;
        let radixes = if radixes.iter().any(radix_needs_cleaning) {
            cloned_radixes = radixes.to_vec();
            cloned_radixes
                .par_iter_mut()
                .filter(|r| radix_needs_cleaning(r))
                .for_each(|r| self.full_propagate_parallelized(r));
            &cloned_radixes
        } else {
            radixes
        };

        self.unchecked_boolean_one_hot_dot_prod(&boolean_blocks, radixes)
    }
}
