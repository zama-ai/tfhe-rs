use crate::integer::{BooleanBlock, IntegerRadixCiphertext, ServerKey};
use rayon::prelude::*;

impl ServerKey {
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
}
