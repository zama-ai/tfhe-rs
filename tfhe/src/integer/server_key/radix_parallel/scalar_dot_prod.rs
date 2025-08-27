use crate::core_crypto::prelude::{CastInto, Numeric, OverflowingAdd};
use crate::integer::block_decomposition::{BlockDecomposer, DecomposableInto};
use crate::integer::{BooleanBlock, IntegerRadixCiphertext, ServerKey};
use std::ops::{AddAssign, Mul};

use crate::prelude::CastFrom;
use crate::shortint::ciphertext::NoiseLevel;
use rayon::prelude::*;

impl ServerKey {
    /// Computes the dot product between encrypted booleans and clear values
    ///
    /// * `n_blocks` number of blocks in the resulting ciphertext
    ///
    /// # Panic
    ///
    /// * Panics if `boolean_blocks` and `clears` do not have the same lengths
    /// * Panics if `boolean_blocks` or `clears` is empty
    pub fn unchecked_boolean_scalar_dot_prod_parallelized<Clear, T>(
        &self,
        boolean_blocks: &[BooleanBlock],
        clears: &[Clear],
        n_blocks: u32,
    ) -> T
    where
        Clear: Numeric
            + DecomposableInto<u64>
            + CastInto<usize>
            + CastFrom<u128>
            + Mul<Clear, Output = Clear>
            + AddAssign<Clear>
            + OverflowingAdd<Clear, Output = Clear>,
        T: IntegerRadixCiphertext,
    {
        assert_eq!(
            boolean_blocks.len(),
            clears.len(),
            "both operands must have the same number of elements"
        );

        assert!(!boolean_blocks.is_empty(), "operands must not be empty");

        assert!(Clear::BITS as u32 >= n_blocks * self.message_modulus().0.ilog2());

        // How many boolean blocks we pack together
        let mut packing_size = 1;
        let mut packed_noise_level = 1;
        for _ in 1..self.message_modulus().0.ilog2() {
            packed_noise_level = (packed_noise_level * 2) + 1;
            if packed_noise_level > self.key.max_noise_level.get() {
                break;
            }

            packing_size += 1;
        }

        let packed = boolean_blocks
            .par_chunks(packing_size)
            .map(|chunk| {
                let mut result = chunk[0].0.clone();

                for other in chunk[1..].iter() {
                    self.key.unchecked_scalar_mul_assign(&mut result, 2);
                    self.key.unchecked_add_assign(&mut result, &other.0);
                }

                result
            })
            .collect::<Vec<_>>();

        let block_mask = Clear::cast_from(u128::from(self.message_modulus().0 - 1));

        let many_lut_chunk =
            ((self.message_modulus().0 * self.carry_modulus().0) / (1 << packing_size)) as usize;
        let to_be_summed = packed
            .iter()
            .zip(clears.chunks(packing_size))
            .map(|(block, clear_chunk)| {
                // Try to see if most significant blocks might be zero
                // and avoid some PBS
                let mut summed_clear = Clear::ZERO;
                let mut overflowed;
                let mut real_n_blocks = 0;
                for c in clear_chunk.iter() {
                    if *c < Clear::ZERO {
                        real_n_blocks = n_blocks;
                        break;
                    }
                    (summed_clear, overflowed) = summed_clear.overflowing_add(*c);
                    if overflowed {
                        real_n_blocks = n_blocks;
                        break;
                    }
                }

                if real_n_blocks == 0 {
                    real_n_blocks = BlockDecomposer::with_early_stop_at_zero(
                        summed_clear,
                        self.message_modulus().0.ilog2(),
                    )
                    .count()
                    .min(n_blocks as usize) as u32;
                }

                let funcs = (0..real_n_blocks)
                    .map(|block_index| {
                        // The LUT is going to do a part of the dot prod for the corresponding
                        // block
                        move |block| {
                            let mut summed_clear = Clear::ZERO;
                            for (i, c) in clear_chunk.iter().rev().enumerate() {
                                summed_clear += *c * Clear::cast_from(u128::from(block >> i) & 1);
                            }

                            let shift = block_index * self.message_modulus().0.ilog2();
                            ((summed_clear >> shift) & block_mask).cast_into()
                        }
                    })
                    .collect::<Vec<_>>();

                let mut blocks = funcs
                    .par_chunks(many_lut_chunk)
                    .flat_map(|chunk| {
                        let funcs_ref = chunk
                            .iter()
                            .map(|f| f as &dyn Fn(u64) -> u64)
                            .collect::<Vec<_>>();

                        let lut = self.key.generate_many_lookup_table(funcs_ref.as_slice());
                        self.key.apply_many_lookup_table(block, &lut)
                    })
                    .collect::<Vec<_>>();

                blocks.resize_with(n_blocks as usize, || self.key.create_trivial(0));

                T::from(blocks)
            })
            .collect::<Vec<_>>();

        self.unchecked_sum_ciphertexts_vec_parallelized(to_be_summed)
            .expect("empty input")
    }

    /// Computes the dot product between encrypted booleans and clear values
    ///
    /// * `n_blocks` number of blocks in the resulting ciphertext
    ///
    /// # Panic
    ///
    /// * Panics if `boolean_blocks` and `clears` do not have the same lengths
    /// * Panics if `boolean_blocks` or `clears` is empty
    pub fn smart_boolean_scalar_dot_prod_parallelized<Clear, T>(
        &self,
        boolean_blocks: &mut [BooleanBlock],
        clears: &[Clear],
        n_blocks: u32,
    ) -> T
    where
        Clear: Numeric
            + DecomposableInto<u64>
            + CastInto<usize>
            + CastFrom<u128>
            + Mul<Clear, Output = Clear>
            + AddAssign<Clear>
            + OverflowingAdd<Clear, Output = Clear>,
        T: IntegerRadixCiphertext,
    {
        if boolean_blocks
            .iter()
            .any(|b| b.0.noise_level() > NoiseLevel::NOMINAL || b.0.degree.get() >= 2)
        {
            let id_lut = self.key.generate_lookup_table(|x| u64::from(x != 0));
            boolean_blocks
                .par_iter_mut()
                .filter(|b| b.0.noise_level() > NoiseLevel::NOMINAL || b.0.degree.get() >= 2)
                .for_each(|b| self.key.apply_lookup_table_assign(&mut b.0, &id_lut));
        }

        self.unchecked_boolean_scalar_dot_prod_parallelized(boolean_blocks, clears, n_blocks)
    }

    /// Computes the dot product between encrypted booleans and clear values
    ///
    /// * `n_blocks` number of blocks in the resulting ciphertext
    ///
    /// # Panic
    ///
    /// * Panics if `boolean_blocks` and `clears` do not have the same lengths
    /// * Panics if `boolean_blocks` or `clears` is empty
    pub fn boolean_scalar_dot_prod_parallelized<Clear, T>(
        &self,
        boolean_blocks: &[BooleanBlock],
        clears: &[Clear],
        n_blocks: u32,
    ) -> T
    where
        Clear: Numeric
            + DecomposableInto<u64>
            + CastInto<usize>
            + CastFrom<u128>
            + Mul<Clear, Output = Clear>
            + AddAssign<Clear>
            + OverflowingAdd<Clear, Output = Clear>,
        T: IntegerRadixCiphertext,
    {
        let mut cloned;

        let boolean_blocks = if boolean_blocks
            .iter()
            .any(|b| b.0.noise_level() > NoiseLevel::NOMINAL || b.0.degree.get() >= 2)
        {
            let id_lut = self.key.generate_lookup_table(|x| u64::from(x != 0));
            cloned = boolean_blocks.to_vec();
            cloned
                .par_iter_mut()
                .filter(|b| b.0.noise_level() > NoiseLevel::NOMINAL || b.0.degree.get() >= 2)
                .for_each(|b| self.key.apply_lookup_table_assign(&mut b.0, &id_lut));
            &cloned
        } else {
            boolean_blocks
        };

        self.unchecked_boolean_scalar_dot_prod_parallelized(boolean_blocks, clears, n_blocks)
    }
}
