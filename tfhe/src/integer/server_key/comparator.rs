use rayon::prelude::*;

use super::ServerKey;
use crate::integer::RadixCiphertext;
use crate::shortint::server_key::Accumulator;

/// Simple enum to select whether we are looking for the min or the max
enum MinMaxSelector {
    Max,
    Min,
}

fn has_non_zero_carries(ct: &RadixCiphertext) -> bool {
    ct.blocks
        .iter()
        .any(|block| block.degree.0 >= block.message_modulus.0)
}

/// struct to compare integers
///
/// This struct keeps in memory the LUTs that are used
/// during the comparisons and min/max algorithms
pub struct Comparator<'a> {
    server_key: &'a ServerKey,
    sign_accumulator: Accumulator,
    selection_accumulator: Accumulator,
    mask_accumulator: Accumulator,
    x_accumulator: Accumulator,
    y_accumulator: Accumulator,
}

impl<'a> Comparator<'a> {
    const IS_INFERIOR: u64 = 0;
    const IS_EQUAL: u64 = 1;
    const IS_SUPERIOR: u64 = 2;

    /// Creates a new Comparator for the given ServerKey
    ///
    /// # Panics
    ///
    /// panics if the message space + carry space is inferior to 4 bits
    pub fn new(server_key: &'a ServerKey) -> Self {
        assert!(
            server_key.key.message_modulus.0 * server_key.key.carry_modulus.0 >= 16,
            "At least 4 bits of space (message + carry) are required to be able to do comparisons"
        );

        let message_modulus = server_key.key.message_modulus.0 as u64;
        let sign_accumulator = server_key.key.generate_accumulator(|x| u64::from(x != 0));
        // Comparison encoding
        // -------------------
        // x > y -> 2 = 10
        // x = y -> 1 = 01
        // x < y -> 0 = 00

        // Prev   Curr   Res
        // ----   ----   ---
        //   00     00    00
        //   00     01    00
        //   00     10    00
        //   00     11    -- (unused)
        //
        //   01     00    00
        //   01     01    01
        //   01     10    10
        //   01     11    -- (unused)
        //
        //   10     00    10
        //   10     01    10
        //   10     10    10
        let selection_accumulator = server_key.key.generate_accumulator(|x| {
            [
                Self::IS_INFERIOR,
                Self::IS_INFERIOR,
                Self::IS_INFERIOR,
                Self::IS_INFERIOR,
                Self::IS_INFERIOR,
                Self::IS_EQUAL,
                Self::IS_SUPERIOR,
                Self::IS_SUPERIOR,
                Self::IS_SUPERIOR,
                Self::IS_SUPERIOR,
                Self::IS_SUPERIOR,
            ]
            .get(x as usize)
            .copied()
            // This accumulator / LUT will be used in a context
            // where we know the values are <= 12
            .unwrap_or(0)
        });

        let mask_accumulator =
            server_key
                .key
                .generate_accumulator(|x| if x == 0 { message_modulus } else { 0 });

        let x_accumulator =
            server_key
                .key
                .generate_accumulator(|x| if x < message_modulus { x } else { 0 });

        let y_accumulator = server_key.key.generate_accumulator(|x| {
            if x >= message_modulus {
                x - message_modulus
            } else {
                0
            }
        });

        Self {
            server_key,
            sign_accumulator,
            selection_accumulator,
            mask_accumulator,
            x_accumulator,
            y_accumulator,
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
    fn pack_block_chunk(
        &self,
        chunk: &[crate::shortint::Ciphertext],
    ) -> crate::shortint::Ciphertext {
        let low = &chunk[0];
        let mut high = chunk[1].clone();
        debug_assert!(high.degree.0 < high.message_modulus.0);
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
    fn pack_block_assign(
        &self,
        low: &crate::shortint::Ciphertext,
        high: &mut crate::shortint::Ciphertext,
    ) {
        debug_assert!(high.degree.0 < high.message_modulus.0);
        self.server_key
            .key
            .unchecked_scalar_mul_assign(high, high.message_modulus.0 as u8);
        self.server_key.key.unchecked_add_assign(high, low);
    }

    // lhs will be assigned
    // - 0 if lhs < rhs
    // - 1 if lhs == rhs
    // - 2 if lhs > rhs
    fn compare_block_assign(
        &self,
        lhs: &mut crate::shortint::Ciphertext,
        rhs: &crate::shortint::Ciphertext,
    ) {
        // When rhs > lhs, the subtraction will overflow, and the bit of padding will be set to 1
        // meaning that the output of the pbs will be the negative (modulo message space)
        //
        // Example:
        // lhs: 1, rhs: 3, message modulus: 4, carry modulus 4
        // lhs - rhs = -2 % (4 * 4) = 14 = 1|1110 (padding_bit|b4b3b2b1)
        // Since there was an overflow the bit of padding is 1 and not 0.
        // When applying the LUT for an input value of 14 we would expect 1,
        // but since the bit of padding is 1, we will get -1 modulus our message space,
        // so (-1) % (4 * 4) = 15 = 1|1111
        // We then add one and get 0 = 0|0000

        // Here we need the true lwe sub, not the one that comes from shortint.
        crate::core_crypto::algorithms::lwe_ciphertext_sub_assign(&mut lhs.ct, &rhs.ct);
        self.server_key
            .key
            .keyswitch_programmable_bootstrap_assign(lhs, &self.sign_accumulator);

        // Here Lhs can have the following values: (-1) % (message modulus * carry modulus), 0, 1
        // So the output values after the addition will be: 0, 1, 2
        self.server_key.key.unchecked_scalar_add_assign(lhs, 1);
    }

    /// returns:
    ///
    /// - 0 if lhs < rhs
    /// - 1 if lhs == rhs
    /// - 2 if lhs > rhs
    ///
    /// Expects the carry buffers to be empty
    ///
    /// Requires that the RadixCiphertext block have 4 bits minimum (carry + message)
    fn unchecked_compare(
        &self,
        lhs: &RadixCiphertext,
        rhs: &RadixCiphertext,
    ) -> crate::shortint::Ciphertext {
        assert_eq!(lhs.blocks.len(), rhs.blocks.len());
        let num_block = lhs.blocks.len();

        let comparisons = if lhs.blocks[0].carry_modulus.0 < lhs.blocks[0].message_modulus.0 {
            let mut comparisons = Vec::with_capacity(num_block);
            for i in 0..lhs.blocks.len() {
                let mut lhs = lhs.blocks[i].clone();
                let rhs = &rhs.blocks[i];

                self.compare_block_assign(&mut lhs, rhs);
                comparisons.push(lhs);
            }
            comparisons
        } else {
            let mut lhs_chunks_iter = lhs.blocks.chunks_exact(2);
            let mut rhs_chunks_iter = rhs.blocks.chunks_exact(2);
            let mut comparisons =
                Vec::with_capacity(lhs_chunks_iter.len() + lhs_chunks_iter.remainder().len());

            for (lhs_chunk, rhs_chunk) in lhs_chunks_iter.by_ref().zip(rhs_chunks_iter.by_ref()) {
                let mut packed_lhs = self.pack_block_chunk(lhs_chunk);
                let packed_rhs = self.pack_block_chunk(rhs_chunk);
                self.compare_block_assign(&mut packed_lhs, &packed_rhs);
                comparisons.push(packed_lhs);
            }

            if let ([last_lhs_block], [last_rhs_block]) =
                (lhs_chunks_iter.remainder(), rhs_chunks_iter.remainder())
            {
                let mut last_lhs_block = last_lhs_block.clone();
                self.compare_block_assign(&mut last_lhs_block, last_rhs_block);
                comparisons.push(last_lhs_block)
            }

            comparisons
        };

        // Iterate block from most significant to less significant
        let mut selection = comparisons.last().cloned().unwrap();
        for comparison in comparisons[0..comparisons.len() - 1].iter().rev() {
            self.server_key
                .key
                .unchecked_scalar_mul_assign(&mut selection, 4);
            self.server_key
                .key
                .unchecked_add_assign(&mut selection, comparison);

            self.server_key.key.keyswitch_programmable_bootstrap_assign(
                &mut selection,
                &self.selection_accumulator,
            );
        }

        selection
    }

    /// Expects the carry buffers to be empty
    ///
    /// Requires that the RadixCiphertext block have 4 bits minimum (carry + message)
    fn unchecked_compare_parallelized(
        &self,
        lhs: &RadixCiphertext,
        rhs: &RadixCiphertext,
    ) -> crate::shortint::Ciphertext {
        assert_eq!(lhs.blocks.len(), rhs.blocks.len());

        let num_block = lhs.blocks.len();
        let num_block_is_odd = num_block % 2;

        let mut comparisons = if lhs.blocks[0].carry_modulus.0 < lhs.blocks[0].message_modulus.0 {
            let mut comparisons = Vec::with_capacity(num_block);
            lhs.blocks
                .par_iter()
                .zip(rhs.blocks.par_iter())
                .map(|(lhs, rhs)| {
                    let mut lhs = lhs.clone();
                    self.compare_block_assign(&mut lhs, rhs);
                    lhs
                })
                .collect_into_vec(&mut comparisons);
            comparisons
        } else {
            let mut comparisons = Vec::with_capacity((num_block / 2) + num_block_is_odd);
            lhs.blocks
                .par_chunks_exact(2)
                .zip(rhs.blocks.par_chunks_exact(2))
                .map(|(lhs_chunk, rhs_chunk)| {
                    let (mut packed_lhs, packed_rhs) = rayon::join(
                        || self.pack_block_chunk(lhs_chunk),
                        || self.pack_block_chunk(rhs_chunk),
                    );

                    self.compare_block_assign(&mut packed_lhs, &packed_rhs);
                    packed_lhs
                })
                .collect_into_vec(&mut comparisons);

            if num_block_is_odd == 1 {
                let mut last_lhs_block = lhs.blocks[num_block - 1].clone();
                let last_rhs_block = &rhs.blocks[num_block - 1];
                self.compare_block_assign(&mut last_lhs_block, last_rhs_block);
                comparisons.push(last_lhs_block);
            }

            comparisons
        };

        let mut comparisons_2 = Vec::with_capacity(comparisons.len() / 2);
        while comparisons.len() != 1 {
            comparisons
                .par_chunks_exact(2)
                .map(|chunk| {
                    let (low, high) = (&chunk[0], &chunk[1]);
                    let mut high = high.clone();

                    // We don't use pack_block_assign as the offset '4' does not depend on params
                    self.server_key
                        .key
                        .unchecked_scalar_mul_assign(&mut high, 4);
                    self.server_key.key.unchecked_add_assign(&mut high, low);

                    self.server_key.key.keyswitch_programmable_bootstrap_assign(
                        &mut high,
                        &self.selection_accumulator,
                    );
                    high
                })
                .collect_into_vec(&mut comparisons_2);

            if (comparisons.len() % 2) == 1 {
                comparisons_2.push(comparisons[comparisons.len() - 1].clone());
            }

            std::mem::swap(&mut comparisons_2, &mut comparisons);
        }
        let selection = comparisons.drain(..).next().unwrap();

        selection
    }

    fn smart_compare(
        &self,
        lhs: &mut RadixCiphertext,
        rhs: &mut RadixCiphertext,
    ) -> crate::shortint::Ciphertext {
        if has_non_zero_carries(lhs) {
            self.server_key.full_propagate(lhs);
        }
        if has_non_zero_carries(rhs) {
            self.server_key.full_propagate(rhs);
        }
        self.unchecked_compare(lhs, rhs)
    }

    fn smart_compare_parallelized(
        &self,
        lhs: &mut RadixCiphertext,
        rhs: &mut RadixCiphertext,
    ) -> crate::shortint::Ciphertext {
        rayon::join(
            || {
                if has_non_zero_carries(lhs) {
                    self.server_key.full_propagate_parallelized(lhs);
                }
            },
            || {
                if has_non_zero_carries(rhs) {
                    self.server_key.full_propagate_parallelized(rhs);
                }
            },
        );
        self.unchecked_compare_parallelized(lhs, rhs)
    }

    /// Expects the carry buffers to be empty
    fn unchecked_min_or_max(
        &self,
        lhs: &RadixCiphertext,
        rhs: &RadixCiphertext,
        selector: MinMaxSelector,
    ) -> RadixCiphertext {
        let (x_accumulator, y_accumulator) = match selector {
            MinMaxSelector::Max => (&self.x_accumulator, &self.y_accumulator),
            MinMaxSelector::Min => (&self.y_accumulator, &self.x_accumulator),
        };
        let num_block = lhs.blocks.len();

        let mut mask = self.unchecked_compare(lhs, rhs);
        self.server_key
            .key
            .keyswitch_programmable_bootstrap_assign(&mut mask, &self.mask_accumulator);

        let mut result = Vec::with_capacity(num_block);
        for i in 0..num_block {
            let lhs_masked = self.server_key.key.unchecked_add(&lhs.blocks[i], &mask);
            let rhs_masked = self.server_key.key.unchecked_add(&rhs.blocks[i], &mask);

            let maybe_x = self
                .server_key
                .key
                .keyswitch_programmable_bootstrap(&lhs_masked, x_accumulator);
            let maybe_y = self
                .server_key
                .key
                .keyswitch_programmable_bootstrap(&rhs_masked, y_accumulator);

            let r = self.server_key.key.unchecked_add(&maybe_x, &maybe_y);
            result.push(r)
        }

        RadixCiphertext { blocks: result }
    }

    /// Expects the carry buffers to be empty
    fn unchecked_min_or_max_parallelized(
        &self,
        lhs: &RadixCiphertext,
        rhs: &RadixCiphertext,
        selector: MinMaxSelector,
    ) -> RadixCiphertext {
        let (x_accumulator, y_accumulator) = match selector {
            MinMaxSelector::Max => (&self.x_accumulator, &self.y_accumulator),
            MinMaxSelector::Min => (&self.y_accumulator, &self.x_accumulator),
        };

        let mut mask = self.unchecked_compare_parallelized(lhs, rhs);
        self.server_key
            .key
            .keyswitch_programmable_bootstrap_assign(&mut mask, &self.mask_accumulator);

        let blocks = lhs
            .blocks
            .par_iter()
            .zip(rhs.blocks.par_iter())
            .map(|(lhs_block, rhs_block)| {
                let (maybe_x, maybe_y) = rayon::join(
                    || {
                        let mut lhs_masked = self.server_key.key.unchecked_add(lhs_block, &mask);
                        self.server_key.key.keyswitch_programmable_bootstrap_assign(
                            &mut lhs_masked,
                            x_accumulator,
                        );
                        lhs_masked
                    },
                    || {
                        let mut rhs_masked = self.server_key.key.unchecked_add(rhs_block, &mask);
                        self.server_key.key.keyswitch_programmable_bootstrap_assign(
                            &mut rhs_masked,
                            y_accumulator,
                        );
                        rhs_masked
                    },
                );

                self.server_key.key.unchecked_add(&maybe_x, &maybe_y)
            })
            .collect::<Vec<_>>();

        RadixCiphertext { blocks }
    }

    fn smart_min_or_max(
        &self,
        lhs: &mut RadixCiphertext,
        rhs: &mut RadixCiphertext,
        selector: MinMaxSelector,
    ) -> RadixCiphertext {
        if has_non_zero_carries(lhs) {
            self.server_key.full_propagate_parallelized(lhs);
        }
        if has_non_zero_carries(rhs) {
            self.server_key.full_propagate_parallelized(rhs);
        }
        self.unchecked_min_or_max(lhs, rhs, selector)
    }

    fn smart_min_or_max_parallelized(
        &self,
        lhs: &mut RadixCiphertext,
        rhs: &mut RadixCiphertext,
        selector: MinMaxSelector,
    ) -> RadixCiphertext {
        rayon::join(
            || {
                if has_non_zero_carries(lhs) {
                    self.server_key.full_propagate_parallelized(lhs);
                }
            },
            || {
                if has_non_zero_carries(rhs) {
                    self.server_key.full_propagate_parallelized(rhs);
                }
            },
        );
        self.unchecked_min_or_max_parallelized(lhs, rhs, selector)
    }

    fn map_comparison_result<F>(
        &self,
        comparison: crate::shortint::Ciphertext,
        sign_result_handler_fn: F,
        num_blocks: usize,
    ) -> RadixCiphertext
    where
        F: Fn(u64) -> u64,
    {
        let acc = self
            .server_key
            .key
            .generate_accumulator(sign_result_handler_fn);
        let result_block = self
            .server_key
            .key
            .keyswitch_programmable_bootstrap(&comparison, &acc);

        let mut blocks = Vec::with_capacity(num_blocks);
        blocks.push(result_block);
        for _ in 0..num_blocks - 1 {
            blocks.push(self.server_key.key.create_trivial(0));
        }

        RadixCiphertext { blocks }
    }

    /// Expects the carry buffers to be empty
    fn unchecked_comparison_impl<CmpFn, F>(
        &self,
        comparison_fn: CmpFn,
        sign_result_handler_fn: F,
        lhs: &RadixCiphertext,
        rhs: &RadixCiphertext,
    ) -> RadixCiphertext
    where
        CmpFn: Fn(&Self, &RadixCiphertext, &RadixCiphertext) -> crate::shortint::Ciphertext,
        F: Fn(u64) -> u64,
    {
        let comparison = comparison_fn(self, lhs, rhs);
        self.map_comparison_result(comparison, sign_result_handler_fn, lhs.blocks.len())
    }

    /// Expects the carry buffers to be empty
    fn smart_comparison_impl<CmpFn, F>(
        &self,
        smart_comparison_fn: CmpFn,
        sign_result_handler_fn: F,
        lhs: &mut RadixCiphertext,
        rhs: &mut RadixCiphertext,
    ) -> RadixCiphertext
    where
        CmpFn: Fn(&Self, &mut RadixCiphertext, &mut RadixCiphertext) -> crate::shortint::Ciphertext,
        F: Fn(u64) -> u64,
    {
        let comparison = smart_comparison_fn(self, lhs, rhs);
        self.map_comparison_result(comparison, sign_result_handler_fn, lhs.blocks.len())
    }

    //======================================
    // Unchecked Single-Threaded operations
    //======================================

    pub fn unchecked_eq(&self, lhs: &RadixCiphertext, rhs: &RadixCiphertext) -> RadixCiphertext {
        self.unchecked_comparison_impl(
            Self::unchecked_compare,
            |x| u64::from(x == Self::IS_EQUAL),
            lhs,
            rhs,
        )
    }

    pub fn unchecked_gt(&self, lhs: &RadixCiphertext, rhs: &RadixCiphertext) -> RadixCiphertext {
        self.unchecked_comparison_impl(
            Self::unchecked_compare,
            |x| u64::from(x == Self::IS_SUPERIOR),
            lhs,
            rhs,
        )
    }

    pub fn unchecked_ge(&self, lhs: &RadixCiphertext, rhs: &RadixCiphertext) -> RadixCiphertext {
        self.unchecked_comparison_impl(
            Self::unchecked_compare,
            |x| u64::from(x == Self::IS_EQUAL || x == Self::IS_SUPERIOR),
            lhs,
            rhs,
        )
    }

    pub fn unchecked_lt(&self, lhs: &RadixCiphertext, rhs: &RadixCiphertext) -> RadixCiphertext {
        self.unchecked_comparison_impl(
            Self::unchecked_compare,
            |x| u64::from(x == Self::IS_INFERIOR),
            lhs,
            rhs,
        )
    }

    pub fn unchecked_le(&self, lhs: &RadixCiphertext, rhs: &RadixCiphertext) -> RadixCiphertext {
        self.unchecked_comparison_impl(
            Self::unchecked_compare,
            |x| u64::from(x == Self::IS_EQUAL || x == Self::IS_INFERIOR),
            lhs,
            rhs,
        )
    }

    pub fn unchecked_max(&self, lhs: &RadixCiphertext, rhs: &RadixCiphertext) -> RadixCiphertext {
        self.unchecked_min_or_max(lhs, rhs, MinMaxSelector::Max)
    }

    pub fn unchecked_min(&self, lhs: &RadixCiphertext, rhs: &RadixCiphertext) -> RadixCiphertext {
        self.unchecked_min_or_max(lhs, rhs, MinMaxSelector::Min)
    }

    //======================================
    // Unchecked Multi-Threaded operations
    //======================================

    pub fn unchecked_eq_parallelized(
        &self,
        lhs: &RadixCiphertext,
        rhs: &RadixCiphertext,
    ) -> RadixCiphertext {
        self.unchecked_comparison_impl(
            Self::unchecked_compare_parallelized,
            |x| u64::from(x == Self::IS_EQUAL),
            lhs,
            rhs,
        )
    }

    pub fn unchecked_gt_parallelized(
        &self,
        lhs: &RadixCiphertext,
        rhs: &RadixCiphertext,
    ) -> RadixCiphertext {
        self.unchecked_comparison_impl(
            Self::unchecked_compare_parallelized,
            |x| u64::from(x == Self::IS_SUPERIOR),
            lhs,
            rhs,
        )
    }

    pub fn unchecked_ge_parallelized(
        &self,
        lhs: &RadixCiphertext,
        rhs: &RadixCiphertext,
    ) -> RadixCiphertext {
        self.unchecked_comparison_impl(
            Self::unchecked_compare_parallelized,
            |x| u64::from(x == Self::IS_EQUAL || x == Self::IS_SUPERIOR),
            lhs,
            rhs,
        )
    }

    pub fn unchecked_lt_parallelized(
        &self,
        lhs: &RadixCiphertext,
        rhs: &RadixCiphertext,
    ) -> RadixCiphertext {
        self.unchecked_comparison_impl(
            Self::unchecked_compare_parallelized,
            |x| u64::from(x == Self::IS_INFERIOR),
            lhs,
            rhs,
        )
    }

    pub fn unchecked_le_parallelized(
        &self,
        lhs: &RadixCiphertext,
        rhs: &RadixCiphertext,
    ) -> RadixCiphertext {
        self.unchecked_comparison_impl(
            Self::unchecked_compare_parallelized,
            |x| u64::from(x == Self::IS_EQUAL || x == Self::IS_INFERIOR),
            lhs,
            rhs,
        )
    }

    pub fn unchecked_max_parallelized(
        &self,
        lhs: &RadixCiphertext,
        rhs: &RadixCiphertext,
    ) -> RadixCiphertext {
        self.unchecked_min_or_max_parallelized(lhs, rhs, MinMaxSelector::Max)
    }

    pub fn unchecked_min_parallelized(
        &self,
        lhs: &RadixCiphertext,
        rhs: &RadixCiphertext,
    ) -> RadixCiphertext {
        self.unchecked_min_or_max_parallelized(lhs, rhs, MinMaxSelector::Min)
    }

    //======================================
    // Smart Single-Threaded operations
    //======================================

    pub fn smart_eq(
        &self,
        lhs: &mut RadixCiphertext,
        rhs: &mut RadixCiphertext,
    ) -> RadixCiphertext {
        self.smart_comparison_impl(
            Self::smart_compare,
            |x| u64::from(x == Self::IS_EQUAL),
            lhs,
            rhs,
        )
    }

    pub fn smart_gt(
        &self,
        lhs: &mut RadixCiphertext,
        rhs: &mut RadixCiphertext,
    ) -> RadixCiphertext {
        self.smart_comparison_impl(
            Self::smart_compare,
            |x| u64::from(x == Self::IS_SUPERIOR),
            lhs,
            rhs,
        )
    }

    pub fn smart_ge(
        &self,
        lhs: &mut RadixCiphertext,
        rhs: &mut RadixCiphertext,
    ) -> RadixCiphertext {
        self.smart_comparison_impl(
            Self::smart_compare,
            |x| u64::from(x == Self::IS_EQUAL || x == Self::IS_SUPERIOR),
            lhs,
            rhs,
        )
    }

    pub fn smart_lt(
        &self,
        lhs: &mut RadixCiphertext,
        rhs: &mut RadixCiphertext,
    ) -> RadixCiphertext {
        self.smart_comparison_impl(
            Self::smart_compare,
            |x| u64::from(x == Self::IS_INFERIOR),
            lhs,
            rhs,
        )
    }

    pub fn smart_le(
        &self,
        lhs: &mut RadixCiphertext,
        rhs: &mut RadixCiphertext,
    ) -> RadixCiphertext {
        self.smart_comparison_impl(
            Self::smart_compare,
            |x| u64::from(x == Self::IS_EQUAL || x == Self::IS_INFERIOR),
            lhs,
            rhs,
        )
    }

    pub fn smart_max(
        &self,
        lhs: &mut RadixCiphertext,
        rhs: &mut RadixCiphertext,
    ) -> RadixCiphertext {
        self.smart_min_or_max(lhs, rhs, MinMaxSelector::Max)
    }

    pub fn smart_min(
        &self,
        lhs: &mut RadixCiphertext,
        rhs: &mut RadixCiphertext,
    ) -> RadixCiphertext {
        self.smart_min_or_max(lhs, rhs, MinMaxSelector::Min)
    }

    //======================================
    // Smart Multi-Threaded operations
    //======================================

    pub fn smart_eq_parallelized(
        &self,
        lhs: &mut RadixCiphertext,
        rhs: &mut RadixCiphertext,
    ) -> RadixCiphertext {
        self.smart_comparison_impl(
            Self::smart_compare_parallelized,
            |x| u64::from(x == Self::IS_EQUAL),
            lhs,
            rhs,
        )
    }

    pub fn smart_gt_parallelized(
        &self,
        lhs: &mut RadixCiphertext,
        rhs: &mut RadixCiphertext,
    ) -> RadixCiphertext {
        self.smart_comparison_impl(
            Self::smart_compare_parallelized,
            |x| u64::from(x == Self::IS_SUPERIOR),
            lhs,
            rhs,
        )
    }

    pub fn smart_ge_parallelized(
        &self,
        lhs: &mut RadixCiphertext,
        rhs: &mut RadixCiphertext,
    ) -> RadixCiphertext {
        self.smart_comparison_impl(
            Self::smart_compare_parallelized,
            |x| u64::from(x == Self::IS_EQUAL || x == Self::IS_SUPERIOR),
            lhs,
            rhs,
        )
    }

    pub fn smart_lt_parallelized(
        &self,
        lhs: &mut RadixCiphertext,
        rhs: &mut RadixCiphertext,
    ) -> RadixCiphertext {
        self.smart_comparison_impl(
            Self::smart_compare_parallelized,
            |x| u64::from(x == Self::IS_INFERIOR),
            lhs,
            rhs,
        )
    }

    pub fn smart_le_parallelized(
        &self,
        lhs: &mut RadixCiphertext,
        rhs: &mut RadixCiphertext,
    ) -> RadixCiphertext {
        self.smart_comparison_impl(
            Self::smart_compare_parallelized,
            |x| u64::from(x == Self::IS_EQUAL || x == Self::IS_INFERIOR),
            lhs,
            rhs,
        )
    }

    pub fn smart_max_parallelized(
        &self,
        lhs: &mut RadixCiphertext,
        rhs: &mut RadixCiphertext,
    ) -> RadixCiphertext {
        self.smart_min_or_max_parallelized(lhs, rhs, MinMaxSelector::Max)
    }

    pub fn smart_min_parallelized(
        &self,
        lhs: &mut RadixCiphertext,
        rhs: &mut RadixCiphertext,
    ) -> RadixCiphertext {
        self.smart_min_or_max_parallelized(lhs, rhs, MinMaxSelector::Min)
    }
}

#[cfg(test)]
mod tests {
    use super::Comparator;
    use crate::integer::{gen_keys, RadixCiphertext, U256};
    use crate::shortint::Parameters;
    use rand;
    use rand::prelude::*;

    /// Function to test an "unchecked" compartor function.
    ///
    /// This calls the `unchecked_comparator_method` with fresh ciphertexts
    /// and compares that it gives the same results as the `clear_fn`.
    fn test_unchecked_function<UncheckedFn, ClearF>(
        param: Parameters,
        num_test: usize,
        unchecked_comparator_method: UncheckedFn,
        clear_fn: ClearF,
    ) where
        UncheckedFn: for<'a, 'b> Fn(
            &'a Comparator<'b>,
            &'a RadixCiphertext,
            &'a RadixCiphertext,
        ) -> RadixCiphertext,
        ClearF: Fn(U256, U256) -> U256,
    {
        let mut rng = rand::thread_rng();

        let num_block = (256f64 / (param.message_modulus.0 as f64).log(2.0)).ceil() as usize;

        let (cks, sks) = gen_keys(&param);
        let comparator = Comparator::new(&sks);

        for _ in 0..num_test {
            let clear_a = rng.gen::<U256>();
            let clear_b = rng.gen::<U256>();

            let a = cks.encrypt_radix(clear_a, num_block);
            let b = cks.encrypt_radix(clear_b, num_block);

            let result = unchecked_comparator_method(&comparator, &a, &b);
            let mut decrypted = U256::default();
            cks.decrypt_radix_into(&result, &mut decrypted);

            let expected_result = clear_fn(clear_a, clear_b);

            assert_eq!(decrypted, expected_result);
        }
    }

    /// Function to test a "smart" comparator function.
    ///
    /// This calls the `smart_comparator_method` with non-fresh ciphertexts,
    /// that is ciphertexts that have non-zero carries, and compares that the result is
    /// the same as the one of`clear_fn`.
    fn test_smart_function<SmartFn, ClearF>(
        param: Parameters,
        num_test: usize,
        smart_comparator_method: SmartFn,
        clear_fn: ClearF,
    ) where
        SmartFn: for<'a, 'b> Fn(
            &'a Comparator<'b>,
            &'a mut RadixCiphertext,
            &'a mut RadixCiphertext,
        ) -> RadixCiphertext,
        ClearF: Fn(U256, U256) -> U256,
    {
        let (cks, sks) = gen_keys(&param);
        let num_block = (256f64 / (param.message_modulus.0 as f64).log(2.0)).ceil() as usize;
        let comparator = Comparator::new(&sks);

        let mut rng = rand::thread_rng();

        for _ in 0..num_test {
            let mut clear_0 = rng.gen::<U256>();
            let mut clear_1 = rng.gen::<U256>();
            let mut ct_0 = cks.encrypt_radix(clear_0, num_block);
            let mut ct_1 = cks.encrypt_radix(clear_1, num_block);

            // Raise the degree, so as to ensure worst case path in operations
            while !super::has_non_zero_carries(&ct_0) {
                let clear_2 = rng.gen::<U256>();
                let ct_2 = cks.encrypt_radix(clear_2, num_block);
                sks.unchecked_add_assign(&mut ct_0, &ct_2);
                clear_0 += clear_2;
            }

            while !super::has_non_zero_carries(&ct_1) {
                let clear_2 = rng.gen::<U256>();
                let ct_2 = cks.encrypt_radix(clear_2, num_block);
                sks.unchecked_add_assign(&mut ct_1, &ct_2);
                clear_1 += clear_2;
            }

            // Sanity decryption checks
            {
                let mut a = U256::default();
                cks.decrypt_radix_into(&ct_0, &mut a);
                assert_eq!(a, clear_0);

                cks.decrypt_radix_into(&ct_1, &mut a);
                assert_eq!(a, clear_1);
            }

            assert!(super::has_non_zero_carries(&ct_0));
            assert!(super::has_non_zero_carries(&ct_1));
            let encrypted_result = smart_comparator_method(&comparator, &mut ct_0, &mut ct_1);
            assert!(!super::has_non_zero_carries(&ct_0));
            assert!(!super::has_non_zero_carries(&ct_1));

            // Sanity decryption checks
            {
                let mut a = U256::default();
                cks.decrypt_radix_into(&ct_0, &mut a);
                assert_eq!(a, clear_0);
                cks.decrypt_radix_into(&ct_1, &mut a);
                assert_eq!(a, clear_1);
            }

            let mut decrypted_result = U256::default();
            cks.decrypt_radix_into(&encrypted_result, &mut decrypted_result);

            let expected_result = clear_fn(clear_0, clear_1);
            assert_eq!(decrypted_result, expected_result);
        }
    }

    fn test_unchecked_min_256_bits(params: crate::shortint::Parameters, num_tests: usize) {
        test_unchecked_function(
            params,
            num_tests,
            |comparator, lhs, rhs| comparator.unchecked_min(lhs, rhs),
            std::cmp::min,
        )
    }

    fn test_unchecked_max_256_bits(params: crate::shortint::Parameters, num_tests: usize) {
        test_unchecked_function(
            params,
            num_tests,
            |comparator, lhs, rhs| comparator.unchecked_max(lhs, rhs),
            std::cmp::max,
        )
    }

    fn test_unchecked_min_parallelized_256_bits(
        params: crate::shortint::Parameters,
        num_tests: usize,
    ) {
        test_unchecked_function(
            params,
            num_tests,
            |comparator, lhs, rhs| comparator.unchecked_min_parallelized(lhs, rhs),
            std::cmp::min,
        )
    }

    fn test_unchecked_max_parallelized_256_bits(
        params: crate::shortint::Parameters,
        num_tests: usize,
    ) {
        test_unchecked_function(
            params,
            num_tests,
            |comparator, lhs, rhs| comparator.unchecked_max_parallelized(lhs, rhs),
            std::cmp::max,
        )
    }

    macro_rules! create_parametrized_test{
        ($name:ident { $($param:ident),* }) => {
            ::paste::paste! {
                $(
                #[test]
                fn [<test_ $name _ $param:lower>]() {
                    $name($param)
                }
                )*
            }
        };
    }

    /// This macro generates the tests for a given comparison fn
    ///
    /// All our comparison function have 4 variants:
    /// - unchecked_$comparison_name
    /// - unchecked_$comparison_name_parallelized
    /// - smart_$comparison_name
    /// - smart_$comparison_name_parallelized
    ///
    /// So, for example, for the `gt` comparison fn, this macro will generate the tests for
    /// the 4 variants described above
    macro_rules! define_comparison_test_functions {
        ($comparison_name:ident) => {
            paste::paste!{
                fn [<unchecked_ $comparison_name _256_bits>](params: crate::shortint::Parameters) {
                    let num_tests = 1;
                    test_unchecked_function(
                        params,
                        num_tests,
                        |comparator, lhs, rhs| comparator.[<unchecked_ $comparison_name>](lhs, rhs),
                        |lhs, rhs| U256::from(<U256>::$comparison_name(&lhs, &rhs) as u128),
                    )
                }

                fn [<unchecked_ $comparison_name _parallelized_256_bits>](params: crate::shortint::Parameters) {
                    let num_tests = 1;
                    test_unchecked_function(
                        params,
                        num_tests,
                        |comparator, lhs, rhs| comparator.[<unchecked_ $comparison_name _parallelized>](lhs, rhs),
                        |lhs, rhs| U256::from(<U256>::$comparison_name(&lhs, &rhs) as u128),
                    )
                }

                fn [<smart_ $comparison_name _256_bits>](params: crate::shortint::Parameters) {
                    let num_tests = 1;
                    test_smart_function(
                        params,
                        num_tests,
                        |comparator, lhs, rhs| comparator.[<smart_ $comparison_name>](lhs, rhs),
                        |lhs, rhs| U256::from(<U256>::$comparison_name(&lhs, &rhs) as u128),
                    )
                }

                fn [<smart_ $comparison_name _parallelized_256_bits>](params: crate::shortint::Parameters) {
                    let num_tests = 1;
                    test_smart_function(
                        params,
                        num_tests,
                        |comparator, lhs, rhs| comparator.[<smart_ $comparison_name _parallelized>](lhs, rhs),
                        |lhs, rhs| U256::from(<U256>::$comparison_name(&lhs, &rhs) as u128),
                    )
                }

                create_parametrized_test!([<unchecked_ $comparison_name _256_bits>]
                {
                    PARAM_MESSAGE_2_CARRY_2,
                    PARAM_MESSAGE_3_CARRY_3,
                    PARAM_MESSAGE_4_CARRY_4
                });
                create_parametrized_test!([<unchecked_ $comparison_name _parallelized_256_bits>]
                {
                    PARAM_MESSAGE_2_CARRY_2,
                    PARAM_MESSAGE_3_CARRY_3,
                    PARAM_MESSAGE_4_CARRY_4
                });

                create_parametrized_test!([<smart_ $comparison_name _256_bits>]
                {
                    PARAM_MESSAGE_2_CARRY_2,
                    // We don't use PARAM_MESSAGE_3_CARRY_3,
                    // as smart test might overflow values
                    // and when using 3_3 to represent 256 we actually have more than 256 bits
                    // of message so the overflow behaviour is not the same, leading to false negatives
                    PARAM_MESSAGE_4_CARRY_4
                });
                create_parametrized_test!([<smart_ $comparison_name _parallelized_256_bits>]
                {
                    PARAM_MESSAGE_2_CARRY_2,
                    // We don't use PARAM_MESSAGE_3_CARRY_3,
                    // as smart test might overflow values
                    // and when using 3_3 to represent 256 we actually have more than 256 bits
                    // of message so the overflow behaviour is not the same, leading to false negatives
                    PARAM_MESSAGE_4_CARRY_4
                });
            }
        };
    }

    use crate::shortint::parameters::{
        PARAM_MESSAGE_2_CARRY_2, PARAM_MESSAGE_3_CARRY_3, PARAM_MESSAGE_4_CARRY_4,
    };

    define_comparison_test_functions!(eq);
    define_comparison_test_functions!(lt);
    define_comparison_test_functions!(le);
    define_comparison_test_functions!(gt);
    define_comparison_test_functions!(ge);

    //================
    // Min
    //================

    #[test]
    fn test_unchecked_min_256_bits_param_message_2_carry_2() {
        test_unchecked_min_256_bits(crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2, 4)
    }

    #[test]
    fn test_unchecked_min_256_bits_param_message_3_carry_3() {
        test_unchecked_min_256_bits(crate::shortint::parameters::PARAM_MESSAGE_3_CARRY_3, 2)
    }

    #[test]
    fn test_unchecked_min_256_bits_param_message_4_carry_4() {
        test_unchecked_min_256_bits(crate::shortint::parameters::PARAM_MESSAGE_4_CARRY_4, 2)
    }

    #[test]
    fn test_unchecked_min_parallelized_256_bits_param_message_2_carry_2() {
        test_unchecked_min_parallelized_256_bits(
            crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2,
            4,
        )
    }

    #[test]
    fn test_unchecked_min_parallelized_256_bits_param_message_3_carry_3() {
        test_unchecked_min_parallelized_256_bits(
            crate::shortint::parameters::PARAM_MESSAGE_3_CARRY_3,
            2,
        )
    }

    #[test]
    fn test_unchecked_min_parallelized_256_bits_param_message_4_carry_4() {
        test_unchecked_min_parallelized_256_bits(
            crate::shortint::parameters::PARAM_MESSAGE_4_CARRY_4,
            2,
        )
    }

    //================
    // Max
    //================

    #[test]
    fn test_unchecked_max_256_bits_param_message_2_carry_2() {
        test_unchecked_max_256_bits(crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2, 4)
    }

    #[test]
    fn test_unchecked_max_256_bits_param_message_3_carry_3() {
        test_unchecked_max_256_bits(crate::shortint::parameters::PARAM_MESSAGE_3_CARRY_3, 2)
    }

    #[test]
    fn test_unchecked_max_256_bits_param_message_4_carry_4() {
        test_unchecked_max_256_bits(crate::shortint::parameters::PARAM_MESSAGE_4_CARRY_4, 2)
    }

    #[test]
    fn test_unchecked_max_parallelized_256_bits_param_message_2_carry_2() {
        test_unchecked_max_parallelized_256_bits(
            crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2,
            4,
        )
    }

    #[test]
    fn test_unchecked_max_parallelized_256_bits_param_message_3_carry_3() {
        test_unchecked_max_parallelized_256_bits(
            crate::shortint::parameters::PARAM_MESSAGE_3_CARRY_3,
            2,
        )
    }

    #[test]
    fn test_unchecked_max_parallelized_256_bits_param_message_4_carry_4() {
        test_unchecked_max_parallelized_256_bits(
            crate::shortint::parameters::PARAM_MESSAGE_4_CARRY_4,
            2,
        )
    }
}
