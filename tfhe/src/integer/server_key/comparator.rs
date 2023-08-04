use rayon::prelude::*;

use super::ServerKey;
use crate::core_crypto::prelude::Plaintext;
use crate::integer::block_decomposition::{BlockDecomposer, DecomposableInto};
use crate::integer::ciphertext::RadixCiphertext;
use crate::shortint::server_key::LookupTableOwned;
use crate::shortint::Ciphertext;

/// Used for compare_blocks_with_zero
pub(crate) enum ZeroComparisonType {
    // We want to compare with zeros for equality (==)
    Equality,
    // We want to compare with zeros for difference (!=)
    Difference,
}

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
    sign_lut: LookupTableOwned,
    sign_reduction_lsb_msb_lut: LookupTableOwned,
    sign_to_offset_lut: LookupTableOwned,
    lhs_lut: LookupTableOwned,
    rhs_lut: LookupTableOwned,
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
        let sign_lut = server_key.key.generate_lookup_table(|x| u64::from(x != 0));
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
        let sign_reduction_lsb_msb_lut = server_key.key.generate_lookup_table(|x| {
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

        let sign_to_offset_lut = server_key.key.generate_lookup_table(|sign| {
            if sign == Self::IS_INFERIOR {
                message_modulus
            } else {
                0
            }
        });

        let lhs_lut = server_key
            .key
            .generate_lookup_table(|x| if x < message_modulus { x } else { 0 });

        let rhs_lut = server_key.key.generate_lookup_table(|x| {
            if x >= message_modulus {
                x - message_modulus
            } else {
                0
            }
        });

        Self {
            server_key,
            sign_lut,
            sign_reduction_lsb_msb_lut,
            sign_to_offset_lut,
            lhs_lut,
            rhs_lut,
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
        self.server_key.pack_block_chunk(chunk)
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
            .apply_lookup_table_assign(lhs, &self.sign_lut);

        // Here Lhs can have the following values: (-1) % (message modulus * carry modulus), 0, 1
        // So the output values after the addition will be: 0, 1, 2
        self.server_key.key.unchecked_scalar_add_assign(lhs, 1);
    }

    // lhs will be assigned
    // - 0 if lhs < rhs
    // - 1 if lhs == rhs
    // - 2 if lhs > rhs
    fn scalar_compare_block_assign(&self, lhs: &mut crate::shortint::Ciphertext, scalar: u8) {
        // Same logic as compare_block_assign
        // but rhs is a scalar
        let delta =
            (1u64 << (u64::BITS as u64 - 1)) / (lhs.carry_modulus.0 * lhs.message_modulus.0) as u64;
        let plaintext = Plaintext((scalar as u64) * delta);
        crate::core_crypto::algorithms::lwe_ciphertext_plaintext_sub_assign(&mut lhs.ct, plaintext);
        self.server_key
            .key
            .apply_lookup_table_assign(lhs, &self.sign_lut);

        self.server_key.key.unchecked_scalar_add_assign(lhs, 1);
    }

    fn reduce_two_sign_blocks_assign(
        &self,
        msb_sign: &mut crate::shortint::Ciphertext,
        lsb_sign: &crate::shortint::Ciphertext,
    ) {
        // We don't use pack_block_assign as the offset '4' does not depend on params
        self.server_key.key.unchecked_scalar_mul_assign(msb_sign, 4);
        self.server_key.key.unchecked_add_assign(msb_sign, lsb_sign);

        self.server_key
            .key
            .apply_lookup_table_assign(msb_sign, &self.sign_reduction_lsb_msb_lut);
    }

    /// Reduces a vec containing shortint blocks that encrypts a sign
    /// (inferior, equal, superior) to one single shortint block containing the
    /// final sign
    fn reduce_signs_parallelized(
        &self,
        mut sign_blocks: Vec<crate::shortint::Ciphertext>,
    ) -> crate::shortint::Ciphertext
where {
        let mut sign_blocks_2 = Vec::with_capacity(sign_blocks.len() / 2);
        while sign_blocks.len() != 1 {
            sign_blocks
                .par_chunks_exact(2)
                .map(|chunk| {
                    let (low, high) = (&chunk[0], &chunk[1]);
                    let mut high = high.clone();
                    self.reduce_two_sign_blocks_assign(&mut high, low);
                    high
                })
                .collect_into_vec(&mut sign_blocks_2);

            if (sign_blocks.len() % 2) == 1 {
                sign_blocks_2.push(sign_blocks[sign_blocks.len() - 1].clone());
            }

            std::mem::swap(&mut sign_blocks_2, &mut sign_blocks);
        }
        sign_blocks.into_iter().next().unwrap()
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
    fn unchecked_sign(
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

            self.server_key
                .key
                .apply_lookup_table_assign(&mut selection, &self.sign_reduction_lsb_msb_lut);
        }

        selection
    }

    /// Expects the carry buffers to be empty
    ///
    /// Requires that the RadixCiphertext block have 4 bits minimum (carry + message)
    ///
    /// This functions takes two ciphertext:
    ///
    /// It returns a Vec of block that will contain the sign of the comparison
    /// (Self::IS_INFERIOR, Self::IS_EQUAL, Self::IS_SUPERIOR)
    ///
    /// The output len may be shorter as blocks may be packed
    fn unchecked_sign_parallelized(
        &self,
        lhs: &RadixCiphertext,
        rhs: &RadixCiphertext,
    ) -> crate::shortint::Ciphertext {
        assert_eq!(lhs.blocks.len(), rhs.blocks.len());

        let num_block = lhs.blocks.len();
        let num_block_is_odd = num_block % 2;

        let comparisons = if lhs.blocks[0].carry_modulus.0 < lhs.blocks[0].message_modulus.0 {
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
                .par_chunks(2)
                .zip(rhs.blocks.par_chunks(2))
                .map(|(lhs_chunk, rhs_chunk)| {
                    let (mut packed_lhs, packed_rhs) = rayon::join(
                        || self.pack_block_chunk(lhs_chunk),
                        || self.pack_block_chunk(rhs_chunk),
                    );

                    self.compare_block_assign(&mut packed_lhs, &packed_rhs);
                    packed_lhs
                })
                .collect_into_vec(&mut comparisons);

            comparisons
        };

        self.reduce_signs_parallelized(comparisons)
    }

    /// This functions takes two slices:
    ///
    /// - one of encrypted blocks
    /// - the other of scalar to compare to each encrypted block
    ///
    /// It returns a Vec of block that will contain the sign of the comparison
    /// (Self::IS_INFERIOR, Self::IS_EQUAL, Self::IS_SUPERIOR)
    ///
    /// The output len is shorter as blocks will be packed
    fn unchecked_scalar_block_slice_sign_parallelized(
        &self,
        lhs_blocks: &[Ciphertext],
        scalar_blocks: &[u8],
    ) -> Vec<crate::shortint::Ciphertext> {
        assert_eq!(lhs_blocks.len(), scalar_blocks.len());
        let num_blocks = lhs_blocks.len();
        let num_blocks_halved = (num_blocks / 2) + (num_blocks % 2);

        let message_modulus = self.server_key.key.message_modulus.0;
        let mut signs = Vec::with_capacity(num_blocks_halved);
        lhs_blocks
            .par_chunks(2)
            .zip(scalar_blocks.par_chunks(2))
            .map(|(lhs_chunk, scalar_chunk)| {
                let packed_scalar = scalar_chunk[0]
                    + (scalar_chunk.get(1).copied().unwrap_or(0) * message_modulus as u8);
                let mut packed_lhs = self.pack_block_chunk(lhs_chunk);
                self.scalar_compare_block_assign(&mut packed_lhs, packed_scalar);
                packed_lhs
            })
            .collect_into_vec(&mut signs);

        signs
    }

    pub fn unchecked_scalar_sign_parallelized<T>(&self, lhs: &RadixCiphertext, rhs: T) -> Ciphertext
    where
        T: DecomposableInto<u64>,
    {
        assert!(!lhs.blocks.is_empty());

        let message_modulus = self.server_key.key.message_modulus.0;

        let mut scalar_blocks =
            BlockDecomposer::with_early_stop_at_zero(rhs, message_modulus.ilog2())
                .iter_as::<u64>()
                .map(|x| x as u8)
                .collect::<Vec<_>>();

        // scalar is obviously bigger if it has non-zero
        // blocks  after lhs's last block
        let is_scalar_obviously_bigger = scalar_blocks
            .get(lhs.blocks.len()..)
            .map(|sub_slice| sub_slice.iter().any(|&scalar_block| scalar_block != 0))
            .unwrap_or(false);
        if is_scalar_obviously_bigger {
            return self.server_key.key.create_trivial(Self::IS_INFERIOR);
        }
        // If we are sill here, that means scalar_blocks above
        // num_blocks are 0s, we can remove them
        // as we will handle them separately.
        scalar_blocks.truncate(lhs.blocks.len());

        let (least_significant_blocks, most_significant_blocks) =
            lhs.blocks.split_at(scalar_blocks.len());

        // Reducing the signs is the bottleneck of the comparison algorithms,
        // however if the scalar case there is an improvement:
        //
        // The idea is to reduce the number of signs block we have to
        // reduce. We can do that by splitting the comparison problem in two parts.
        //
        // - One part where we compute the signs block between the scalar with just enough blocks
        //   from the ciphertext that can represent the scalar value
        //
        // - The other part is to compare the ciphertext blocks not considered for the sign
        //   computation with zero, and create a signle sign block from that.
        //
        // The smaller the scalar value is comparaed to the ciphertext num bits encrypted,
        // the more the comparisons with zeros we have to do,
        // and the less signs block we will have to reduce.
        //
        // This will create a speedup as comparing a bunch of blocks with 0
        // is faster
        let (lsb_sign, msb_sign) = rayon::join(
            || {
                if least_significant_blocks.is_empty() {
                    None
                } else {
                    let signs = self.unchecked_scalar_block_slice_sign_parallelized(
                        least_significant_blocks,
                        &scalar_blocks,
                    );
                    Some(self.reduce_signs_parallelized(signs))
                }
            },
            || {
                if most_significant_blocks.is_empty() {
                    return None;
                }
                let msb_cmp_zero = self.server_key.compare_blocks_with_zero(
                    most_significant_blocks,
                    ZeroComparisonType::Equality,
                );
                let are_all_msb_equal_to_zero =
                    self.server_key.are_all_comparisons_block_true(msb_cmp_zero);
                let lut = self.server_key.key.generate_lookup_table(|x| {
                    if x == 1 {
                        Self::IS_EQUAL
                    } else {
                        Self::IS_SUPERIOR
                    }
                });
                let sign = self
                    .server_key
                    .key
                    .apply_lookup_table(&are_all_msb_equal_to_zero, &lut);
                Some(sign)
            },
        );

        match (lsb_sign, msb_sign) {
            (None, Some(sign)) => sign,
            (Some(sign), None) => sign,
            (Some(lsb_sign), Some(mut msb_sign)) => {
                self.reduce_two_sign_blocks_assign(&mut msb_sign, &lsb_sign);
                msb_sign
            }
            (None, None) => {
                // assert should have  been hit earlier
                unreachable!("Empty input ciphertext")
            }
        }
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
        self.unchecked_sign(lhs, rhs)
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
        self.unchecked_sign_parallelized(lhs, rhs)
    }

    /// Expects the carry buffers to be empty
    fn unchecked_min_or_max(
        &self,
        lhs: &RadixCiphertext,
        rhs: &RadixCiphertext,
        selector: MinMaxSelector,
    ) -> RadixCiphertext {
        let (lhs_lut, rhs_lut) = match selector {
            MinMaxSelector::Max => (&self.lhs_lut, &self.rhs_lut),
            MinMaxSelector::Min => (&self.rhs_lut, &self.lhs_lut),
        };
        let num_block = lhs.blocks.len();

        let mut offset = self.unchecked_sign(lhs, rhs);
        self.server_key
            .key
            .apply_lookup_table_assign(&mut offset, &self.sign_to_offset_lut);

        let mut result = Vec::with_capacity(num_block);
        for i in 0..num_block {
            let lhs_block = self.server_key.key.unchecked_add(&lhs.blocks[i], &offset);
            let rhs_block = self.server_key.key.unchecked_add(&rhs.blocks[i], &offset);

            let maybe_lhs = self.server_key.key.apply_lookup_table(&lhs_block, lhs_lut);
            let maybe_rhs = self.server_key.key.apply_lookup_table(&rhs_block, rhs_lut);

            let r = self.server_key.key.unchecked_add(&maybe_lhs, &maybe_rhs);
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
        let sign = self.unchecked_sign_parallelized(lhs, rhs);
        match selector {
            MinMaxSelector::Max => self
                .server_key
                .unchecked_programmable_if_then_else_parallelized(&sign, lhs, rhs, |sign| {
                    sign == Self::IS_SUPERIOR
                }),
            MinMaxSelector::Min => self
                .server_key
                .unchecked_programmable_if_then_else_parallelized(&sign, lhs, rhs, |sign| {
                    sign == Self::IS_INFERIOR
                }),
        }
    }

    fn unchecked_scalar_min_or_max_parallelized<T>(
        &self,
        lhs: &RadixCiphertext,
        rhs: T,
        selector: MinMaxSelector,
    ) -> RadixCiphertext
    where
        T: DecomposableInto<u64>,
    {
        let sign = self.unchecked_scalar_sign_parallelized(lhs, rhs);
        let rhs = self.server_key.create_trivial_radix(rhs, lhs.blocks.len());
        match selector {
            MinMaxSelector::Max => self
                .server_key
                .unchecked_programmable_if_then_else_parallelized(&sign, lhs, &rhs, |sign| {
                    sign == Self::IS_SUPERIOR
                }),
            MinMaxSelector::Min => self
                .server_key
                .unchecked_programmable_if_then_else_parallelized(&sign, lhs, &rhs, |sign| {
                    sign == Self::IS_INFERIOR
                }),
        }
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

    fn map_sign_result<F>(
        &self,
        comparison: crate::shortint::Ciphertext,
        sign_result_handler_fn: F,
        num_blocks: usize,
    ) -> RadixCiphertext
    where
        F: Fn(u64) -> bool,
    {
        let acc = self
            .server_key
            .key
            .generate_lookup_table(|x| u64::from(sign_result_handler_fn(x)));
        let result_block = self.server_key.key.apply_lookup_table(&comparison, &acc);

        let mut blocks = Vec::with_capacity(num_blocks);
        blocks.push(result_block);
        for _ in 0..num_blocks - 1 {
            blocks.push(self.server_key.key.create_trivial(0));
        }

        RadixCiphertext { blocks }
    }

    /// Expects the carry buffers to be empty
    fn unchecked_comparison_impl<'b, CmpFn, F>(
        &self,
        comparison_fn: CmpFn,
        sign_result_handler_fn: F,
        lhs: &'b RadixCiphertext,
        rhs: &'b RadixCiphertext,
    ) -> RadixCiphertext
    where
        CmpFn: Fn(&Self, &'b RadixCiphertext, &'b RadixCiphertext) -> crate::shortint::Ciphertext,
        F: Fn(u64) -> bool,
    {
        let comparison = comparison_fn(self, lhs, rhs);
        self.map_sign_result(comparison, sign_result_handler_fn, lhs.blocks.len())
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
        F: Fn(u64) -> bool,
    {
        let comparison = smart_comparison_fn(self, lhs, rhs);
        self.map_sign_result(comparison, sign_result_handler_fn, lhs.blocks.len())
    }

    //======================================
    // Unchecked Single-Threaded operations
    //======================================

    pub fn unchecked_gt(&self, lhs: &RadixCiphertext, rhs: &RadixCiphertext) -> RadixCiphertext {
        self.unchecked_comparison_impl(Self::unchecked_sign, |x| x == Self::IS_SUPERIOR, lhs, rhs)
    }

    pub fn unchecked_ge(&self, lhs: &RadixCiphertext, rhs: &RadixCiphertext) -> RadixCiphertext {
        self.unchecked_comparison_impl(
            Self::unchecked_sign,
            |x| x == Self::IS_EQUAL || x == Self::IS_SUPERIOR,
            lhs,
            rhs,
        )
    }

    pub fn unchecked_lt(&self, lhs: &RadixCiphertext, rhs: &RadixCiphertext) -> RadixCiphertext {
        self.unchecked_comparison_impl(Self::unchecked_sign, |x| x == Self::IS_INFERIOR, lhs, rhs)
    }

    pub fn unchecked_le(&self, lhs: &RadixCiphertext, rhs: &RadixCiphertext) -> RadixCiphertext {
        self.unchecked_comparison_impl(
            Self::unchecked_sign,
            |x| x == Self::IS_EQUAL || x == Self::IS_INFERIOR,
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

    pub fn unchecked_gt_parallelized(
        &self,
        lhs: &RadixCiphertext,
        rhs: &RadixCiphertext,
    ) -> RadixCiphertext {
        self.unchecked_comparison_impl(
            Self::unchecked_sign_parallelized,
            |x| x == Self::IS_SUPERIOR,
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
            Self::unchecked_sign_parallelized,
            |x| x == Self::IS_EQUAL || x == Self::IS_SUPERIOR,
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
            Self::unchecked_sign_parallelized,
            |x| x == Self::IS_INFERIOR,
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
            Self::unchecked_sign_parallelized,
            |x| x == Self::IS_EQUAL || x == Self::IS_INFERIOR,
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

    pub fn smart_gt(
        &self,
        lhs: &mut RadixCiphertext,
        rhs: &mut RadixCiphertext,
    ) -> RadixCiphertext {
        self.smart_comparison_impl(Self::smart_compare, |x| x == Self::IS_SUPERIOR, lhs, rhs)
    }

    pub fn smart_ge(
        &self,
        lhs: &mut RadixCiphertext,
        rhs: &mut RadixCiphertext,
    ) -> RadixCiphertext {
        self.smart_comparison_impl(
            Self::smart_compare,
            |x| x == Self::IS_EQUAL || x == Self::IS_SUPERIOR,
            lhs,
            rhs,
        )
    }

    pub fn smart_lt(
        &self,
        lhs: &mut RadixCiphertext,
        rhs: &mut RadixCiphertext,
    ) -> RadixCiphertext {
        self.smart_comparison_impl(Self::smart_compare, |x| x == Self::IS_INFERIOR, lhs, rhs)
    }

    pub fn smart_le(
        &self,
        lhs: &mut RadixCiphertext,
        rhs: &mut RadixCiphertext,
    ) -> RadixCiphertext {
        self.smart_comparison_impl(
            Self::smart_compare,
            |x| x == Self::IS_EQUAL || x == Self::IS_INFERIOR,
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

    pub fn smart_gt_parallelized(
        &self,
        lhs: &mut RadixCiphertext,
        rhs: &mut RadixCiphertext,
    ) -> RadixCiphertext {
        self.smart_comparison_impl(
            Self::smart_compare_parallelized,
            |x| x == Self::IS_SUPERIOR,
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
            |x| x == Self::IS_EQUAL || x == Self::IS_SUPERIOR,
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
            |x| x == Self::IS_INFERIOR,
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
            |x| x == Self::IS_EQUAL || x == Self::IS_INFERIOR,
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

    //======================================
    // "Default" Multi-Threaded operations
    //======================================

    pub fn gt_parallelized(&self, lhs: &RadixCiphertext, rhs: &RadixCiphertext) -> RadixCiphertext {
        let mut tmp_lhs: RadixCiphertext;
        let mut tmp_rhs: RadixCiphertext;
        let (lhs, rhs) = match (lhs.block_carries_are_empty(), rhs.block_carries_are_empty()) {
            (true, true) => (lhs, rhs),
            (true, false) => {
                tmp_rhs = rhs.clone();
                self.server_key.full_propagate_parallelized(&mut tmp_rhs);
                (lhs, &tmp_rhs)
            }
            (false, true) => {
                tmp_lhs = lhs.clone();
                self.server_key.full_propagate_parallelized(&mut tmp_lhs);
                (&tmp_lhs, rhs)
            }
            (false, false) => {
                tmp_lhs = lhs.clone();
                tmp_rhs = rhs.clone();
                rayon::join(
                    || self.server_key.full_propagate_parallelized(&mut tmp_lhs),
                    || self.server_key.full_propagate_parallelized(&mut tmp_rhs),
                );
                (&tmp_lhs, &tmp_rhs)
            }
        };

        self.unchecked_gt_parallelized(lhs, rhs)
    }

    pub fn ge_parallelized(&self, lhs: &RadixCiphertext, rhs: &RadixCiphertext) -> RadixCiphertext {
        let mut tmp_lhs: RadixCiphertext;
        let mut tmp_rhs: RadixCiphertext;
        let (lhs, rhs) = match (lhs.block_carries_are_empty(), rhs.block_carries_are_empty()) {
            (true, true) => (lhs, rhs),
            (true, false) => {
                tmp_rhs = rhs.clone();
                self.server_key.full_propagate_parallelized(&mut tmp_rhs);
                (lhs, &tmp_rhs)
            }
            (false, true) => {
                tmp_lhs = lhs.clone();
                self.server_key.full_propagate_parallelized(&mut tmp_lhs);
                (&tmp_lhs, rhs)
            }
            (false, false) => {
                tmp_lhs = lhs.clone();
                tmp_rhs = rhs.clone();
                rayon::join(
                    || self.server_key.full_propagate_parallelized(&mut tmp_lhs),
                    || self.server_key.full_propagate_parallelized(&mut tmp_rhs),
                );
                (&tmp_lhs, &tmp_rhs)
            }
        };

        self.unchecked_ge_parallelized(lhs, rhs)
    }

    pub fn lt_parallelized(&self, lhs: &RadixCiphertext, rhs: &RadixCiphertext) -> RadixCiphertext {
        let mut tmp_lhs: RadixCiphertext;
        let mut tmp_rhs: RadixCiphertext;
        let (lhs, rhs) = match (lhs.block_carries_are_empty(), rhs.block_carries_are_empty()) {
            (true, true) => (lhs, rhs),
            (true, false) => {
                tmp_rhs = rhs.clone();
                self.server_key.full_propagate_parallelized(&mut tmp_rhs);
                (lhs, &tmp_rhs)
            }
            (false, true) => {
                tmp_lhs = lhs.clone();
                self.server_key.full_propagate_parallelized(&mut tmp_lhs);
                (&tmp_lhs, rhs)
            }
            (false, false) => {
                tmp_lhs = lhs.clone();
                tmp_rhs = rhs.clone();
                rayon::join(
                    || self.server_key.full_propagate_parallelized(&mut tmp_lhs),
                    || self.server_key.full_propagate_parallelized(&mut tmp_rhs),
                );
                (&tmp_lhs, &tmp_rhs)
            }
        };

        self.unchecked_lt_parallelized(lhs, rhs)
    }

    pub fn le_parallelized(&self, lhs: &RadixCiphertext, rhs: &RadixCiphertext) -> RadixCiphertext {
        let mut tmp_lhs: RadixCiphertext;
        let mut tmp_rhs: RadixCiphertext;
        let (lhs, rhs) = match (lhs.block_carries_are_empty(), rhs.block_carries_are_empty()) {
            (true, true) => (lhs, rhs),
            (true, false) => {
                tmp_rhs = rhs.clone();
                self.server_key.full_propagate_parallelized(&mut tmp_rhs);
                (lhs, &tmp_rhs)
            }
            (false, true) => {
                tmp_lhs = lhs.clone();
                self.server_key.full_propagate_parallelized(&mut tmp_lhs);
                (&tmp_lhs, rhs)
            }
            (false, false) => {
                tmp_lhs = lhs.clone();
                tmp_rhs = rhs.clone();
                rayon::join(
                    || self.server_key.full_propagate_parallelized(&mut tmp_lhs),
                    || self.server_key.full_propagate_parallelized(&mut tmp_rhs),
                );
                (&tmp_lhs, &tmp_rhs)
            }
        };

        self.unchecked_le_parallelized(lhs, rhs)
    }

    pub fn max_parallelized(
        &self,
        lhs: &RadixCiphertext,
        rhs: &RadixCiphertext,
    ) -> RadixCiphertext {
        let mut tmp_lhs: RadixCiphertext;
        let mut tmp_rhs: RadixCiphertext;

        let (lhs, rhs) = match (lhs.block_carries_are_empty(), rhs.block_carries_are_empty()) {
            (true, true) => (lhs, rhs),
            (true, false) => {
                tmp_rhs = rhs.clone();
                self.server_key.full_propagate_parallelized(&mut tmp_rhs);
                (lhs, &tmp_rhs)
            }
            (false, true) => {
                tmp_lhs = lhs.clone();
                self.server_key.full_propagate_parallelized(&mut tmp_lhs);
                (&tmp_lhs, rhs)
            }
            (false, false) => {
                tmp_lhs = lhs.clone();
                tmp_rhs = rhs.clone();
                rayon::join(
                    || self.server_key.full_propagate_parallelized(&mut tmp_lhs),
                    || self.server_key.full_propagate_parallelized(&mut tmp_rhs),
                );
                (&tmp_lhs, &tmp_rhs)
            }
        };

        self.unchecked_max_parallelized(lhs, rhs)
    }

    pub fn min_parallelized(
        &self,
        lhs: &RadixCiphertext,
        rhs: &RadixCiphertext,
    ) -> RadixCiphertext {
        let mut tmp_lhs: RadixCiphertext;
        let mut tmp_rhs: RadixCiphertext;

        let (lhs, rhs) = match (lhs.block_carries_are_empty(), rhs.block_carries_are_empty()) {
            (true, true) => (lhs, rhs),
            (true, false) => {
                tmp_rhs = rhs.clone();
                self.server_key.full_propagate_parallelized(&mut tmp_rhs);
                (lhs, &tmp_rhs)
            }
            (false, true) => {
                tmp_lhs = lhs.clone();
                self.server_key.full_propagate_parallelized(&mut tmp_lhs);
                (&tmp_lhs, rhs)
            }
            (false, false) => {
                tmp_lhs = lhs.clone();
                tmp_rhs = rhs.clone();
                rayon::join(
                    || self.server_key.full_propagate_parallelized(&mut tmp_lhs),
                    || self.server_key.full_propagate_parallelized(&mut tmp_rhs),
                );
                (&tmp_lhs, &tmp_rhs)
            }
        };

        self.unchecked_min_parallelized(lhs, rhs)
    }

    //===========================================
    // Unchecked Scalar Multi-Threaded operations
    //===========================================
    //
    pub fn unchecked_scalar_compare_parallelized<T, F>(
        &self,
        lhs: &RadixCiphertext,
        rhs: T,
        sign_result_handler_fn: F,
    ) -> RadixCiphertext
    where
        T: DecomposableInto<u64>,
        F: Fn(u64) -> bool + Sync,
    {
        let sign_block = self.unchecked_scalar_sign_parallelized(lhs, rhs);
        self.map_sign_result(sign_block, sign_result_handler_fn, lhs.blocks.len())
    }

    pub fn unchecked_scalar_gt_parallelized<T>(
        &self,
        lhs: &RadixCiphertext,
        rhs: T,
    ) -> RadixCiphertext
    where
        T: DecomposableInto<u64>,
    {
        self.unchecked_scalar_compare_parallelized(lhs, rhs, |x| x == Self::IS_SUPERIOR)
    }

    pub fn unchecked_scalar_ge_parallelized<T>(
        &self,
        lhs: &RadixCiphertext,
        rhs: T,
    ) -> RadixCiphertext
    where
        T: DecomposableInto<u64>,
    {
        self.unchecked_scalar_compare_parallelized(lhs, rhs, |x| {
            x == Self::IS_SUPERIOR || x == Self::IS_EQUAL
        })
    }

    pub fn unchecked_scalar_lt_parallelized<T>(
        &self,
        lhs: &RadixCiphertext,
        rhs: T,
    ) -> RadixCiphertext
    where
        T: DecomposableInto<u64>,
    {
        self.unchecked_scalar_compare_parallelized(lhs, rhs, |x| x == Self::IS_INFERIOR)
    }

    pub fn unchecked_scalar_le_parallelized<T>(
        &self,
        lhs: &RadixCiphertext,
        rhs: T,
    ) -> RadixCiphertext
    where
        T: DecomposableInto<u64>,
    {
        self.unchecked_scalar_compare_parallelized(lhs, rhs, |x| {
            x == Self::IS_INFERIOR || x == Self::IS_EQUAL
        })
    }

    pub fn unchecked_scalar_max_parallelized<T>(
        &self,
        lhs: &RadixCiphertext,
        rhs: T,
    ) -> RadixCiphertext
    where
        T: DecomposableInto<u64>,
    {
        self.unchecked_scalar_min_or_max_parallelized(lhs, rhs, MinMaxSelector::Max)
    }

    pub fn unchecked_scalar_min_parallelized<T>(
        &self,
        lhs: &RadixCiphertext,
        rhs: T,
    ) -> RadixCiphertext
    where
        T: DecomposableInto<u64>,
    {
        self.unchecked_scalar_min_or_max_parallelized(lhs, rhs, MinMaxSelector::Min)
    }

    //=======================================
    // Smart Scalar Multi-Threaded operations
    //=======================================

    fn smart_scalar_compare_parallelized<T, F>(
        &self,
        lhs: &mut RadixCiphertext,
        rhs: T,
        sign_result_handler_fn: F,
    ) -> RadixCiphertext
    where
        T: DecomposableInto<u64>,
        F: Fn(u64) -> bool + Sync,
    {
        if has_non_zero_carries(lhs) {
            self.server_key.full_propagate_parallelized(lhs);
        }
        self.unchecked_scalar_compare_parallelized(lhs, rhs, sign_result_handler_fn)
    }

    pub fn smart_scalar_gt_parallelized<T>(
        &self,
        lhs: &mut RadixCiphertext,
        rhs: T,
    ) -> RadixCiphertext
    where
        T: DecomposableInto<u64>,
    {
        self.smart_scalar_compare_parallelized(lhs, rhs, |x| x == Self::IS_SUPERIOR)
    }

    pub fn smart_scalar_ge_parallelized<T>(
        &self,
        lhs: &mut RadixCiphertext,
        rhs: T,
    ) -> RadixCiphertext
    where
        T: DecomposableInto<u64>,
    {
        self.smart_scalar_compare_parallelized(lhs, rhs, |x| {
            x == Self::IS_SUPERIOR || x == Self::IS_EQUAL
        })
    }

    pub fn smart_scalar_lt_parallelized<T>(
        &self,
        lhs: &mut RadixCiphertext,
        rhs: T,
    ) -> RadixCiphertext
    where
        T: DecomposableInto<u64>,
    {
        self.smart_scalar_compare_parallelized(lhs, rhs, |x| x == Self::IS_INFERIOR)
    }

    pub fn smart_scalar_le_parallelized<T>(
        &self,
        lhs: &mut RadixCiphertext,
        rhs: T,
    ) -> RadixCiphertext
    where
        T: DecomposableInto<u64>,
    {
        self.smart_scalar_compare_parallelized(lhs, rhs, |x| {
            x == Self::IS_INFERIOR || x == Self::IS_EQUAL
        })
    }

    pub fn smart_scalar_max_parallelized<T>(
        &self,
        lhs: &mut RadixCiphertext,
        rhs: T,
    ) -> RadixCiphertext
    where
        T: DecomposableInto<u64>,
    {
        if has_non_zero_carries(lhs) {
            self.server_key.full_propagate_parallelized(lhs);
        }
        self.unchecked_scalar_min_or_max_parallelized(lhs, rhs, MinMaxSelector::Max)
    }

    pub fn smart_scalar_min_parallelized<T>(
        &self,
        lhs: &mut RadixCiphertext,
        rhs: T,
    ) -> RadixCiphertext
    where
        T: DecomposableInto<u64>,
    {
        if has_non_zero_carries(lhs) {
            self.server_key.full_propagate_parallelized(lhs);
        }
        self.unchecked_scalar_min_or_max_parallelized(lhs, rhs, MinMaxSelector::Min)
    }

    //======================================
    // "Default" Scalar Multi-Threaded operations
    //======================================

    fn default_scalar_compare_parallelized<T, F>(
        &self,
        lhs: &RadixCiphertext,
        rhs: T,
        sign_result_handler_fn: F,
    ) -> RadixCiphertext
    where
        T: DecomposableInto<u64>,
        F: Fn(u64) -> bool + Sync,
    {
        let mut tmp_lhs: RadixCiphertext;
        let lhs = if has_non_zero_carries(lhs) {
            tmp_lhs = lhs.clone();
            self.server_key.full_propagate_parallelized(&mut tmp_lhs);
            &tmp_lhs
        } else {
            lhs
        };
        self.unchecked_scalar_compare_parallelized(lhs, rhs, sign_result_handler_fn)
    }

    pub fn scalar_gt_parallelized<T>(&self, lhs: &RadixCiphertext, rhs: T) -> RadixCiphertext
    where
        T: DecomposableInto<u64>,
    {
        self.default_scalar_compare_parallelized(lhs, rhs, |x| x == Self::IS_SUPERIOR)
    }

    pub fn scalar_ge_parallelized<T>(&self, lhs: &RadixCiphertext, rhs: T) -> RadixCiphertext
    where
        T: DecomposableInto<u64>,
    {
        self.default_scalar_compare_parallelized(lhs, rhs, |x| {
            x == Self::IS_SUPERIOR || x == Self::IS_EQUAL
        })
    }

    pub fn scalar_lt_parallelized<T>(&self, lhs: &RadixCiphertext, rhs: T) -> RadixCiphertext
    where
        T: DecomposableInto<u64>,
    {
        self.default_scalar_compare_parallelized(lhs, rhs, |x| x == Self::IS_INFERIOR)
    }

    pub fn scalar_le_parallelized<T>(&self, lhs: &RadixCiphertext, rhs: T) -> RadixCiphertext
    where
        T: DecomposableInto<u64>,
    {
        self.default_scalar_compare_parallelized(lhs, rhs, |x| {
            x == Self::IS_INFERIOR || x == Self::IS_EQUAL
        })
    }

    pub fn scalar_max_parallelized<T>(&self, lhs: &RadixCiphertext, rhs: T) -> RadixCiphertext
    where
        T: DecomposableInto<u64>,
    {
        let mut tmp_lhs: RadixCiphertext;
        let lhs = if has_non_zero_carries(lhs) {
            tmp_lhs = lhs.clone();
            self.server_key.full_propagate_parallelized(&mut tmp_lhs);
            &tmp_lhs
        } else {
            lhs
        };
        self.unchecked_scalar_min_or_max_parallelized(lhs, rhs, MinMaxSelector::Max)
    }

    pub fn scalar_min_parallelized<T>(&self, lhs: &RadixCiphertext, rhs: T) -> RadixCiphertext
    where
        T: DecomposableInto<u64>,
    {
        let mut tmp_lhs: RadixCiphertext;
        let lhs = if has_non_zero_carries(lhs) {
            tmp_lhs = lhs.clone();
            self.server_key.full_propagate_parallelized(&mut tmp_lhs);
            &tmp_lhs
        } else {
            lhs
        };
        self.unchecked_scalar_min_or_max_parallelized(lhs, rhs, MinMaxSelector::Min)
    }
}

#[cfg(test)]
mod tests {
    use super::Comparator;
    use crate::integer::block_decomposition::DecomposableInto;
    use crate::integer::ciphertext::RadixCiphertext;
    use crate::integer::{gen_keys, U256};
    use crate::shortint::ClassicPBSParameters;
    use rand;
    use rand::prelude::*;

    // These used to be directly implemented
    // in Comparator methods, however,
    // they were made more efficient and don't
    // use the things stored in the Comparator struct to work
    // so they were moved out of it.
    //
    // But to still benefit from the 'comparator test infrastructure'
    // we remap them in test cfg
    impl<'a> Comparator<'a> {
        pub fn smart_eq(
            &self,
            lhs: &mut RadixCiphertext,
            rhs: &mut RadixCiphertext,
        ) -> RadixCiphertext {
            self.server_key.smart_eq(lhs, rhs)
        }

        pub fn unchecked_eq(
            &self,
            lhs: &RadixCiphertext,
            rhs: &RadixCiphertext,
        ) -> RadixCiphertext {
            self.server_key.unchecked_eq(lhs, rhs)
        }

        pub fn unchecked_eq_parallelized(
            &self,
            lhs: &RadixCiphertext,
            rhs: &RadixCiphertext,
        ) -> RadixCiphertext {
            self.server_key.eq_parallelized(lhs, rhs)
        }

        pub fn smart_eq_parallelized(
            &self,
            lhs: &mut RadixCiphertext,
            rhs: &mut RadixCiphertext,
        ) -> RadixCiphertext {
            self.server_key.smart_eq_parallelized(lhs, rhs)
        }

        pub fn eq_parallelized(
            &self,
            lhs: &RadixCiphertext,
            rhs: &RadixCiphertext,
        ) -> RadixCiphertext {
            self.server_key.eq_parallelized(lhs, rhs)
        }

        pub fn smart_ne(
            &self,
            lhs: &mut RadixCiphertext,
            rhs: &mut RadixCiphertext,
        ) -> RadixCiphertext {
            self.server_key.smart_ne(lhs, rhs)
        }

        pub fn unchecked_ne(
            &self,
            lhs: &RadixCiphertext,
            rhs: &RadixCiphertext,
        ) -> RadixCiphertext {
            self.server_key.unchecked_ne(lhs, rhs)
        }

        pub fn unchecked_ne_parallelized(
            &self,
            lhs: &RadixCiphertext,
            rhs: &RadixCiphertext,
        ) -> RadixCiphertext {
            self.server_key.ne_parallelized(lhs, rhs)
        }

        pub fn smart_ne_parallelized(
            &self,
            lhs: &mut RadixCiphertext,
            rhs: &mut RadixCiphertext,
        ) -> RadixCiphertext {
            self.server_key.smart_ne_parallelized(lhs, rhs)
        }

        pub fn ne_parallelized(
            &self,
            lhs: &RadixCiphertext,
            rhs: &RadixCiphertext,
        ) -> RadixCiphertext {
            self.server_key.ne_parallelized(lhs, rhs)
        }
    }

    impl<'a> Comparator<'a> {
        pub fn unchecked_scalar_eq_parallelized<T: DecomposableInto<u64>>(
            &self,
            lhs: &RadixCiphertext,
            rhs: T,
        ) -> RadixCiphertext {
            self.server_key.unchecked_scalar_eq_parallelized(lhs, rhs)
        }

        pub fn smart_scalar_eq_parallelized<T: DecomposableInto<u64>>(
            &self,
            lhs: &mut RadixCiphertext,
            rhs: T,
        ) -> RadixCiphertext {
            self.server_key.smart_scalar_eq_parallelized(lhs, rhs)
        }

        pub fn scalar_eq_parallelized<T: DecomposableInto<u64>>(
            &self,
            lhs: &RadixCiphertext,
            rhs: T,
        ) -> RadixCiphertext {
            self.server_key.scalar_eq_parallelized(lhs, rhs)
        }

        pub fn unchecked_scalar_ne_parallelized<T: DecomposableInto<u64>>(
            &self,
            lhs: &RadixCiphertext,
            rhs: T,
        ) -> RadixCiphertext {
            self.server_key.unchecked_scalar_ne_parallelized(lhs, rhs)
        }

        pub fn smart_scalar_ne_parallelized<T: DecomposableInto<u64>>(
            &self,
            lhs: &mut RadixCiphertext,
            rhs: T,
        ) -> RadixCiphertext {
            self.server_key.smart_scalar_ne_parallelized(lhs, rhs)
        }

        pub fn scalar_ne_parallelized<T: DecomposableInto<u64>>(
            &self,
            lhs: &RadixCiphertext,
            rhs: T,
        ) -> RadixCiphertext {
            self.server_key.scalar_ne_parallelized(lhs, rhs)
        }
    }

    /// Function to test an "unchecked" compartor function.
    ///
    /// This calls the `unchecked_comparator_method` with fresh ciphertexts
    /// and compares that it gives the same results as the `clear_fn`.
    fn test_unchecked_function<UncheckedFn, ClearF>(
        param: ClassicPBSParameters,
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

        let (cks, sks) = gen_keys(param);
        let comparator = Comparator::new(&sks);

        for _ in 0..num_test {
            let clear_a = rng.gen::<U256>();
            let clear_b = rng.gen::<U256>();

            let a = cks.encrypt_radix(clear_a, num_block);
            let b = cks.encrypt_radix(clear_b, num_block);

            {
                let result = unchecked_comparator_method(&comparator, &a, &b);
                let decrypted: U256 = cks.decrypt_radix(&result);
                let expected_result = clear_fn(clear_a, clear_b);
                assert_eq!(decrypted, expected_result);
            }

            {
                // Force case where lhs == rhs
                let result = unchecked_comparator_method(&comparator, &a, &a);
                let decrypted: U256 = cks.decrypt_radix(&result);
                let expected_result = clear_fn(clear_a, clear_a);
                assert_eq!(decrypted, expected_result);
            }
        }
    }

    /// Function to test a "smart" comparator function.
    ///
    /// This calls the `smart_comparator_method` with non-fresh ciphertexts,
    /// that is ciphertexts that have non-zero carries, and compares that the result is
    /// the same as the one of`clear_fn`.
    fn test_smart_function<SmartFn, ClearF>(
        param: ClassicPBSParameters,
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
        let (cks, sks) = gen_keys(param);
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
                let a: U256 = cks.decrypt_radix(&ct_0);
                assert_eq!(a, clear_0);

                let b: U256 = cks.decrypt_radix(&ct_1);
                assert_eq!(b, clear_1);
            }

            assert!(super::has_non_zero_carries(&ct_0));
            assert!(super::has_non_zero_carries(&ct_1));
            let encrypted_result = smart_comparator_method(&comparator, &mut ct_0, &mut ct_1);
            assert!(!super::has_non_zero_carries(&ct_0));
            assert!(!super::has_non_zero_carries(&ct_1));

            // Sanity decryption checks
            {
                let a: U256 = cks.decrypt_radix(&ct_0);
                assert_eq!(a, clear_0);

                let b: U256 = cks.decrypt_radix(&ct_1);
                assert_eq!(b, clear_1);
            }

            let decrypted_result: U256 = cks.decrypt_radix(&encrypted_result);

            let expected_result = clear_fn(clear_0, clear_1);
            assert_eq!(decrypted_result, expected_result);
        }
    }

    /// Function to test a "default" comparator function.
    ///
    /// This calls the `comparator_method` with non-fresh ciphertexts,
    /// that is ciphertexts that have non-zero carries, and compares that the result is
    /// the same as the one of`clear_fn`.
    fn test_default_function<SmartFn, ClearF>(
        param: ClassicPBSParameters,
        num_test: usize,
        default_comparator_method: SmartFn,
        clear_fn: ClearF,
    ) where
        SmartFn: for<'a, 'b> Fn(
            &'a Comparator<'b>,
            &'a RadixCiphertext,
            &'a RadixCiphertext,
        ) -> RadixCiphertext,
        ClearF: Fn(U256, U256) -> U256,
    {
        let (cks, sks) = gen_keys(param);
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
                let a: U256 = cks.decrypt_radix(&ct_0);
                assert_eq!(a, clear_0);

                let b: U256 = cks.decrypt_radix(&ct_1);
                assert_eq!(b, clear_1);
            }

            assert!(super::has_non_zero_carries(&ct_0));
            assert!(super::has_non_zero_carries(&ct_1));
            let encrypted_result = default_comparator_method(&comparator, &ct_0, &ct_1);
            assert!(!super::has_non_zero_carries(&encrypted_result));

            // Sanity decryption checks
            {
                let a: U256 = cks.decrypt_radix(&ct_0);
                assert_eq!(a, clear_0);

                let b: U256 = cks.decrypt_radix(&ct_1);
                assert_eq!(b, clear_1);
            }

            let decrypted_result: U256 = cks.decrypt_radix(&encrypted_result);

            let expected_result = clear_fn(clear_0, clear_1);
            assert_eq!(decrypted_result, expected_result);
        }
    }

    fn test_unchecked_min_256_bits(
        params: crate::shortint::ClassicPBSParameters,
        num_tests: usize,
    ) {
        test_unchecked_function(
            params,
            num_tests,
            |comparator, lhs, rhs| comparator.unchecked_min(lhs, rhs),
            std::cmp::min,
        )
    }

    fn test_unchecked_max_256_bits(
        params: crate::shortint::ClassicPBSParameters,
        num_tests: usize,
    ) {
        test_unchecked_function(
            params,
            num_tests,
            |comparator, lhs, rhs| comparator.unchecked_max(lhs, rhs),
            std::cmp::max,
        )
    }

    fn test_unchecked_min_parallelized_256_bits(
        params: crate::shortint::ClassicPBSParameters,
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
        params: crate::shortint::ClassicPBSParameters,
        num_tests: usize,
    ) {
        test_unchecked_function(
            params,
            num_tests,
            |comparator, lhs, rhs| comparator.unchecked_max_parallelized(lhs, rhs),
            std::cmp::max,
        )
    }

    fn test_min_parallelized_256_bits(
        params: crate::shortint::ClassicPBSParameters,
        num_tests: usize,
    ) {
        test_default_function(
            params,
            num_tests,
            |comparator, lhs, rhs| comparator.min_parallelized(lhs, rhs),
            std::cmp::min,
        )
    }

    fn test_max_parallelized_256_bits(
        params: crate::shortint::ClassicPBSParameters,
        num_tests: usize,
    ) {
        test_default_function(
            params,
            num_tests,
            |comparator, lhs, rhs| comparator.max_parallelized(lhs, rhs),
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
    /// All our comparison function have 5 variants:
    /// - unchecked_$comparison_name
    /// - unchecked_$comparison_name_parallelized
    /// - smart_$comparison_name
    /// - smart_$comparison_name_parallelized
    /// - $comparison_name_parallelized
    ///
    /// So, for example, for the `gt` comparison fn, this macro will generate the tests for
    /// the 5 variants described above
    macro_rules! define_comparison_test_functions {
        ($comparison_name:ident) => {
            paste::paste!{
                fn [<unchecked_ $comparison_name _256_bits>](params:  crate::shortint::ClassicPBSParameters) {
                    let num_tests = 1;
                    test_unchecked_function(
                        params,
                        num_tests,
                        |comparator, lhs, rhs| comparator.[<unchecked_ $comparison_name>](lhs, rhs),
                        |lhs, rhs| U256::from(<U256>::$comparison_name(&lhs, &rhs) as u128),
                    )
                }

                fn [<unchecked_ $comparison_name _parallelized_256_bits>](params:  crate::shortint::ClassicPBSParameters) {
                    let num_tests = 1;
                    test_unchecked_function(
                        params,
                        num_tests,
                        |comparator, lhs, rhs| comparator.[<unchecked_ $comparison_name _parallelized>](lhs, rhs),
                        |lhs, rhs| U256::from(<U256>::$comparison_name(&lhs, &rhs) as u128),
                    )
                }

                fn [<smart_ $comparison_name _256_bits>](params:  crate::shortint::ClassicPBSParameters) {
                    let num_tests = 1;
                    test_smart_function(
                        params,
                        num_tests,
                        |comparator, lhs, rhs| comparator.[<smart_ $comparison_name>](lhs, rhs),
                        |lhs, rhs| U256::from(<U256>::$comparison_name(&lhs, &rhs) as u128),
                    )
                }

                fn [<smart_ $comparison_name _parallelized_256_bits>](params:  crate::shortint::ClassicPBSParameters) {
                    let num_tests = 1;
                    test_smart_function(
                        params,
                        num_tests,
                        |comparator, lhs, rhs| comparator.[<smart_ $comparison_name _parallelized>](lhs, rhs),
                        |lhs, rhs| U256::from(<U256>::$comparison_name(&lhs, &rhs) as u128),
                    )
                }

                fn [<$comparison_name _parallelized_256_bits>](params:  crate::shortint::ClassicPBSParameters) {
                    let num_tests = 1;
                    test_default_function(
                        params,
                        num_tests,
                        |comparator, lhs, rhs| comparator.[<$comparison_name _parallelized>](lhs, rhs),
                        |lhs, rhs| U256::from(<U256>::$comparison_name(&lhs, &rhs) as u128),
                    )
                }

                create_parametrized_test!([<unchecked_ $comparison_name _256_bits>]
                {
                    PARAM_MESSAGE_2_CARRY_2_KS_PBS,
                    PARAM_MESSAGE_3_CARRY_3_KS_PBS,
                    PARAM_MESSAGE_4_CARRY_4_KS_PBS
                });
                create_parametrized_test!([<unchecked_ $comparison_name _parallelized_256_bits>]
                {
                    PARAM_MESSAGE_2_CARRY_2_KS_PBS,
                    PARAM_MESSAGE_3_CARRY_3_KS_PBS,
                    PARAM_MESSAGE_4_CARRY_4_KS_PBS
                });

                create_parametrized_test!([<smart_ $comparison_name _256_bits>]
                {
                    PARAM_MESSAGE_2_CARRY_2_KS_PBS,
                    // We don't use PARAM_MESSAGE_3_CARRY_3_KS_PBS,
                    // as smart test might overflow values
                    // and when using 3_3 to represent 256 we actually have more than 256 bits
                    // of message so the overflow behaviour is not the same, leading to false negatives
                    PARAM_MESSAGE_4_CARRY_4_KS_PBS
                });

                create_parametrized_test!([<smart_ $comparison_name _parallelized_256_bits>]
                {
                    PARAM_MESSAGE_2_CARRY_2_KS_PBS,
                    // We don't use PARAM_MESSAGE_3_CARRY_3_KS_PBS,
                    // as smart test might overflow values
                    // and when using 3_3 to represent 256 we actually have more than 256 bits
                    // of message so the overflow behaviour is not the same, leading to false negatives
                    PARAM_MESSAGE_4_CARRY_4_KS_PBS
                });

                create_parametrized_test!([<$comparison_name _parallelized_256_bits>]
                {
                    PARAM_MESSAGE_2_CARRY_2_KS_PBS,
                    // We don't use PARAM_MESSAGE_3_CARRY_3_KS_PBS,
                    // as default test might overflow values
                    // and when using 3_3 to represent 256 we actually have more than 256 bits
                    // of message so the overflow behaviour is not the same, leading to false negatives
                    PARAM_MESSAGE_4_CARRY_4_KS_PBS
                });
            }
        };
    }

    use crate::shortint::parameters::{
        PARAM_MESSAGE_2_CARRY_2_KS_PBS, PARAM_MESSAGE_3_CARRY_3_KS_PBS,
        PARAM_MESSAGE_4_CARRY_4_KS_PBS,
    };

    define_comparison_test_functions!(eq);
    define_comparison_test_functions!(ne);
    define_comparison_test_functions!(lt);
    define_comparison_test_functions!(le);
    define_comparison_test_functions!(gt);
    define_comparison_test_functions!(ge);

    //================
    // Min
    //================

    #[test]
    fn test_unchecked_min_256_bits_param_message_2_carry_2_ks_pbs() {
        test_unchecked_min_256_bits(
            crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            4,
        )
    }

    #[test]
    fn test_unchecked_min_256_bits_param_message_3_carry_3_ks_pbs() {
        test_unchecked_min_256_bits(
            crate::shortint::parameters::PARAM_MESSAGE_3_CARRY_3_KS_PBS,
            2,
        )
    }

    #[test]
    fn test_unchecked_min_256_bits_param_message_4_carry_4_ks_pbs() {
        test_unchecked_min_256_bits(
            crate::shortint::parameters::PARAM_MESSAGE_4_CARRY_4_KS_PBS,
            2,
        )
    }

    #[test]
    fn test_unchecked_min_parallelized_256_bits_param_message_2_carry_2_ks_pbs() {
        test_unchecked_min_parallelized_256_bits(
            crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            4,
        )
    }

    #[test]
    fn test_unchecked_min_parallelized_256_bits_param_message_3_carry_3_ks_pbs() {
        test_unchecked_min_parallelized_256_bits(
            crate::shortint::parameters::PARAM_MESSAGE_3_CARRY_3_KS_PBS,
            2,
        )
    }

    #[test]
    fn test_unchecked_min_parallelized_256_bits_param_message_4_carry_4_ks_pbs() {
        test_unchecked_min_parallelized_256_bits(
            crate::shortint::parameters::PARAM_MESSAGE_4_CARRY_4_KS_PBS,
            2,
        )
    }

    #[test]
    fn test_min_parallelized_256_bits_param_message_2_carry_2_ks_pbs() {
        test_min_parallelized_256_bits(
            crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            4,
        )
    }

    // #[test]
    // fn test_min_parallelized_256_bits_param_message_3_carry_3_ks_pbs() {
    //     test_min_parallelized_256_bits(
    //         crate::shortint::parameters::PARAM_MESSAGE_3_CARRY_3_KS_PBS,
    //         2,
    //     )
    // }

    #[test]
    fn test_min_parallelized_256_bits_param_message_4_carry_4_ks_pbs() {
        test_min_parallelized_256_bits(
            crate::shortint::parameters::PARAM_MESSAGE_4_CARRY_4_KS_PBS,
            2,
        )
    }

    //================
    // Max
    //================

    #[test]
    fn test_unchecked_max_256_bits_param_message_2_carry_2_ks_pbs() {
        test_unchecked_max_256_bits(
            crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            4,
        )
    }

    #[test]
    fn test_unchecked_max_256_bits_param_message_3_carry_3_ks_pbs() {
        test_unchecked_max_256_bits(
            crate::shortint::parameters::PARAM_MESSAGE_3_CARRY_3_KS_PBS,
            2,
        )
    }

    #[test]
    fn test_unchecked_max_256_bits_param_message_4_carry_4_ks_pbs() {
        test_unchecked_max_256_bits(
            crate::shortint::parameters::PARAM_MESSAGE_4_CARRY_4_KS_PBS,
            2,
        )
    }

    #[test]
    fn test_unchecked_max_parallelized_256_bits_param_message_2_carry_2_ks_pbs() {
        test_unchecked_max_parallelized_256_bits(
            crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            4,
        )
    }

    #[test]
    fn test_unchecked_max_parallelized_256_bits_param_message_3_carry_3_ks_pbs() {
        test_unchecked_max_parallelized_256_bits(
            crate::shortint::parameters::PARAM_MESSAGE_3_CARRY_3_KS_PBS,
            2,
        )
    }

    #[test]
    fn test_unchecked_parallelized_256_bits_param_message_4_carry_4_ks_pbs() {
        test_unchecked_max_parallelized_256_bits(
            crate::shortint::parameters::PARAM_MESSAGE_4_CARRY_4_KS_PBS,
            2,
        )
    }

    #[test]
    fn test_max_parallelized_256_bits_param_message_2_carry_2_ks_pbs() {
        test_max_parallelized_256_bits(
            crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            4,
        )
    }

    // #[test]
    // fn test_max_parallelized_256_bits_param_message_3_carry_3_ks_pbs() {
    //     test_max_parallelized_256_bits(
    //         crate::shortint::parameters::PARAM_MESSAGE_3_CARRY_3_KS_PBS,
    //         2,
    //     )
    // }

    #[test]
    fn test_parallelized_256_bits_param_message_4_carry_4_ks_pbs() {
        test_max_parallelized_256_bits(
            crate::shortint::parameters::PARAM_MESSAGE_4_CARRY_4_KS_PBS,
            2,
        )
    }

    //=============================================================
    // Scalar comparison tests
    //=============================================================

    /// Function to test an "unchecked_scalar" compartor function.
    ///
    /// This calls the `unchecked_scalar_comparator_method` with fresh ciphertexts
    /// and compares that it gives the same results as the `clear_fn`.
    fn test_unchecked_scalar_function<UncheckedFn, ClearF>(
        param: ClassicPBSParameters,
        num_test: usize,
        unchecked_comparator_method: UncheckedFn,
        clear_fn: ClearF,
    ) where
        UncheckedFn:
            for<'a, 'b> Fn(&'a Comparator<'b>, &'a RadixCiphertext, U256) -> RadixCiphertext,
        ClearF: Fn(U256, U256) -> U256,
    {
        let mut rng = rand::thread_rng();

        let num_block = (256f64 / (param.message_modulus.0 as f64).log(2.0)).ceil() as usize;

        let (cks, sks) = gen_keys(param);
        let comparator = Comparator::new(&sks);

        for _ in 0..num_test {
            let clear_a = rng.gen::<U256>();
            let clear_b = rng.gen::<U256>();

            let a = cks.encrypt_radix(clear_a, num_block);

            {
                let result = unchecked_comparator_method(&comparator, &a, clear_b);
                let decrypted: U256 = cks.decrypt_radix(&result);
                let expected_result = clear_fn(clear_a, clear_b);
                assert_eq!(decrypted, expected_result);
            }

            {
                // Force case where lhs == rhs
                let result = unchecked_comparator_method(&comparator, &a, clear_a);
                let decrypted: U256 = cks.decrypt_radix(&result);
                let expected_result = clear_fn(clear_a, clear_a);
                assert_eq!(decrypted, expected_result);
            }
        }
    }

    /// Function to test a "smart_scalar" comparator function.
    fn test_smart_scalar_function<SmartFn, ClearF>(
        param: ClassicPBSParameters,
        num_test: usize,
        smart_comparator_method: SmartFn,
        clear_fn: ClearF,
    ) where
        SmartFn:
            for<'a, 'b> Fn(&'a Comparator<'b>, &'a mut RadixCiphertext, U256) -> RadixCiphertext,
        ClearF: Fn(U256, U256) -> U256,
    {
        let (cks, sks) = gen_keys(param);
        let num_block = (256f64 / (param.message_modulus.0 as f64).log(2.0)).ceil() as usize;
        let comparator = Comparator::new(&sks);

        let mut rng = rand::thread_rng();

        for _ in 0..num_test {
            let mut clear_0 = rng.gen::<U256>();
            let clear_1 = rng.gen::<U256>();
            let mut ct_0 = cks.encrypt_radix(clear_0, num_block);

            // Raise the degree, so as to ensure worst case path in operations
            while !super::has_non_zero_carries(&ct_0) {
                let clear_2 = rng.gen::<U256>();
                let ct_2 = cks.encrypt_radix(clear_2, num_block);
                sks.unchecked_add_assign(&mut ct_0, &ct_2);
                clear_0 += clear_2;
            }

            // Sanity decryption checks
            {
                let a: U256 = cks.decrypt_radix(&ct_0);
                assert_eq!(a, clear_0);
            }

            assert!(super::has_non_zero_carries(&ct_0));
            let encrypted_result = smart_comparator_method(&comparator, &mut ct_0, clear_1);
            assert!(!super::has_non_zero_carries(&ct_0));

            // Sanity decryption checks
            {
                let a: U256 = cks.decrypt_radix(&ct_0);
                assert_eq!(a, clear_0);
            }

            let decrypted_result: U256 = cks.decrypt_radix(&encrypted_result);

            let expected_result = clear_fn(clear_0, clear_1);
            assert_eq!(decrypted_result, expected_result);
        }
    }

    /// Function to test a "default_scalar" comparator function.
    fn test_default_scalar_function<SmartFn, ClearF>(
        param: ClassicPBSParameters,
        num_test: usize,
        default_comparator_method: SmartFn,
        clear_fn: ClearF,
    ) where
        SmartFn: for<'a, 'b> Fn(&'a Comparator<'b>, &'a RadixCiphertext, U256) -> RadixCiphertext,
        ClearF: Fn(U256, U256) -> U256,
    {
        let (cks, sks) = gen_keys(param);
        let num_block = (256f64 / (param.message_modulus.0 as f64).log(2.0)).ceil() as usize;
        let comparator = Comparator::new(&sks);

        let mut rng = rand::thread_rng();

        for _ in 0..num_test {
            let mut clear_0 = rng.gen::<U256>();
            let clear_1 = rng.gen::<U256>();

            let mut ct_0 = cks.encrypt_radix(clear_0, num_block);

            // Raise the degree, so as to ensure worst case path in operations
            while !super::has_non_zero_carries(&ct_0) {
                let clear_2 = rng.gen::<U256>();
                let ct_2 = cks.encrypt_radix(clear_2, num_block);
                sks.unchecked_add_assign(&mut ct_0, &ct_2);
                clear_0 += clear_2;
            }

            // Sanity decryption checks
            {
                let a: U256 = cks.decrypt_radix(&ct_0);
                assert_eq!(a, clear_0);
            }

            assert!(super::has_non_zero_carries(&ct_0));
            let encrypted_result = default_comparator_method(&comparator, &ct_0, clear_1);
            assert!(!super::has_non_zero_carries(&encrypted_result));

            // Sanity decryption checks
            {
                let a: U256 = cks.decrypt_radix(&ct_0);
                assert_eq!(a, clear_0);
            }

            let decrypted_result: U256 = cks.decrypt_radix(&encrypted_result);

            let expected_result = clear_fn(clear_0, clear_1);
            assert_eq!(decrypted_result, expected_result);
        }
    }

    /// This macro generates the tests for a given scalar comparison fn
    ///
    /// All our scalar comparison function have 3 variants:
    /// - unchecked_scalar_$comparison_name_parallelized
    /// - smart_scalar_$comparison_name_parallelized
    /// - scalar_$comparison_name_parallelized
    ///
    /// So, for example, for the `gt` comparison fn,
    /// this macro will generate the tests for the 3 variants described above
    macro_rules! define_scalar_comparison_test_functions {
        ($comparison_name:ident) => {
            paste::paste!{

                fn [<unchecked_scalar_ $comparison_name _parallelized_256_bits>](params:  crate::shortint::ClassicPBSParameters) {
                    let num_tests = 1;
                    test_unchecked_scalar_function(
                        params,
                        num_tests,
                        |comparator, lhs, rhs| comparator.[<unchecked_scalar_ $comparison_name _parallelized>](lhs, rhs),
                        |lhs, rhs| U256::from(<U256>::$comparison_name(&lhs, &rhs) as u128),
                    )
                }

                fn [<smart_scalar_ $comparison_name _parallelized_256_bits>](params:  crate::shortint::ClassicPBSParameters) {
                    let num_tests = 1;
                    test_smart_scalar_function(
                        params,
                        num_tests,
                        |comparator, lhs, rhs| comparator.[<smart_scalar_ $comparison_name _parallelized>](lhs, rhs),
                        |lhs, rhs| U256::from(<U256>::$comparison_name(&lhs, &rhs) as u128),
                    )
                }

                fn [<scalar_ $comparison_name _parallelized_256_bits>](params:  crate::shortint::ClassicPBSParameters) {
                    let num_tests = 1;
                    test_default_scalar_function(
                        params,
                        num_tests,
                        |comparator, lhs, rhs| comparator.[<scalar_ $comparison_name _parallelized>](lhs, rhs),
                        |lhs, rhs| U256::from(<U256>::$comparison_name(&lhs, &rhs) as u128),
                    )
                }

                create_parametrized_test!([<unchecked_scalar_ $comparison_name _parallelized_256_bits>]
                {
                    PARAM_MESSAGE_2_CARRY_2_KS_PBS,
                    PARAM_MESSAGE_3_CARRY_3_KS_PBS,
                    PARAM_MESSAGE_4_CARRY_4_KS_PBS
                });

                create_parametrized_test!([<smart_scalar_ $comparison_name _parallelized_256_bits>]
                {
                    PARAM_MESSAGE_2_CARRY_2_KS_PBS,
                    // We don't use PARAM_MESSAGE_3_CARRY_3_KS_PBS,
                    // as smart test might overflow values
                    // and when using 3_3 to represent 256 we actually have more than 256 bits
                    // of message so the overflow behaviour is not the same, leading to false negatives
                    PARAM_MESSAGE_4_CARRY_4_KS_PBS
                });

                create_parametrized_test!([<scalar_ $comparison_name _parallelized_256_bits>]
                {
                    PARAM_MESSAGE_2_CARRY_2_KS_PBS,
                    // We don't use PARAM_MESSAGE_3_CARRY_3_KS_PBS,
                    // as default test might overflow values
                    // and when using 3_3 to represent 256 we actually have more than 256 bits
                    // of message so the overflow behaviour is not the same, leading to false negatives
                    PARAM_MESSAGE_4_CARRY_4_KS_PBS
                });
            }
        };
    }

    define_scalar_comparison_test_functions!(eq);
    define_scalar_comparison_test_functions!(ne);
    define_scalar_comparison_test_functions!(lt);
    define_scalar_comparison_test_functions!(le);
    define_scalar_comparison_test_functions!(gt);
    define_scalar_comparison_test_functions!(ge);

    fn test_unchecked_scalar_min_parallelized_256_bits(
        params: crate::shortint::ClassicPBSParameters,
        num_tests: usize,
    ) {
        test_unchecked_function(
            params,
            num_tests,
            |comparator, lhs, rhs| comparator.unchecked_min_parallelized(lhs, rhs),
            std::cmp::min,
        )
    }

    fn test_unchecked_scalar_max_parallelized_256_bits(
        params: crate::shortint::ClassicPBSParameters,
        num_tests: usize,
    ) {
        test_unchecked_function(
            params,
            num_tests,
            |comparator, lhs, rhs| comparator.unchecked_max_parallelized(lhs, rhs),
            std::cmp::max,
        )
    }

    fn test_scalar_min_parallelized_256_bits(
        params: crate::shortint::ClassicPBSParameters,
        num_tests: usize,
    ) {
        test_default_function(
            params,
            num_tests,
            |comparator, lhs, rhs| comparator.min_parallelized(lhs, rhs),
            std::cmp::min,
        )
    }

    fn test_scalar_max_parallelized_256_bits(
        params: crate::shortint::ClassicPBSParameters,
        num_tests: usize,
    ) {
        test_default_function(
            params,
            num_tests,
            |comparator, lhs, rhs| comparator.max_parallelized(lhs, rhs),
            std::cmp::max,
        )
    }

    //================
    // Scalar Min
    //================

    #[test]
    fn test_unchecked_scalar_min_parallelized_256_bits_param_message_2_carry_2_ks_pbs() {
        test_unchecked_scalar_min_parallelized_256_bits(
            crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            4,
        )
    }

    #[test]
    fn test_unchecked_scalar_min_parallelized_256_bits_param_message_3_carry_3_ks_pbs() {
        test_unchecked_scalar_min_parallelized_256_bits(
            crate::shortint::parameters::PARAM_MESSAGE_3_CARRY_3_KS_PBS,
            2,
        )
    }

    #[test]
    fn test_unchecked_scalar_min_parallelized_256_bits_param_message_4_carry_4_ks_pbs() {
        test_unchecked_scalar_min_parallelized_256_bits(
            crate::shortint::parameters::PARAM_MESSAGE_4_CARRY_4_KS_PBS,
            2,
        )
    }

    #[test]
    fn test_scalar_min_parallelized_256_bits_param_message_2_carry_2_ks_pbs() {
        test_scalar_min_parallelized_256_bits(
            crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            4,
        )
    }

    #[test]
    fn test_scalar_min_parallelized_256_bits_param_message_4_carry_4_ks_pbs() {
        test_scalar_min_parallelized_256_bits(
            crate::shortint::parameters::PARAM_MESSAGE_4_CARRY_4_KS_PBS,
            2,
        )
    }

    //================
    // Scalar Max
    //================

    #[test]
    fn test_unchecked_scalar_max_parallelized_256_bits_param_message_2_carry_2_ks_pbs() {
        test_unchecked_scalar_max_parallelized_256_bits(
            crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            4,
        )
    }

    #[test]
    fn test_unchecked_scalar_max_parallelized_256_bits_param_message_3_carry_3_ks_pbs() {
        test_unchecked_scalar_max_parallelized_256_bits(
            crate::shortint::parameters::PARAM_MESSAGE_3_CARRY_3_KS_PBS,
            2,
        )
    }

    #[test]
    fn test_unchecked_scalar_max_parallelized_256_bits_param_message_4_carry_4_ks_pbs() {
        test_unchecked_scalar_max_parallelized_256_bits(
            crate::shortint::parameters::PARAM_MESSAGE_4_CARRY_4_KS_PBS,
            2,
        )
    }

    #[test]
    fn test_scalar_max_parallelized_256_bits_param_message_2_carry_2_ks_pbs() {
        test_scalar_max_parallelized_256_bits(
            crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            4,
        )
    }

    #[test]
    fn test_scalar_max_parallelized_256_bits_param_message_4_carry_4_ks_pbs() {
        test_scalar_max_parallelized_256_bits(
            crate::shortint::parameters::PARAM_MESSAGE_4_CARRY_4_KS_PBS,
            2,
        )
    }

    /// The goal of this function is to ensure that scalar comparisons
    /// work when the scalar type used is either bigger or smaller (in bit size)
    /// compared to the ciphertext
    fn test_unchecked_scalar_comparisons_edge(param: ClassicPBSParameters) {
        let mut rng = rand::thread_rng();

        let num_block = (128f64 / (param.message_modulus.0 as f64).log(2.0)).ceil() as usize;

        let (cks, sks) = gen_keys(param);
        let comparator = Comparator::new(&sks);

        for _ in 0..4 {
            let clear_a = rng.gen::<u128>();
            let smaller_clear = rng.gen::<u64>();
            let bigger_clear = rng.gen::<U256>();

            let a = cks.encrypt_radix(clear_a, num_block);

            // >=
            {
                let result = comparator.unchecked_scalar_ge_parallelized(&a, smaller_clear);
                let decrypted: U256 = cks.decrypt_radix(&result);
                assert_eq!(
                    decrypted,
                    U256::from(U256::from(clear_a) >= U256::from(smaller_clear))
                );

                let result = comparator.unchecked_scalar_ge_parallelized(&a, bigger_clear);
                let decrypted: U256 = cks.decrypt_radix(&result);
                assert_eq!(decrypted, U256::from(U256::from(clear_a) >= bigger_clear));
            }

            // >
            {
                let result = comparator.unchecked_scalar_gt_parallelized(&a, smaller_clear);
                let decrypted: U256 = cks.decrypt_radix(&result);
                assert_eq!(
                    decrypted,
                    U256::from(U256::from(clear_a) > U256::from(smaller_clear))
                );

                let result = comparator.unchecked_scalar_gt_parallelized(&a, bigger_clear);
                let decrypted: U256 = cks.decrypt_radix(&result);
                assert_eq!(decrypted, U256::from(U256::from(clear_a) > bigger_clear));
            }

            // <=
            {
                let result = comparator.unchecked_scalar_le_parallelized(&a, smaller_clear);
                let decrypted: U256 = cks.decrypt_radix(&result);
                assert_eq!(
                    decrypted,
                    U256::from(U256::from(clear_a) <= U256::from(smaller_clear))
                );

                let result = comparator.unchecked_scalar_le_parallelized(&a, bigger_clear);
                let decrypted: U256 = cks.decrypt_radix(&result);
                assert_eq!(decrypted, U256::from(U256::from(clear_a) <= bigger_clear));
            }

            // <
            {
                let result = comparator.unchecked_scalar_lt_parallelized(&a, smaller_clear);
                let decrypted: U256 = cks.decrypt_radix(&result);
                assert_eq!(
                    decrypted,
                    U256::from(U256::from(clear_a) < U256::from(smaller_clear))
                );

                let result = comparator.unchecked_scalar_lt_parallelized(&a, bigger_clear);
                let decrypted: U256 = cks.decrypt_radix(&result);
                assert_eq!(decrypted, U256::from(U256::from(clear_a) < bigger_clear));
            }

            // ==
            {
                let result = comparator.unchecked_scalar_eq_parallelized(&a, smaller_clear);
                let decrypted: U256 = cks.decrypt_radix(&result);
                assert_eq!(
                    decrypted,
                    U256::from(U256::from(clear_a) == U256::from(smaller_clear))
                );

                let result = comparator.unchecked_scalar_eq_parallelized(&a, bigger_clear);
                let decrypted: U256 = cks.decrypt_radix(&result);
                assert_eq!(decrypted, U256::from(U256::from(clear_a) == bigger_clear));
            }

            // !=
            {
                let result = comparator.unchecked_scalar_ne_parallelized(&a, smaller_clear);
                let decrypted: U256 = cks.decrypt_radix(&result);
                assert_eq!(
                    decrypted,
                    U256::from(U256::from(clear_a) != U256::from(smaller_clear))
                );

                let result = comparator.unchecked_scalar_ne_parallelized(&a, bigger_clear);
                let decrypted: U256 = cks.decrypt_radix(&result);
                assert_eq!(decrypted, U256::from(U256::from(clear_a) != bigger_clear));
            }

            // Here the goal is to test, the branching
            // made in the scalar sign function
            //
            // We are forcing one of the two branches to work on empty slices
            {
                let result = comparator.unchecked_scalar_lt_parallelized(&a, U256::ZERO);
                let decrypted: U256 = cks.decrypt_radix(&result);
                assert_eq!(decrypted, U256::from(U256::from(clear_a) < U256::ZERO));

                let result = comparator.unchecked_scalar_lt_parallelized(&a, U256::MAX);
                let decrypted: U256 = cks.decrypt_radix(&result);
                assert_eq!(decrypted, U256::from(U256::from(clear_a) < U256::MAX));

                // == (as it does not share same code)
                let result = comparator.unchecked_scalar_eq_parallelized(&a, U256::ZERO);
                let decrypted: U256 = cks.decrypt_radix(&result);
                assert_eq!(decrypted, U256::from(U256::from(clear_a) == U256::ZERO));

                // != (as it does not share same code)
                let result = comparator.unchecked_scalar_ne_parallelized(&a, U256::MAX);
                let decrypted: U256 = cks.decrypt_radix(&result);
                assert_eq!(decrypted, U256::from(U256::from(clear_a) != U256::MAX));
            }
        }
    }

    create_parametrized_test!(test_unchecked_scalar_comparisons_edge {
        PARAM_MESSAGE_2_CARRY_2_KS_PBS,
        PARAM_MESSAGE_3_CARRY_3_KS_PBS,
        PARAM_MESSAGE_4_CARRY_4_KS_PBS
    });
}
