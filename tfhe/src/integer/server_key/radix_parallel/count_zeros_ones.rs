use super::ServerKey;
use crate::integer::server_key::num_bits_to_represent_unsigned_value;
use crate::integer::{IntegerRadixCiphertext, RadixCiphertext, SignedRadixCiphertext};
use crate::shortint::ciphertext::Degree;

use rayon::prelude::*;

#[derive(Copy, Clone, PartialEq, Eq)]
enum BitCountKind {
    Zero,
    One,
}

impl BitCountKind {
    fn is_ok(self, bit_value: u64) -> u64 {
        match self {
            Self::Zero => u64::from(bit_value == 0),
            Self::One => u64::from(bit_value == 1),
        }
    }
}

impl ServerKey {
    /// Returns the number of ones in the binary representation of `ct`
    ///
    /// * ct must not have any carries
    /// * The returned result has enough blocks to encrypt 32bits (e.g. 1_1 parameters -> 32 blocks,
    ///   3_3 parameters -> 11 blocks == 33 bits)
    pub fn unchecked_count_ones_parallelized<T>(&self, ct: &T) -> RadixCiphertext
    where
        T: IntegerRadixCiphertext,
    {
        self.unchecked_count_bits_parallelized(ct, BitCountKind::One)
    }

    /// Returns the number of zeros in the binary representation of `ct`
    ///
    /// * ct must not have any carries
    /// * The returned result has enough blocks to encrypt 32bits (e.g. 1_1 parameters -> 32 blocks,
    ///   3_3 parameters -> 11 blocks == 33 bits)
    pub fn unchecked_count_zeros_parallelized<T>(&self, ct: &T) -> RadixCiphertext
    where
        T: IntegerRadixCiphertext,
    {
        self.unchecked_count_bits_parallelized(ct, BitCountKind::Zero)
    }

    fn unchecked_count_bits_parallelized<T>(&self, ct: &T, kind: BitCountKind) -> RadixCiphertext
    where
        T: IntegerRadixCiphertext,
    {
        if self.message_modulus().0 == 4 && self.carry_modulus().0 == 4 {
            self.count_bits_2_2(ct, kind)
        } else {
            self.count_bits_naive(ct, kind)
        }
    }

    /// Returns the number of ones in the binary representation of `ct`
    ///
    /// * The returned result has enough blocks to encrypt 32bits (e.g. 1_1 parameters -> 32 blocks,
    ///   3_3 parameters -> 11 blocks == 33 bits)
    pub fn smart_count_ones_parallelized<T>(&self, ct: &mut T) -> RadixCiphertext
    where
        T: IntegerRadixCiphertext,
    {
        self.smart_count_bits_parallelized(ct, BitCountKind::One)
    }

    /// Returns the number of zeros in the binary representation of `ct`
    ///
    /// * The returned result has enough blocks to encrypt 32bits (e.g. 1_1 parameters -> 32 blocks,
    ///   3_3 parameters -> 11 blocks == 33 bits)
    pub fn smart_count_zeros_parallelized<T>(&self, ct: &mut T) -> RadixCiphertext
    where
        T: IntegerRadixCiphertext,
    {
        self.smart_count_bits_parallelized(ct, BitCountKind::Zero)
    }

    fn smart_count_bits_parallelized<T>(&self, ct: &mut T, kind: BitCountKind) -> RadixCiphertext
    where
        T: IntegerRadixCiphertext,
    {
        if !ct.block_carries_are_empty() {
            self.full_propagate_parallelized(ct);
        }

        self.unchecked_count_bits_parallelized(ct, kind)
    }

    /// Returns the number of ones in the binary representation of `ct`
    ///
    /// * The returned result has enough blocks to encrypt 32bits (e.g. 1_1 parameters -> 32 blocks,
    ///   3_3 parameters -> 11 blocks == 33 bits)
    pub fn count_ones_parallelized<T>(&self, ct: &T) -> RadixCiphertext
    where
        T: IntegerRadixCiphertext,
    {
        self.count_bits_parallelized(ct, BitCountKind::One)
    }

    /// Returns the number of zeros in the binary representation of `ct`
    ///
    /// * The returned result has enough blocks to encrypt 32bits (e.g. 1_1 parameters -> 32 blocks,
    ///   3_3 parameters -> 11 blocks == 33 bits)
    pub fn count_zeros_parallelized<T>(&self, ct: &T) -> RadixCiphertext
    where
        T: IntegerRadixCiphertext,
    {
        self.count_bits_parallelized(ct, BitCountKind::Zero)
    }

    fn count_bits_parallelized<T>(&self, ct: &T, kind: BitCountKind) -> RadixCiphertext
    where
        T: IntegerRadixCiphertext,
    {
        let mut tmp_ct;
        let ct = if ct.block_carries_are_empty() {
            ct
        } else {
            tmp_ct = ct.clone();
            self.full_propagate_parallelized(&mut tmp_ct);
            &tmp_ct
        };

        self.unchecked_count_bits_parallelized(ct, kind)
    }

    /// 'Naive' implementation of count zeros/ones
    ///
    /// * It will work for all parameters
    /// * ct must not have any carries
    /// * The returned result has enough blocks to encrypt 32bits (e.g. 1_1 parameters -> 32 blocks,
    ///   3_3 parameters -> 11 blocks == 33 bits)
    fn count_bits_naive<T>(&self, ct: &T, count_kind: BitCountKind) -> RadixCiphertext
    where
        T: IntegerRadixCiphertext,
    {
        let min_num_blocks_to_have_32_bits = 32u32.div_ceil(self.message_modulus().0.ilog2());
        if ct.blocks().is_empty() {
            return self.create_trivial_zero_radix(min_num_blocks_to_have_32_bits as usize);
        }
        let num_bits_in_block = self.message_modulus().0.ilog2();

        let lut_count_bits = self.key.generate_lookup_table(|x| {
            let mut count = 0u64;
            for i in 0..(num_bits_in_block * 2) {
                count += (x >> i) & 1;
            }
            count
        });

        // We can pack the block if the carry space allow it, but more importantly,
        // if the number of bits in 2 blocks does not exceed the message modulus
        // e.g. 1_1 -> 1 bits in one block -> 2 blocks = 2 bits -> 2 >= 2**1 (2)-> cant pack
        //      3_3 -> 3 bits in one block -> 2 blocks = 6 bits  -> 6 < 2**3 (8) -> can pack
        let can_pack = self.carry_modulus().0 >= self.message_modulus().0
            && (num_bits_in_block * 2) < (self.message_modulus().0 as u32);
        let pre_count = if can_pack {
            ct.blocks()
                .par_chunks(2)
                .map(|chunk_of_two| {
                    let mut packed = self.pack_block_chunk(chunk_of_two);
                    self.key
                        .apply_lookup_table_assign(&mut packed, &lut_count_bits);
                    RadixCiphertext::from(vec![packed])
                })
                .collect::<Vec<_>>()
        } else if num_bits_in_block > 1 {
            // This is a bit suboptimal for 2_2, but there is a specialized algorithm for that
            ct.blocks()
                .par_iter()
                .map(|block| {
                    let mut block = self.key.apply_lookup_table(block, &lut_count_bits);
                    // We used a LUT that spans 2*num_bits_in_block, however there was only one
                    // block, so the estimated degree is not correct, we set it, otherwise
                    // a spurious full propagation would happen later
                    block.degree = Degree::new(u64::from(num_bits_in_block));
                    RadixCiphertext::from(vec![block])
                })
                .collect::<Vec<_>>()
        } else {
            // For 1_1, no need to do a PBS to count bits
            ct.blocks()
                .iter()
                .cloned()
                .map(|block| RadixCiphertext::from(vec![block]))
                .collect::<Vec<_>>()
        };

        let max_possible_bit_count = num_bits_in_block
            .checked_mul(ct.blocks().len() as u32)
            .expect("Number of bits exceed u32::MAX");
        let num_unsigned_blocks =
            self.num_blocks_to_represent_unsigned_value(max_possible_bit_count);
        if count_kind == BitCountKind::One {
            let things_to_sum = pre_count
                .into_iter()
                .map(|ct| self.cast_to_unsigned(ct, num_unsigned_blocks))
                .collect::<Vec<_>>();

            let result = self
                .unchecked_sum_ciphertexts_vec_parallelized(things_to_sum)
                .unwrap_or_else(|| {
                    self.create_trivial_zero_radix(min_num_blocks_to_have_32_bits as usize)
                });

            self.cast_to_unsigned(result, min_num_blocks_to_have_32_bits as usize)
        } else {
            // This is like the ilog2 idea
            //
            // num_zeros = num_bits - num_ones
            // num_zeros =  -(-(num_bits - num_ones))
            // -num_zeros =  -(num_bits - num_ones)
            // -num_zeros = -num_bits + num_ones
            //
            // doing `-num_bits` is easy
            //
            // We could technically have done a LUT that counted zeros instead of ones in the
            // step above.
            // But in the case of 1_X parameters, counting ones does not require to have
            // a LUT done on each block to count the number of ones, and to avoid having to do a
            // LUT to count zeros we prefer to change a bit the sum
            let num_bits_needed = num_bits_to_represent_unsigned_value(max_possible_bit_count) + 1;
            let num_signed_blocks = num_bits_needed.div_ceil(num_bits_in_block as usize);
            assert!(num_signed_blocks >= num_unsigned_blocks);

            let mut things_to_sum = pre_count
                .into_iter()
                .map(|ct| self.cast_to_signed(ct, num_signed_blocks))
                .collect::<Vec<_>>();

            things_to_sum.push(
                self.create_trivial_radix(-i64::from(max_possible_bit_count), num_signed_blocks),
            );
            let result = self
                .unchecked_partial_sum_ciphertexts_vec_parallelized(things_to_sum, None)
                .expect("internal error, empty ciphertext count");
            let (message_blocks, carry_blocks) = rayon::join(
                || {
                    let lut = self.key.generate_lookup_table(|x| {
                        // extract message
                        let x = x % self.key.message_modulus.0;
                        // bitnot the message
                        (!x) % self.key.message_modulus.0
                    });
                    result
                        .blocks
                        .par_iter()
                        .map(|block| self.key.apply_lookup_table(block, &lut))
                        .collect::<Vec<_>>()
                },
                || {
                    let lut = self.key.generate_lookup_table(|x| {
                        // extract carry
                        let x = x / self.key.message_modulus.0;
                        // bitnot the carry
                        (!x) % self.key.message_modulus.0
                    });
                    let mut carry_blocks = Vec::with_capacity(num_unsigned_blocks);
                    result.blocks[..num_signed_blocks - 1] // last carry is not interesting
                        .par_iter()
                        .map(|block| self.key.apply_lookup_table(block, &lut))
                        .collect_into_vec(&mut carry_blocks);
                    // Normally this would be 0, but we want the bitnot of 0, which is msg_mod-1
                    carry_blocks.insert(0, self.key.create_trivial(self.message_modulus().0 - 1));
                    carry_blocks
                },
            );
            let message = SignedRadixCiphertext::from(message_blocks);
            let carry = SignedRadixCiphertext::from(carry_blocks);
            let result = self
                .sum_ciphertexts_parallelized(
                    [
                        message,
                        carry,
                        self.create_trivial_radix(2u32, num_signed_blocks),
                    ]
                    .iter(),
                )
                // Go back to unsigned world because we know the value cannot be negative
                // but casting from signed to unsigned may require to look at the sign bit
                // which we know is not set
                .map(|ct| RadixCiphertext::from(ct.blocks))
                .unwrap();

            self.cast_to_unsigned(result, min_num_blocks_to_have_32_bits as usize)
        }
    }

    /// More complex implementation of count zeros/ones meant for 2_2 parameters
    ///
    /// * It will only work for 2_2 parameters
    /// * ct must not have any carries
    /// * The returned result has enough blocks to encrypt 32bits (e.g. 1_1 parameters -> 32 blocks,
    ///   3_3 parameters -> 11 blocks == 33 bits)
    fn count_bits_2_2<T>(&self, ct: &T, count_kind: BitCountKind) -> RadixCiphertext
    where
        T: IntegerRadixCiphertext,
    {
        let num_bits_in_block = self.message_modulus().0.ilog2();
        let num_blocks = ct.blocks().len();
        let min_num_blocks_to_have_32_bits =
            32u32.div_ceil(self.message_modulus().0.ilog2()) as usize;

        if num_blocks == 0 {
            return self.create_trivial_zero_radix(min_num_blocks_to_have_32_bits);
        }

        // In 2_2, each block may have between 0 and 2 bits set.
        // 2_2 also allows 5 additions maximum (noise wise)
        // 2 * 5 = 10 which is less than the max value storable (15 = (2**4) -1)
        //
        // Since in 2_2 bivariate PBS is possible, we can actually group blocks by two.
        // Each pair of block may have between 0 and 4 bits set, meaning we could add 3 of those
        // count to stay <= 15
        // Degree: 4 * 3 == 12  which is <= 15
        // NoiseLevel: 3
        //
        // Now, to go further, with 3 blocks, which is 6 bits, we can do 2 bivariate PBS, to split
        // the count in two blocks with value in 0…=3
        // [b0,b1] [b2, b3] [b4, b5]
        // PBS 1 -> [b0, b1, b2, b3] -> count(b0, b1, b2)
        // PBS 2 -> [b2, b3, b4, b5] -> count(b3, b4, b5)
        // This also mean 2 PBS for 3 blocks, instead of 3 for 3
        //
        // Each of these blocks could be added to pairs described above, so the
        // degree would become (4 * 3) + 3 = 12 + 3 = 15,
        // and the noise level would be 3 + 1 = 4

        // As described, 3 pairs form a chunk, so we split the input blocks in chunks of
        // `3 * 2 = 6` blocks
        //
        // non_full_chunks are chunks with degree 12, and noise level 3
        // non_chunked are single blocks not belonging to any chunk
        let (mut num_non_full_chunks, mut num_non_chunked) = (num_blocks / 6, num_blocks % 6);
        let mut num_full_chunks = 0;

        // 'Dispatch' some of the non chunked blocks in to complete a chunk
        //
        // 3 blocks can be used to fill 2 chunks
        // We know num_non_chunked < 6, that's why this is an if, not a loop
        let mut num_duo_completer_blocks = 0;
        if num_non_full_chunks >= 2 && num_non_chunked >= 3 {
            num_non_chunked -= 3;
            num_non_full_chunks -= 2;
            num_full_chunks += 2;
            num_duo_completer_blocks += 3;
        }

        // The rest of non chunked blocks are simply going to complete
        // chunk each by adding their block count (that is in range 0…=2)
        // such complete chunk will have a degree = (4 * 3) + 2 = 14
        //
        // But that's as long as there are chunk to complete
        let num_single_completer_blocks = num_non_chunked.min(num_non_full_chunks);
        num_non_full_chunks -= num_single_completer_blocks;
        num_full_chunks += num_single_completer_blocks;
        num_non_chunked -= num_single_completer_blocks;

        // Now, we go a bit beyond again
        //
        // A non-full chunk has 3 packed blocks, so 6 ciphertexts
        // 3 ciphertexts can be split into 2 blocks, to complete 2 non-full chunks
        // so, this means that with 6 blocks we can complete 4 chunks
        //
        // So, a non-full chunk can be deconstructed to fill 4 other non-full chunks.
        // So for every 4 chunks non-full chunk we deconstruct one to fill them
        //
        // This lightly increases the number of PBS done at this stage,
        // but it gets compensated by reducing the number of PBS done at later stages
        // and reduces the number of ciphertexts to sum together
        //
        // This will actually start to happen for rather num_blocks >= 30 (aka 60 bits)
        let mut num_to_deconstruct = 0;
        let mut n = num_non_full_chunks;
        // >= 5 because to complete 4 chunks we need one chunk
        while n >= 5 {
            num_to_deconstruct += 1;
            num_full_chunks += 4;
            num_non_full_chunks -= 5;
            n -= 5; // 4 chunks are full because we deconstructed one
        }

        // We have 3 slices
        // * one with blocks to pack and apply the full bit-count on
        // * one with blocks to pack in a way that we can then apply bit-count on 3 bits
        // * one where we apply a bit count on 2 bits // the rest

        num_duo_completer_blocks += 6 * num_to_deconstruct;
        let num_single_blocks = num_non_chunked + num_single_completer_blocks;
        let num_regular_blocks = (num_full_chunks + num_non_full_chunks) * 6;

        // Make sure this span the whole input slice
        assert_eq!(
            num_regular_blocks + num_duo_completer_blocks + num_single_blocks,
            num_blocks
        );

        let regular_blocks = &ct.blocks()[..num_regular_blocks];
        let duo_completer_blocks =
            &ct.blocks()[num_regular_blocks..num_regular_blocks + num_duo_completer_blocks];
        let single_completer_blocks = &ct.blocks()[num_regular_blocks + num_duo_completer_blocks..];
        // Since we took the rest, make sure it has the len we expect, otherwise
        // result won't be correct
        assert_eq!(single_completer_blocks.len(), num_single_blocks);
        // must be chunk_exact by 3 otherwise there was an error earlier
        assert_eq!(duo_completer_blocks.len() % 3, 0);

        let lut_count_bits_full_range = self.key.generate_lookup_table(|x| {
            let mut count = 0u64;
            for i in 0..(num_bits_in_block * 2) {
                count += count_kind.is_ok((x >> i) & 1);
            }
            count
        });

        let lut_count_bits_half_range = self.key.generate_lookup_table(|x| {
            let mut count = 0u64;
            for i in 0..num_bits_in_block {
                count += count_kind.is_ok((x >> i) & 1);
            }
            count
        });

        let (bit_count_of_packed_blocks, mut bit_counts_of_completer_blocks) = rayon::join(
            || {
                regular_blocks
                    .par_chunks_exact(2)
                    .map(|chunk_of_two| {
                        let mut packed = self.pack_block_chunk(chunk_of_two);
                        self.key
                            .apply_lookup_table_assign(&mut packed, &lut_count_bits_full_range);
                        packed
                    })
                    .collect::<Vec<_>>()
            },
            || {
                let luts = [
                    self.key.generate_lookup_table(|x| {
                        let mut count = 0u64;
                        for i in 0..num_bits_in_block + 1 {
                            count += count_kind.is_ok((x >> i) & 1);
                        }
                        count
                    }),
                    self.key.generate_lookup_table(|x| {
                        let mut count = 0u64;
                        for i in 1..num_bits_in_block + 2 {
                            count += count_kind.is_ok((x >> i) & 1);
                        }
                        count
                    }),
                ];

                let mut packed_blocks = Vec::new();
                for chunk_of_3 in duo_completer_blocks.chunks_exact(3) {
                    packed_blocks.push(self.pack_block_chunk(&chunk_of_3[..2]));
                    packed_blocks.push(self.pack_block_chunk(&chunk_of_3[1..3]));
                }

                packed_blocks
                    .par_iter()
                    .enumerate()
                    .map(|(i, packed_block)| {
                        self.key.apply_lookup_table(packed_block, &luts[i % 2])
                    })
                    .chain(single_completer_blocks.par_iter().map(|block| {
                        self.key
                            .apply_lookup_table(block, &lut_count_bits_half_range)
                    }))
                    .collect::<Vec<_>>()
            },
        );

        // Since each block encrypts 4 bits, max count is 4
        let num_sum = self.max_sum_size(Degree::new(4));

        let mut pre_count = bit_count_of_packed_blocks
            .chunks_exact(num_sum)
            .map(|chunk| {
                let mut result = chunk[0].clone();
                for s in &chunk[1..] {
                    self.key.unchecked_add_assign(&mut result, s);
                }
                result
            })
            .collect::<Vec<_>>();

        // Complete the chunks to maximize degree and minimize sum depths
        for (p, c) in pre_count
            .iter_mut()
            .zip(bit_counts_of_completer_blocks.iter())
        {
            self.key.unchecked_add_assign(p, c);
        }

        let mut pre_count = pre_count
            .par_iter()
            .map(|block| {
                if block.degree.get() >= self.message_modulus().0 {
                    let (msg, carry) = rayon::join(
                        || self.key.message_extract(block),
                        || self.key.carry_extract(block),
                    );
                    RadixCiphertext::from(vec![msg, carry])
                } else {
                    let msg = self.key.message_extract(block);
                    RadixCiphertext::from(vec![msg])
                }
            })
            .collect::<Vec<_>>();

        if pre_count.len() < bit_counts_of_completer_blocks.len() {
            // Then not all blocks were consumed
            // we not forget to add them to the sum list
            for b in bit_counts_of_completer_blocks.drain(pre_count.len()..) {
                pre_count.push(RadixCiphertext::from(vec![b]));
            }
        }

        let max_possible_bit_count = num_bits_in_block
            .checked_mul(ct.blocks().len() as u32)
            .expect("Number of bits exceed u32::MAX");
        let num_blocks = self.num_blocks_to_represent_unsigned_value(max_possible_bit_count);

        let things_to_sum = pre_count
            .into_iter()
            .map(|ct| self.cast_to_unsigned(ct, num_blocks))
            .collect::<Vec<_>>();

        let result = self
            .unchecked_sum_ciphertexts_vec_parallelized(things_to_sum)
            .unwrap_or_else(|| self.create_trivial_zero_radix(min_num_blocks_to_have_32_bits));

        self.cast_to_unsigned(result, min_num_blocks_to_have_32_bits)
    }
}
