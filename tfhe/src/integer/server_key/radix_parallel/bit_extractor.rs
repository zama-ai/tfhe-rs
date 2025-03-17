use crate::integer::ServerKey;
use crate::shortint::server_key::ManyLookupTableOwned;
use crate::shortint::Ciphertext;
use rayon::prelude::*;
use std::collections::VecDeque;

/// Extracts bits from a slice of shortint ciphertext
///
/// * Relies on many-lut to do less PBSes
/// * Position of the extracted bit is customizable
/// * Has a buffer system that allows to pre-generate extracted bits such that the next call to
///   `next()` is free, giving better control as to where computations happen
pub(crate) struct BitExtractor<'a> {
    input_blocks: std::slice::Iter<'a, Ciphertext>,
    bit_extract_luts: Option<ManyLookupTableOwned>,
    bits_per_block: usize,
    server_key: &'a ServerKey,
    buffer: VecDeque<Ciphertext>,
}

impl Iterator for BitExtractor<'_> {
    type Item = Ciphertext;

    fn next(&mut self) -> Option<Self::Item> {
        let maybe_bit_block = self.buffer.pop_front();
        if maybe_bit_block.is_some() {
            return maybe_bit_block;
        }

        self.prepare_next_batch();

        self.buffer.pop_front()
    }
}

impl<'a> BitExtractor<'a> {
    pub(crate) fn new(
        input: &'a [Ciphertext],
        server_key: &'a ServerKey,
        bits_per_block: usize,
    ) -> Self {
        Self::with_final_offset(input, server_key, bits_per_block, 0)
    }

    /// Creates a bit extractor that will extract bits from an input ciphertext
    /// into single blocks.
    ///
    /// The final offset gives the position where the extracted bit shall be placed
    /// in the resulting block.
    /// It may be used to align the bit with a certain position to avoid
    /// shifting it later (and increasing noise)
    pub(crate) fn with_final_offset(
        input: &'a [Ciphertext],
        server_key: &'a ServerKey,
        bits_per_block: usize,
        final_offset: usize,
    ) -> Self {
        assert_eq!(
            server_key.message_modulus().0,
            server_key.carry_modulus().0,
            "BitExtractor requires parameters with carry modulus == message modulus"
        );
        let bit_extract_luts = if bits_per_block == 1 && final_offset == 0 {
            None
        } else {
            let bit_extract_fns = (0..bits_per_block)
                .into_par_iter()
                .map(|i| {
                    move |x: u64| {
                        let bit_value = (x >> i) & 1u64;
                        bit_value << final_offset
                    }
                })
                .collect::<Vec<_>>();

            let tmp = bit_extract_fns
                .iter()
                .map(|func| func as &dyn Fn(u64) -> u64)
                .collect::<Vec<_>>();

            Some(server_key.key.generate_many_lookup_table(tmp.as_slice()))
        };

        Self {
            input_blocks: input.iter(),
            bit_extract_luts,
            bits_per_block,
            server_key,
            buffer: VecDeque::with_capacity(2 * bits_per_block),
        }
    }

    pub(crate) fn set_source_blocks(&mut self, blocks: &'a [Ciphertext]) {
        self.input_blocks = blocks.iter();
        self.buffer.clear();
    }

    pub(crate) fn prepare_next_batch(&mut self) {
        if self.buffer.is_empty() {
            let Some(next_block_to_extract_from) = self.input_blocks.next() else {
                return;
            };

            match &self.bit_extract_luts {
                None => self.buffer.push_back(next_block_to_extract_from.clone()),
                Some(bit_extract_luts) => {
                    let new_bits = self
                        .server_key
                        .key
                        .apply_many_lookup_table(next_block_to_extract_from, bit_extract_luts);

                    self.buffer.extend(new_bits);
                }
            }
        }
    }

    /// Extract the remaining `n` bits in parallel from the current source blocks
    /// and place them into the internal buffer
    ///
    /// # Panics
    ///
    /// Panics if the current slice of blocks has less than n bits available
    pub(crate) fn prepare_n_bits(&mut self, n: usize) {
        if self.buffer.len() >= n {
            return;
        }

        let num_bits_to_extract = n - self.buffer.len();
        let num_blocks_to_process = num_bits_to_extract.div_ceil(self.bits_per_block);
        let blocks = self.input_blocks.as_slice();

        if let Some(bit_extract_luts) = &self.bit_extract_luts {
            let mut new_bits = blocks[..num_blocks_to_process]
                .par_iter()
                .flat_map(|block| {
                    self.server_key
                        .key
                        .apply_many_lookup_table(block, bit_extract_luts)
                })
                .collect::<Vec<_>>();
            self.buffer.extend(new_bits.drain(..));
        } else {
            let iterator = blocks[..num_blocks_to_process].iter().cloned();
            self.buffer.extend(iterator);
        }

        // We have to advance our internal iterator
        self.input_blocks = blocks[num_blocks_to_process..].iter();
    }

    /// Extract all the remaining bits in parallel from the current source blocks
    pub(crate) fn extract_all_bits(&mut self) -> Vec<Ciphertext> {
        let num_blocks = self.input_blocks.len();
        self.extract_n_bits(num_blocks * self.bits_per_block)
    }

    /// Extract the remaining `n` bits in parallel from the current source blocks
    ///
    /// # Panics
    ///
    /// Panics if the current slice of blocks has less than n bits available
    pub(crate) fn extract_n_bits(&mut self, n: usize) -> Vec<Ciphertext> {
        self.prepare_n_bits(n);

        let mut bits = Vec::with_capacity(n);
        bits.extend(self.buffer.drain(0..n));
        bits
    }

    pub(crate) fn current_buffer_len(&self) -> usize {
        self.buffer.len()
    }
}
