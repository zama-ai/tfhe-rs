use crate::integer::ServerKey;
use crate::shortint::server_key::LookupTableOwned;
use crate::shortint::Ciphertext;
use itertools::iproduct;
use rayon::prelude::*;

pub(crate) struct BitExtractor<'a> {
    bit_extract_luts: Vec<LookupTableOwned>,
    bits_per_block: usize,
    server_key: &'a ServerKey,
}

impl<'a> BitExtractor<'a> {
    pub(crate) fn new(server_key: &'a ServerKey, bits_per_block: usize) -> Self {
        let bit_extract_luts = (0..bits_per_block)
            .into_par_iter()
            .map(|i| server_key.key.generate_lookup_table(|x| (x >> i) & 1))
            .collect::<Vec<_>>();

        Self {
            bit_extract_luts,
            server_key,
            bits_per_block,
        }
    }

    pub(crate) fn extract_all_bits(&self, blocks: &[Ciphertext]) -> Vec<Ciphertext> {
        let num_blocks = blocks.len();
        self.extract_n_bits(blocks, num_blocks * self.bits_per_block)
    }

    pub(crate) fn extract_n_bits(&self, blocks: &[Ciphertext], n: usize) -> Vec<Ciphertext> {
        let num_blocks = blocks.len();
        let mut bits = Vec::with_capacity(n);
        let jobs = iproduct!(0..num_blocks, 0..self.bits_per_block)
            .take(n)
            .collect::<Vec<_>>();
        jobs.into_par_iter()
            .map(|(block_index, bit_index)| {
                let block = &blocks[block_index];
                let lut = &self.bit_extract_luts[bit_index];
                self.server_key.key.apply_lookup_table(block, lut)
            })
            .collect_into_vec(&mut bits);

        bits
    }
}
