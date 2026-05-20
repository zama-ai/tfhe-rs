use std::array::from_fn;

use crate::shortint::{Ciphertext, ServerKey};
use crate::transciphering::{FheKeyStream, StreamCipherKind, Transcipherer};
use rayon::prelude::*;

use super::encrypt::encrypt_block;
use super::key::AesFheKey;

/// Server-side AES-128 in CTR mode.
///
/// Holds the FHE-encrypted round keys, the clear IV, and a clear bit counter
/// tracking how many keystream bits have been emitted so far.
///
/// Can be driven directly through the [`Transcipherer`] trait, or held by the
/// owning [`crate::transciphering::TranscipherSession::Aes`] arm for
/// runtime-dispatched use.
pub struct AesFheStream {
    key: AesFheKey,
    iv: u128,
    counter: u64,
}

impl AesFheStream {
    pub fn new(key: AesFheKey, iv: u128) -> Self {
        Self {
            key,
            iv,
            counter: 0,
        }
    }

    /// Compute `AES_k(iv + block_index)` as 128 FHE bits.
    ///
    /// The counter is public, so it is injected via `create_trivial` (no PBS,
    /// no noise). Output layout follows the [`Transcipherer`] convention:
    /// bytes in NIST order, LSB-first within each byte.
    fn keystream_block(&self, sks: &ServerKey, block_index: u128) -> [Ciphertext; 128] {
        let counter_value = self.iv.wrapping_add(block_index);
        let bytes = counter_value.to_be_bytes();
        let mut state: [Ciphertext; 128] =
            from_fn(|i| sks.create_trivial(((bytes[i / 8] >> (i % 8)) & 1) as u64));
        encrypt_block(sks, &mut state, &self.key);
        state
    }
}

impl Transcipherer for AesFheStream {
    fn kind(&self) -> StreamCipherKind {
        StreamCipherKind::Aes
    }

    fn next_keystream_bits(&mut self, sks: &ServerKey, n_bits: usize) -> FheKeyStream {
        // `skip_head` is the offset into the first block when the counter is
        // not block-aligned. NOTE: each call recomputes whole CTR blocks from
        // `start_block`, so a sequence of non-block-aligned calls re-evaluates
        // the partially consumed boundary block in full (one complete FHE AES
        // block, i.e. thousands of PBS). The standard byte-aligned
        // transciphering path requests a whole message in one call and avoids
        // this; non-aligned sequential use would benefit from caching the tail
        // block.
        let skip_head = (self.counter % 128) as usize;
        let start_block = self.counter / 128;
        let n_blocks = (skip_head + n_bits).div_ceil(128);

        let blocks: Vec<[Ciphertext; 128]> = (0..n_blocks as u64)
            .into_par_iter()
            .map(|i| self.keystream_block(sks, (start_block + i) as u128))
            .collect();

        self.counter = self
            .counter
            .checked_add(n_bits as u64)
            .expect("AesFheStream: keystream bit counter overflowed u64");

        let flat: Vec<Ciphertext> = blocks
            .into_iter()
            .flatten()
            .skip(skip_head)
            .take(n_bits)
            .collect();

        FheKeyStream::from_raw_parts(flat)
    }

    fn seek(&mut self, _sks: &ServerKey, target_counter: u64) {
        self.counter = target_counter;
    }

    fn current_counter(&self) -> u64 {
        self.counter
    }
}
