use crate::shortint::{Ciphertext, ServerKey};
use crate::transciphering::ciphers::aes::AesIv;
use crate::transciphering::{FheKeyStream, StreamCipherKind, Transcipherer};
use rayon::prelude::*;

use super::encrypt::encrypt_block;
use super::key::AesFheRoundKeys;

/// Server-side AES-128 in CTR mode, driven through the [`Transcipherer`] trait.
pub struct AesFheState {
    key: AesFheRoundKeys,
    iv: AesIv,
    counter: u64,
}

impl AesFheState {
    pub fn new(key: AesFheRoundKeys, iv: impl Into<AesIv>) -> Self {
        Self {
            key,
            iv: iv.into(),
            counter: 0,
        }
    }

    /// Compute `AES_k(iv + block_index)` as 128 FHE bits. The counter is public,
    /// so it is injected via `create_trivial` (no PBS).
    fn keystream_block(&self, sks: &ServerKey, block_index: u128) -> [Ciphertext; 128] {
        let counter_value = self.iv.to_u128().wrapping_add(block_index);
        encrypt_block(sks, counter_value, &self.key)
    }
}

impl Transcipherer for AesFheState {
    fn kind(&self) -> StreamCipherKind {
        StreamCipherKind::Aes
    }

    fn next_keystream_bits(&mut self, sks: &ServerKey, n_bits: usize) -> FheKeyStream {
        //  counter
        //     │
        //     ▼
        //  ┌────────────────┬────────────────┬────────────────┐
        //  │  start_block   │ start_block+1  │ start_block+2  │  ← 128 bits each
        //  └────────────────┴────────────────┴────────────────┘
        //   ▓▓▓▓▓░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▓▓▓▓▓▓
        //   └─┬─┘└────────────────  n_bits  ─────────────┘└─┬──┘
        //  skip_head           kept & returned          tail dropped
        //  (dropped)
        //
        //  Both boundary blocks are computed in full but only partially used:
        //  a non-block-aligned call wastes the head + tail. The byte-aligned
        //  transciphering path requests the whole message in one call to avoid
        //  this.
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
