use tfhe_csprng::generators::aes_ctr::{AesBlockCipher, AesKey};
use tfhe_csprng::generators::default::DefaultBlockCipher;

use crate::transciphering::{StreamCipher, StreamCipherKind};

/// Client-side AES-128 in CTR mode, in clear. Mirrors
/// [`super::fhe::AesFheStream`] with identical IV and counter semantics.
pub struct AesPlainStream {
    cipher: DefaultBlockCipher,
    iv: u128,
    counter: u64,
}

impl AesPlainStream {
    pub fn new(key: u128, iv: u128) -> Self {
        Self {
            cipher: DefaultBlockCipher::new(AesKey(u128::from_ne_bytes(key.to_be_bytes()))),
            iv,
            counter: 0,
        }
    }
}

impl StreamCipher for AesPlainStream {
    fn kind(&self) -> StreamCipherKind {
        StreamCipherKind::Aes
    }

    fn next_keystream_bits(&mut self, n_bits: usize) -> Vec<u8> {
        let skip_head = (self.counter % 128) as usize;
        let start_block = self.counter / 128;
        let n_blocks = (skip_head + n_bits).div_ceil(128);

        // Each `generate_next` output is 16 bytes in NIST order, which read
        // LSB-first via `bit_at` directly matches the trait convention.
        let mut keystream_bytes: Vec<u8> = Vec::with_capacity(n_blocks * 16);
        for i in 0..n_blocks as u128 {
            let counter_value = self.iv.wrapping_add(start_block as u128 + i);
            let counter_csprng = u128::from_ne_bytes(counter_value.to_be_bytes());
            let block = self.cipher.generate_next(counter_csprng);
            keystream_bytes.extend_from_slice(&block);
        }

        self.counter = self
            .counter
            .checked_add(n_bits as u64)
            .expect("AesPlainStream: keystream bit counter overflowed u64");

        let mut result = vec![0u8; n_bits.div_ceil(8)];
        for out_idx in 0..n_bits {
            let src_idx = skip_head + out_idx;
            let bit = (keystream_bytes[src_idx / 8] >> (src_idx % 8)) & 1;
            result[out_idx / 8] |= bit << (out_idx % 8);
        }
        result
    }

    fn seek(&mut self, target_counter: u64) {
        self.counter = target_counter;
    }

    fn current_counter(&self) -> u64 {
        self.counter
    }
}
