//! Server-side homomorphic conversion of a symmetric-cipher ciphertext into
//! an FHE ciphertext.
//!
//! The client encrypts data with a lightweight symmetric stream cipher, using
//! a key it generates locally, and ships an FHE encryption of that key to the
//! server once. The server, holding only the encrypted key, applies a
//! trans-cipher round that turns each symmetric ciphertext into an FHE
//! ciphertext of the same plaintext.
//!
//! End-to-end example using Kreyvium:
//!
//! ```
//! use rand::Rng;
//! use tfhe::shortint::prelude::*;
//! use tfhe::shortint::parameters::current_params::V1_6_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
//! use tfhe::transciphering::{StreamCipher, Transcipherer};
//! use tfhe::transciphering::ciphers::kreyvium::{
//!     KreyviumEncryptedKey, KreyviumFheStream, KreyviumPlainStream,
//! };
//!
//! let (client_key, server_key) =
//!     gen_keys(V1_6_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128);
//!
//! // Client: pick a symmetric key + IV and encrypt a u64 with plain Kreyvium.
//! let mut rng = rand::thread_rng();
//! let key_bits: [bool; 128] = std::array::from_fn(|_| rng.gen());
//! let iv_bits: [bool; 128] = std::array::from_fn(|_| rng.gen());
//! let input: u64 = 0xDEADBEEFCAFEBABE;
//! let input_bytes = input.to_le_bytes();
//!
//! let mut sym = KreyviumPlainStream::new(key_bits.into(), iv_bits);
//! let sym_cipher = sym.encrypt(&input_bytes);
//!
//! // Client → server: ship the FHE-encrypted Kreyvium key (one-time setup).
//! let enc_key: KreyviumEncryptedKey =
//!     key_bits.map(|b| client_key.encrypt(b as u64)).into();
//! let iv_u64 = iv_bits.map(|b| b as u64);
//!
//! // Server: warm up the FHE-side Kreyvium stream and trans-cipher.
//! let mut engine = KreyviumFheStream::new(enc_key, iv_u64, &server_key);
//! let blocks = engine.trans_cipher(&server_key, &sym_cipher);
//!
//! // Client: decrypt to recover `input`.
//! let recovered: u64 = blocks
//!     .iter()
//!     .enumerate()
//!     .map(|(i, b)| (client_key.decrypt(b) & 0b11) << (2 * i))
//!     .sum();
//! assert_eq!(recovered, input);
//! ```

pub mod backward_compatibility;
pub mod ciphers;

use backward_compatibility::TranscipheringCipherKindVersions;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

use crate::core_crypto::commons::utils::ZipChecked;
use crate::shortint::{Ciphertext, ServerKey};

/// Client-side: a stateful symmetric-cipher session, no FHE.
pub trait StreamCipher {
    fn kind(&self) -> TranscipheringCipherKind;

    /// Produce the next `n_bits` of keystream and advance the internal counter.
    /// Bits are packed LSB-first into bytes; in the standard byte-aligned
    /// transciphering use case `n_bits` is a multiple of 8.
    fn next_keystream_bits(&mut self, n_bits: usize) -> Vec<u8>;

    /// XOR `input` with the next `8 * input.len()` keystream bits. Advances
    /// the counter.
    fn encrypt(&mut self, input: &[u8]) -> Vec<u8> {
        let mask = self.next_keystream_bits(8 * input.len());
        input.iter().zip_checked(mask).map(|(i, m)| i ^ m).collect()
    }

    /// Stream-cipher decryption: identical to [`Self::encrypt`].
    fn decrypt(&mut self, encrypted: &[u8]) -> Vec<u8> {
        self.encrypt(encrypted)
    }

    /// Advance the keystream position by `n_bits` without emitting them.
    /// Complexity depends on the cipher.
    fn skip(&mut self, n_bits: usize);

    /// Current keystream bit position.
    fn current_counter(&self) -> u64;
}

/// Server-side: a stateful FHE-side session that mirrors a StreamCipher.
/// Same shape as `StreamCipher`, FHE-evaluated.
pub trait Transcipherer {
    fn kind(&self) -> TranscipheringCipherKind;

    /// Produce the next `n_bits` of FHE-encrypted keystream and advance the
    /// internal counter. One `shortint::Ciphertext` per bit.
    ///
    /// Each returned `Ciphertext` carries the keystream bit in its **low
    /// bit only**. Under params with `message_modulus > 2` (e.g.
    /// MESSAGE_2_CARRY_2) the higher message bits may hold garbage that
    /// implementations are free to leave behind to avoid an extra PBS per
    /// round. Any consumer that composes the keystream with another
    /// ciphertext must reduce to message_modulus, typically by folding the cleanup
    /// into the trans-cipher XOR PBS, at no extra cost.
    fn next_keystream_bits(&mut self, sks: &ServerKey, n_bits: usize) -> Vec<Ciphertext>;

    /// Trans-cipher `input_stream` against `8 * input_stream.len()` bits of
    /// keystream from this session, advancing the internal counter.
    fn trans_cipher(&mut self, sks: &ServerKey, input_stream: &[u8]) -> Vec<Ciphertext> {
        let keystream = self.next_keystream_bits(sks, 8 * input_stream.len());
        if sks.message_modulus.0 == 4 && sks.carry_modulus.0 == 4 {
            trans_cipher_2_2(sks, &keystream, input_stream)
        } else {
            trans_cipher_naive(sks, &keystream, input_stream)
        }
    }

    /// Advance the keystream position by `n_bits` without emitting them.
    fn skip(&mut self, sks: &ServerKey, n_bits: usize);

    fn current_counter(&self) -> u64;
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Versionize)]
#[versionize(TranscipheringCipherKindVersions)]
pub enum TranscipheringCipherKind {
    Kreyvium,
    Dynamic,
}

/// Trans-cipher an FHE keystream against a clear symmetric ciphertext under
/// MESSAGE_2_CARRY_2.
///
/// `keystream` is what [`Transcipherer::next_keystream_bits`] returns: one
/// `Ciphertext` per bit, with the real bit in the **low** position and
/// garbage allowed in the high message bit. `sym_cipher` is the clear
/// symmetric-cipher output from the user.
///
/// Cost: one 0.5 PBS per bit.
/// Xoring and packing a pair of 2 bits of keystream + 2 bits of input is done in a
/// single PBS.
///
/// `input_stream.len()` must equal `keystream.len().div_ceil(8)`: the
/// minimum number of bytes that contain `keystream.len()` bits. When
/// `keystream.len()` is not a multiple of 8, the trailing bits of the last
/// input byte are ignored.
fn trans_cipher_2_2(
    sks: &ServerKey,
    keystream: &[Ciphertext],
    input_stream: &[u8],
) -> Vec<Ciphertext> {
    assert_eq!(
        input_stream.len(),
        keystream.len().div_ceil(8),
        "input must have exactly ceil(keystream_len / 8) = {} bytes (got {})",
        keystream.len().div_ceil(8),
        input_stream.len()
    );

    // For each possible 2-bit clear input value `i` (i_hi | i_lo), build a LUT
    // that performs keystream xor and packing in a single pbs
    let luts: [_; 4] = std::array::from_fn(|i| {
        let i_lo = (i & 1) as u64;
        let i_hi = ((i >> 1) & 1) as u64;
        sks.generate_lookup_table_bivariate(move |k0, k1| {
            ((k0 & 1) ^ i_lo) | (((k1 & 1) ^ i_hi) << 1)
        })
    });

    let pairs = keystream.par_chunks_exact(2);
    // 0 or 1 trailing keystream ct when `keystream.len()` is odd.
    let trailing = pairs.remainder();

    // Pair `i` consumes input bits 2i and 2i+1 (LSB-first across bytes), and
    // produces one 2-bit XOR'd ciphertext via a single bivariate PBS.
    let pairs_iter = pairs.enumerate().map(|(i, ks)| {
        let lo_idx = 2 * i;
        let hi_idx = 2 * i + 1;
        let i_lo = (input_stream[lo_idx / 8] >> (lo_idx % 8)) & 1;
        let i_hi = (input_stream[hi_idx / 8] >> (hi_idx % 8)) & 1;
        let s = (i_lo | (i_hi << 1)) as usize;
        sks.unchecked_apply_lookup_table_bivariate(&ks[0], &ks[1], &luts[s])
    });

    // Odd keystream length: one PBS for the trailing bit
    let trailing_iter = trailing.par_iter().map(|last_ks| {
        let last_idx = keystream.len() - 1;
        let s = ((input_stream[last_idx / 8] >> (last_idx % 8)) & 1) as u64;
        let trailing_lut = sks.generate_lookup_table(move |t| (t & 1) ^ s);
        let mut last = last_ks.clone();
        sks.apply_lookup_table_assign(&mut last, &trailing_lut);
        last
    });

    pairs_iter.chain(trailing_iter).collect()
}

/// Generic param-agnostic trans-cipher, usable as a fallback for any
/// param set.
///
/// Cost: two PBS per output bit.
/// One for the xor, followed by a per-block linear combination that packs `m`
/// bits into one output ciphertext, followed by a second PBS to restore the noise.
///
/// `input_stream.len()` must equal `keystream.len().div_ceil(8)`: i.e. the
/// minimum number of bytes that contain `keystream.len()` bits. When
/// `keystream.len()` is not a multiple of 8, the trailing bits of the last
/// input byte are ignored.
fn trans_cipher_naive(
    sks: &ServerKey,
    keystream: &[Ciphertext],
    input_stream: &[u8],
) -> Vec<Ciphertext> {
    assert_eq!(
        input_stream.len(),
        keystream.len().div_ceil(8),
        "input must have exactly ceil(keystream_len / 8) = {} bytes (got {})",
        keystream.len().div_ceil(8),
        input_stream.len()
    );

    let m = sks.message_modulus.0.ilog2() as usize;

    // Per-bit XOR LUT, indexed by the clear sym bit
    let luts: [_; 2] =
        std::array::from_fn(|i| sks.generate_lookup_table(move |t| (t & 1) ^ (i as u64)));

    // One PBS per output bit, in parallel: cleans the keystream low bit and
    // XORs the clear input bit (LSB-first across bytes). Each result is a 1-bit
    // ciphertext.
    let cleaned: Vec<Ciphertext> = keystream
        .par_iter()
        .enumerate()
        .map(|(i, k)| {
            let s = ((input_stream[i / 8] >> (i % 8)) & 1) as usize;
            let mut c = k.clone();
            sks.apply_lookup_table_assign(&mut c, &luts[s]);
            c
        })
        .collect();

    // Pack up to m cleaned bits per output ciphertext via linear combination,
    // in parallel. The final chunk may be partial when `keystream.len()` is
    // not a multiple of `m`. Then a final pbs is done to restore the noise
    // to a nominal level when the linear combination grew it.
    cleaned
        .par_chunks(m)
        .map(|chunk| {
            let mut out = chunk[0].clone();
            for (j, c) in chunk.iter().enumerate().skip(1) {
                let shifted = sks.unchecked_scalar_mul(c, 1u8 << j);
                sks.unchecked_add_assign(&mut out, &shifted);
            }
            if chunk.len() >= 2 {
                sks.message_extract_assign(&mut out);
            }
            out
        })
        .collect()
}
