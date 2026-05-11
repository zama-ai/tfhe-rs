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
//!     KreyviumFheKey, KreyviumFheStream, KreyviumPlainStream,
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
//! let enc_key: KreyviumFheKey =
//!     key_bits.map(|b| client_key.encrypt(b as u64)).into();
//!
//! // Server: warm up the FHE-side Kreyvium stream and trans-cipher.
//! let mut fhe_stream = KreyviumFheStream::new(enc_key, iv_bits, &server_key);
//! let blocks = fhe_stream.trans_cipher(&server_key, &sym_cipher);
//!
//! // Client: decrypt to recover `input`.
//! let recovered: u64 = blocks
//!     .iter()
//!     .enumerate()
//!     .map(|(i, b)| client_key.decrypt(b) << (2 * i))
//!     .sum();
//! assert_eq!(recovered, input);
//! ```

pub mod ciphers;

use rayon::prelude::*;

use crate::core_crypto::commons::utils::ZipChecked;
use crate::shortint::{Ciphertext, ServerKey};

/// Client-side: a stateful symmetric-cipher session, no FHE.
pub trait StreamCipher {
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
    /// Produce the next `n_bits` of FHE-encrypted keystream and advance the
    /// internal counter. One `shortint::Ciphertext` per bit, each a clean
    /// single-bit ciphertext (degree 1, value in {0, 1}).
    fn next_keystream_bits(&mut self, sks: &ServerKey, n_bits: usize) -> FheKeyStream;

    /// Trans-cipher `input_stream` against `8 * input_stream.len()` bits of
    /// keystream from this session, advancing the internal counter.
    fn trans_cipher(&mut self, sks: &ServerKey, input_stream: &[u8]) -> Vec<Ciphertext> {
        let keystream = self.next_keystream_bits(sks, 8 * input_stream.len());
        apply_keystream(sks, &keystream, input_stream)
    }

    /// Trans-cipher `input_stream` against `num_bits` bits of
    /// keystream from this session, advancing the internal counter.
    ///
    /// `input_stream.len()` must equal `num_bits.div_ceil(8)`. When
    /// `num_bits` is not a multiple of 8, the trailing bits of the last
    /// input byte are ignored.
    fn trans_cipher_with_bits(
        &mut self,
        sks: &ServerKey,
        input_stream: &[u8],
        num_bits: usize,
    ) -> Vec<Ciphertext> {
        assert_eq!(
            input_stream.len(),
            num_bits.div_ceil(8),
            "input must have exactly ceil(keystream_len / 8) = {} bytes (got {})",
            num_bits.div_ceil(8),
            input_stream.len()
        );

        let keystream = self.next_keystream_bits(sks, num_bits);
        apply_keystream(sks, &keystream, input_stream)
    }

    /// Advance the keystream position by `n_bits` without emitting them.
    fn skip(&mut self, sks: &ServerKey, n_bits: usize);

    fn current_counter(&self) -> u64;
}

/// An FHE encrypted keystream that can be xored with an input encrypted with a [`StreamCipher`].
pub struct FheKeyStream(Vec<Ciphertext>);

impl FheKeyStream {
    pub fn from_raw_parts(bits: Vec<Ciphertext>) -> Self {
        Self(bits)
    }

    pub fn into_raw_parts(self) -> Vec<Ciphertext> {
        self.0
    }

    pub fn iter(&self) -> std::slice::Iter<'_, Ciphertext> {
        self.0.iter()
    }
}

impl<'a> IntoIterator for &'a FheKeyStream {
    type Item = &'a Ciphertext;
    type IntoIter = std::slice::Iter<'a, Ciphertext>;
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// LSB-first bit `i` of `bytes` (i.e. `bytes[i / 8] >> (i % 8) & 1`).
fn bit_at(bytes: &[u8], i: usize) -> u8 {
    (bytes[i / 8] >> (i % 8)) & 1
}

/// Xor an FHE keystream with a clear symmetric ciphertext
pub fn apply_keystream(
    sks: &ServerKey,
    keystream: &FheKeyStream,
    input_stream: &[u8],
) -> Vec<Ciphertext> {
    if sks.message_modulus.0 == 4 && sks.carry_modulus.0 == 4 {
        apply_keystream_2_2(sks, &keystream.0, input_stream)
    } else {
        apply_keystream_naive(sks, &keystream.0, input_stream)
    }
}

/// Xor an FHE keystream with a clear symmetric ciphertext under
/// MESSAGE_2_CARRY_2.
///
/// `keystream` is what [`Transcipherer::next_keystream_bits`] returns: one
/// clean single-bit `Ciphertext` per bit. `input_stream` is the clear
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
fn apply_keystream_2_2(
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
    // Example:
    // keystream (2 lwe 2_2 encoded): 0000a 0000b
    // user input bits (plaintext)  :     x     y
    // output (1 lwe 2_2 encoded)   : 000(b^y)(a^x)
    let pairs_iter = pairs.enumerate().map(|(i, keystream)| {
        let lo_idx = 2 * i;
        let hi_idx = 2 * i + 1;
        let i_lo = bit_at(input_stream, lo_idx);
        let i_hi = bit_at(input_stream, hi_idx);
        let s = (i_lo | (i_hi << 1)) as usize;
        sks.unchecked_apply_lookup_table_bivariate(&keystream[0], &keystream[1], &luts[s])
    });

    // Odd keystream length: one PBS for the trailing bit
    let trailing_iter = trailing.par_iter().map(|last_keystream| {
        let last_idx = keystream.len() - 1;
        let s = bit_at(input_stream, last_idx) as u64;
        let trailing_lut = sks.generate_lookup_table(move |t| (t & 1) ^ s);
        let mut last = last_keystream.clone();
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
fn apply_keystream_naive(
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
            let s = bit_at(input_stream, i) as usize;
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
