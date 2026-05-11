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
//!     KreyviumFheStream, KreyviumPlainKey, KreyviumPlainStream,
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
//! let mut sym = KreyviumPlainStream::new(key_bits, iv_bits);
//! let sym_cipher = sym.encrypt(&input_bytes);
//!
//! // Client → server: ship the FHE-encrypted Kreyvium key (one-time setup).
//! let enc_key = KreyviumPlainKey::from(key_bits).encrypt(&client_key);
//!
//! // Server: warm up the FHE-side Kreyvium stream and trans-cipher.
//! let mut fhe_stream = KreyviumFheStream::new(enc_key, iv_bits, &server_key);
//! let blocks = fhe_stream.trans_cipher(&server_key, &sym_cipher).unwrap();
//!
//! // Client: decrypt to recover `input`.
//! let recovered: u64 = blocks
//!     .iter()
//!     .enumerate()
//!     .map(|(i, b)| client_key.decrypt(b) << (2 * i))
//!     .sum();
//! assert_eq!(recovered, input);
//! ```

pub mod backward_compatibility;
pub mod ciphers;

use rayon::prelude::*;
use tfhe_versionable::Versionize;

use crate::conformance::ParameterSetConformant;
use crate::core_crypto::commons::utils::ZipChecked;
use crate::shortint::{Ciphertext, ServerKey};
use crate::transciphering::backward_compatibility::{
    StreamCipherKindVersions, StreamCiphertextVersions,
};
use crate::transciphering::ciphers::kreyvium::KreyviumFheStream;

/// Identifier for a concrete stream-cipher family.
///
/// Carried by [`StreamCiphertext`] so a [`Transcipherer`] can refuse inputs
/// that were not produced by the matching [`StreamCipher`].
///
/// The [`Self::Dynamic`] variant can be used for out-of-tree experimental ciphers
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, Versionize,
)]
#[versionize(StreamCipherKindVersions)]
pub enum StreamCipherKind {
    Kreyvium,
    Dynamic,
}

/// Output of [`StreamCipher::encrypt`] / [`StreamCipher::encrypt_bits`]: a
/// stream-cipher ciphertext that the client ships to the server for
/// trans-ciphering.
///
/// This is a "ciphertext" from the stream-cipher perspective; from the FHE
/// perspective these bytes are plaintext (they are in the clear until
/// `trans_cipher` lifts them under FHE).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(StreamCiphertextVersions)]
pub struct StreamCiphertext {
    kind: StreamCipherKind,
    /// Keystream bit position at which this ciphertext was encrypted.
    counter: u64,
    n_bits: usize,
    bytes: Vec<u8>,
}

impl StreamCiphertext {
    pub fn kind(&self) -> StreamCipherKind {
        self.kind
    }

    pub fn counter(&self) -> u64 {
        self.counter
    }

    pub fn n_bits(&self) -> usize {
        self.n_bits
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Parameters used to check [`StreamCiphertext`] conformance: the expected
/// cipher family and bit length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamCiphertextConformanceParams {
    pub kind: StreamCipherKind,
    pub n_bits: usize,
}

impl ParameterSetConformant for StreamCiphertext {
    type ParameterSet = StreamCiphertextConformanceParams;

    fn is_conformant(&self, params: &Self::ParameterSet) -> bool {
        self.kind == params.kind
            && self.n_bits == params.n_bits
            && self.bytes.len() == self.n_bits.div_ceil(8)
    }
}

/// Errors raised by [`StreamCipher`] / [`Transcipherer`] operations that
/// consume a [`StreamCiphertext`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TranscipherError {
    /// The [`StreamCiphertext`] was produced by a cipher different from the
    /// one consuming it.
    KindMismatch {
        expected: StreamCipherKind,
        got: StreamCipherKind,
    },
    /// The consumer's current keystream counter does not match the
    /// [`StreamCiphertext`]'s recorded counter. When the ciphertext is
    /// ahead, the caller can call [`StreamCipher::skip`] / [`Transcipherer::skip`]
    /// to align and retry.
    CounterMismatch { expected: u64, got: u64 },
}

impl std::fmt::Display for TranscipherError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KindMismatch { expected, got } => write!(
                f,
                "stream ciphertext cipher kind mismatch: expected {expected:?}, got {got:?}"
            ),
            Self::CounterMismatch { expected, got } => {
                if got > expected {
                    write!(
                        f,
                        "stream ciphertext counter mismatch: session at {expected}, \
                         ciphertext at {got}. Call `skip({})` to align",
                        got - expected,
                    )
                } else {
                    write!(
                        f,
                        "stream ciphertext counter mismatch: session at {expected}, \
                         ciphertext at {got}.",
                    )
                }
            }
        }
    }
}

impl std::error::Error for TranscipherError {}

/// Client-side: a stateful symmetric-cipher session, no FHE.
pub trait StreamCipher {
    /// Cipher family this session belongs to. Embedded into every
    /// [`StreamCiphertext`] produced by [`Self::encrypt`] /
    /// [`Self::encrypt_bits`].
    fn kind(&self) -> StreamCipherKind;

    /// Produce the next `n_bits` of keystream and advance the internal counter.
    /// Bits are packed LSB-first into bytes; in the standard byte-aligned
    /// transciphering use case `n_bits` is a multiple of 8.
    fn next_keystream_bits(&mut self, n_bits: usize) -> Vec<u8>;

    /// XOR the first `n_bits` of `input` with `n_bits` keystream bits.
    ///
    /// `input.len()` must equal `n_bits.div_ceil(8)`. When `n_bits` is not a
    /// multiple of 8, the trailing bits of the last input byte are passed
    /// through unchanged (the keystream has zero bits in that range, so the
    /// XOR is a no-op there).
    fn encrypt_bits(&mut self, input: &[u8], n_bits: usize) -> StreamCiphertext {
        assert_eq!(
            input.len(),
            n_bits.div_ceil(8),
            "input must have exactly ceil(n_bits / 8) = {} bytes (got {})",
            n_bits.div_ceil(8),
            input.len()
        );

        let counter = self.current_counter();
        let mask = self.next_keystream_bits(n_bits);
        let bytes: Vec<u8> = input.iter().zip_checked(mask).map(|(i, m)| i ^ m).collect();

        StreamCiphertext {
            kind: self.kind(),
            counter,
            n_bits,
            bytes,
        }
    }

    /// XOR `input` with the next `8 * input.len()` keystream bits. Advances
    /// the counter.
    fn encrypt(&mut self, input: &[u8]) -> StreamCiphertext {
        self.encrypt_bits(input, 8 * input.len())
    }

    /// Stream-cipher decryption: XOR `encrypted` with a fresh chunk of
    /// keystream. Returns `encrypted.n_bits().div_ceil(8)` bytes.
    ///
    /// Errors with [`TranscipherError::KindMismatch`] when `encrypted` was
    /// produced by a different cipher family.
    fn decrypt(&mut self, encrypted: &StreamCiphertext) -> Result<Vec<u8>, TranscipherError> {
        if encrypted.kind != self.kind() {
            return Err(TranscipherError::KindMismatch {
                expected: self.kind(),
                got: encrypted.kind,
            });
        }
        if encrypted.counter != self.current_counter() {
            return Err(TranscipherError::CounterMismatch {
                expected: self.current_counter(),
                got: encrypted.counter,
            });
        }

        let mask = self.next_keystream_bits(encrypted.n_bits);
        Ok(encrypted
            .bytes
            .iter()
            .zip_checked(mask)
            .map(|(i, m)| i ^ m)
            .collect())
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
    /// Cipher family this session belongs to. Must match the
    /// [`StreamCiphertext::kind`] of any input passed to [`Self::trans_cipher`].
    fn kind(&self) -> StreamCipherKind;

    /// Produce the next `n_bits` of FHE-encrypted keystream and advance the
    /// internal counter. One `shortint::Ciphertext` per bit, each a clean
    /// single-bit ciphertext (degree 1, value in {0, 1}).
    fn next_keystream_bits(&mut self, sks: &ServerKey, n_bits: usize) -> FheKeyStream;

    /// Trans-cipher `input` against `input.n_bits()` bits of keystream from
    /// this session, advancing the internal counter.
    ///
    /// Errors with [`TranscipherError::KindMismatch`] when `input` was
    /// produced by a different cipher family.
    fn trans_cipher(
        &mut self,
        sks: &ServerKey,
        input: &StreamCiphertext,
    ) -> Result<Vec<Ciphertext>, TranscipherError> {
        if input.kind != self.kind() {
            return Err(TranscipherError::KindMismatch {
                expected: self.kind(),
                got: input.kind,
            });
        }
        if input.counter != self.current_counter() {
            return Err(TranscipherError::CounterMismatch {
                expected: self.current_counter(),
                got: input.counter,
            });
        }

        let keystream = self.next_keystream_bits(sks, input.n_bits);
        Ok(apply_keystream(sks, &keystream, input))
    }

    /// Advance the keystream position by `n_bits` without emitting them.
    fn skip(&mut self, sks: &ServerKey, n_bits: usize);

    fn current_counter(&self) -> u64;
}

/// Owning, runtime-dispatched [`Transcipherer`]. Lets higher layers keep a
/// single concrete type that can hold any in-tree cipher state, plus
/// arbitrary out-of-tree implementors via [`Self::Dynamic`].
///
/// [`Self::Dynamic`] mirrors [`StreamCipherKind::Dynamic`]: the trait-object
/// variant reports `StreamCipherKind::Dynamic` from `kind()`, so the default
/// [`Transcipherer::trans_cipher`] kind-check still enforces same-family
/// pairing.
#[allow(clippy::large_enum_variant)] // Lint complains because of the Dynamic variant, but it should not be
pub enum TranscipherSession {
    Kreyvium(KreyviumFheStream),
    Dynamic(Box<dyn Transcipherer + Send + Sync>),
}

impl Transcipherer for TranscipherSession {
    fn kind(&self) -> StreamCipherKind {
        match self {
            Self::Kreyvium(t) => t.kind(),
            Self::Dynamic(t) => t.kind(),
        }
    }

    fn next_keystream_bits(&mut self, sks: &ServerKey, n_bits: usize) -> FheKeyStream {
        match self {
            Self::Kreyvium(t) => t.next_keystream_bits(sks, n_bits),
            Self::Dynamic(t) => t.next_keystream_bits(sks, n_bits),
        }
    }

    fn trans_cipher(
        &mut self,
        sks: &ServerKey,
        input: &StreamCiphertext,
    ) -> Result<Vec<Ciphertext>, TranscipherError> {
        match self {
            Self::Kreyvium(t) => t.trans_cipher(sks, input),
            Self::Dynamic(t) => t.trans_cipher(sks, input),
        }
    }

    fn skip(&mut self, sks: &ServerKey, n_bits: usize) {
        match self {
            Self::Kreyvium(t) => t.skip(sks, n_bits),
            Self::Dynamic(t) => t.skip(sks, n_bits),
        }
    }

    fn current_counter(&self) -> u64 {
        match self {
            Self::Kreyvium(t) => t.current_counter(),
            Self::Dynamic(t) => t.current_counter(),
        }
    }
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

/// Xor an FHE keystream with a clear [`StreamCiphertext`].
///
/// Validates that `input` was produced by a cipher in the same family as the
/// `keystream` (which the caller asserts implicitly by pairing them). The
/// number of keystream bits consumed is `input.n_bits()`.
pub fn apply_keystream(
    sks: &ServerKey,
    keystream: &FheKeyStream,
    input: &StreamCiphertext,
) -> Vec<Ciphertext> {
    assert_eq!(
        keystream.0.len(),
        input.n_bits,
        "keystream length ({}) must equal input.n_bits ({})",
        keystream.0.len(),
        input.n_bits,
    );
    if sks.message_modulus.0 == 4 && sks.carry_modulus.0 == 4 {
        apply_keystream_2_2(sks, &keystream.0, &input.bytes)
    } else {
        apply_keystream_naive(sks, &keystream.0, &input.bytes)
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
