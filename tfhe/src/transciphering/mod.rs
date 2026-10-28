//! Server-side homomorphic conversion of a symmetric-cipher ciphertext into
//! an FHE ciphertext.
//!
//! It is a way for a client to provide inputs to the server without having to run the FHE
//! encryption, resulting in smaller inputs and removing the need for a zk proof of encryption.
//! The client encrypts data with a lightweight symmetric stream cipher, using
//! a key it generates locally, and ships an FHE encryption of that key to the
//! server once. The server, holding only the encrypted key, applies a
//! transcipher round that turns each symmetric ciphertext into an FHE
//! ciphertext of the same plaintext.
//!
//! End-to-end example using Kreyvium:
//!
//! ```
//! use rand::Rng;
//! use tfhe::shortint::prelude::*;
//! use tfhe::shortint::parameters::current_params::V1_9_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
//! use tfhe::transciphering::{
//!     KreyviumFheState, KreyviumPlainKey, KreyviumPlainState, StreamCipher, Transcipherer,
//!     TranscipheringOutputLayout,
//! };
//!
//! let (client_key, server_key) =
//!     gen_keys(V1_9_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128);
//!
//! // Client: pick a symmetric key + IV and encrypt a u64 with plain Kreyvium.
//! let mut rng = rand::thread_rng();
//! let key_bits: [bool; 128] = std::array::from_fn(|_| rng.gen());
//! let iv_bits: [bool; 128] = std::array::from_fn(|_| rng.gen());
//! let input: u64 = 0xDEADBEEFCAFEBABE;
//! let input_bytes = input.to_le_bytes();
//!
//! let mut sym = KreyviumPlainState::new(key_bits, iv_bits);
//! let sym_cipher = sym.encrypt(&input_bytes).unwrap();
//!
//! // Client → server: ship the FHE-encrypted Kreyvium key (one-time setup).
//! let enc_key = KreyviumPlainKey::from(key_bits).encrypt(&client_key);
//!
//! // Server: warm up the FHE-side Kreyvium stream and transcipher.
//! let mut fhe_stream = KreyviumFheState::new(enc_key, iv_bits, &server_key);
//! let layout = TranscipheringOutputLayout::radix(sym_cipher.n_bits(), server_key.message_modulus);
//! let blocks = fhe_stream
//!     .transcipher(&server_key, &sym_cipher, &layout)
//!     .unwrap();
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
mod keys;
mod keystream_application;

use std::num::NonZeroU8;

use backward_compatibility::KeyStreamLayoutVersions;
use itertools::Itertools;
pub use keys::{
    CompressedTranscipheringServerKey, ExpandedTranscipheringServerKey, TranscipheringPrivateKey,
    TranscipheringServerKey,
};

pub use keystream_application::apply_keystream;

pub use ciphers::aes::{
    AesFheKey, AesFheRoundKeys, AesFheState, AesIv, AesPlainKey, AesPlainState,
    SerializableAesFheKey,
};
pub use ciphers::kreyvium::{
    KreyviumFheKey, KreyviumFheState, KreyviumIV, KreyviumPlainKey, KreyviumPlainState,
    SerializableKreyviumFheKey,
};
pub use ciphers::one_time_pad::{
    OneTimePadFheSecretMask, OneTimePadFheState, OneTimePadPlainSecretMask,
    OneTimePadPlainSecretMaskConformanceParams, OneTimePadPlainState,
};

use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

use crate::conformance::ParameterSetConformant;
use crate::core_crypto::commons::utils::ZipChecked;
use crate::shortint::ciphertext::{Degree, NoiseLevel};
use crate::shortint::{CarryModulus, Ciphertext, MessageModulus, ServerKey};
use crate::transciphering::backward_compatibility::{
    StreamCipherKindVersions, StreamCiphertextVersions,
};

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
    Dynamic,
    Kreyvium,
    Aes,
    OneTimePad,
}

/// Output of [`StreamCipher::encrypt`] / [`StreamCipher::encrypt_bits`]: a
/// stream-cipher ciphertext that the client ships to the server for
/// transciphering.
///
/// This is a "ciphertext" from the stream-cipher perspective; from the FHE
/// perspective these bytes are plaintext (they are in the clear until
/// `transcipher` lifts them under FHE).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(StreamCiphertextVersions)]
pub struct StreamCiphertext {
    kind: StreamCipherKind,
    /// Keystream bit position at which this ciphertext was encrypted.
    encryption_counter: u64,
    n_bits: usize,
    bytes: Vec<u8>,
}

impl StreamCiphertext {
    pub fn kind(&self) -> StreamCipherKind {
        self.kind
    }

    pub fn encryption_counter(&self) -> u64 {
        self.encryption_counter
    }

    pub fn n_bits(&self) -> usize {
        self.n_bits
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Extracts the bits in `range` (LSB-first), with bit `range.start` at position 0.
    ///
    /// The range must be contained in a single byte. Returns `None` if the range is reversed, out
    /// of bounds or spans more than one byte.
    pub fn get_bit_range(&self, range: std::ops::Range<usize>) -> Option<u64> {
        #[allow(clippy::suspicious_operation_groupings, reason = "That's what we want")]
        if range.start > range.end || range.end > self.n_bits {
            return None;
        }

        if range.is_empty() {
            return Some(0);
        }

        let byte_idx = range.start / 8;
        if (range.end - 1) / 8 != byte_idx {
            return None;
        }

        let byte = u64::from(*self.bytes.get(byte_idx)?);
        // range.len() <= 8, so the shift does not overflow
        Some((byte >> (range.start % 8)) & ((1 << range.len()) - 1))
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
        session_kind: StreamCipherKind,
        ciphertext_kind: StreamCipherKind,
    },
    /// The consumer's current keystream counter does not match the
    /// [`StreamCiphertext`]'s recorded counter. The caller can call
    /// [`StreamCipher::seek`] / [`Transcipherer::seek`] with the ciphertext's
    /// counter to align and retry.
    CounterMismatch {
        session_counter: u64,
        ciphertext_counter: u64,
    },
    /// The provided output layout is not correct
    InvalidOutputLayout,
    /// The [`Transcipherer`] failed to produce keystream
    KeystreamProductionError(FheKeyStreamError),
    /// The keystream produced by the [`Transcipherer`] is not valid
    InvalidKeystream,
    /// The input stream ciphertext is invalid, for example the buffer size does not match the
    /// advertised number of bits
    InvalidStreamCiphertext,
}

impl std::fmt::Display for TranscipherError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KindMismatch {
                session_kind,
                ciphertext_kind,
            } => write!(
                f,
                "stream ciphertext cipher kind mismatch: session kind {session_kind:?}, \
                ciphertext kind {ciphertext_kind:?}"
            ),
            Self::CounterMismatch {
                session_counter,
                ciphertext_counter,
            } => {
                write!(
                    f,
                    "stream ciphertext counter mismatch: session at {session_counter}, \
                    ciphertext at {ciphertext_counter}. \
                    Call `seek({ciphertext_counter})` to align",
                )
            }
            Self::InvalidOutputLayout => write!(
                f,
                "Provided output layout and input stream cipher do not match"
            ),
            Self::KeystreamProductionError(e) => e.fmt(f),
            Self::InvalidKeystream => write!(
                f,
                "The Keystream provided by the transcipherer is not correct"
            ),
            Self::InvalidStreamCiphertext => {
                write!(f, "The user provided stream ciphertext is invalid")
            }
        }
    }
}

impl std::error::Error for TranscipherError {}

/// Returned when a stream cipher state cannot generate enough keystream to satisfy the request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InsufficientKeystream;

impl std::fmt::Display for InsufficientKeystream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Cannot generate enough keystream from the current cipher state. \
            A new fresh state should be generated"
        )
    }
}

impl std::error::Error for InsufficientKeystream {}

impl From<InsufficientKeystream> for TranscipherError {
    fn from(value: InsufficientKeystream) -> Self {
        Self::KeystreamProductionError(FheKeyStreamError::Insufficient(value))
    }
}

/// Errors raised when generating an FHE keystream with [`Transcipherer::next_keystream_bits`]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FheKeyStreamError {
    /// Not enough keystream left to produce the requested bits
    Insufficient(InsufficientKeystream),
    /// The keystream produced an invalid ciphertext: its degree does not match the layout (some
    /// keystream bits are not set, or its unused bits may not be 0), or its noise is not nominal
    InvalidCiphertext {
        index: usize,
        degree: Degree,
        noise_level: NoiseLevel,
    },
    InvalidStreamCipherState,
}

impl std::fmt::Display for FheKeyStreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Insufficient(err) => err.fmt(f),
            Self::InvalidCiphertext {
                index,
                degree,
                noise_level,
            } => write!(
                f,
                "keystream ciphertext {index} breaks the keystream contract: \
                degree does not match the layout ({degree:?}), or noise level is not nominal \
                ({noise_level:?})"
            ),
            Self::InvalidStreamCipherState => write!(f, "the stream cipher is in an invalid state"),
        }
    }
}

impl std::error::Error for FheKeyStreamError {}

impl From<InsufficientKeystream> for FheKeyStreamError {
    fn from(value: InsufficientKeystream) -> Self {
        Self::Insufficient(value)
    }
}

impl From<FheKeyStreamError> for TranscipherError {
    fn from(value: FheKeyStreamError) -> Self {
        Self::KeystreamProductionError(value)
    }
}

/// Client-side: a stateful symmetric-cipher session, no FHE.
pub trait StreamCipher {
    /// Cipher family this session belongs to. Embedded into every
    /// [`StreamCiphertext`] produced by [`Self::encrypt`] /
    /// [`Self::encrypt_bits`].
    fn kind(&self) -> StreamCipherKind;

    /// Produce the next `n_bits` of keystream and advance the internal counter.
    /// Bits are packed LSB-first into bytes; in the standard byte-aligned
    /// transciphering use case `n_bits` is a multiple of 8.
    fn next_keystream_bits(&mut self, n_bits: usize) -> Result<Vec<u8>, InsufficientKeystream>;

    /// XOR the first `n_bits` of `input` with `n_bits` keystream bits.
    ///
    /// `input.len()` must equal `n_bits.div_ceil(8)`. When `n_bits` is not a
    /// multiple of 8, the trailing bits of the last input byte are passed
    /// through unchanged (the keystream has zero bits in that range, so the
    /// XOR is a no-op there).
    fn encrypt_bits(
        &mut self,
        input: &[u8],
        n_bits: usize,
    ) -> Result<StreamCiphertext, InsufficientKeystream> {
        assert_eq!(
            input.len(),
            n_bits.div_ceil(8),
            "input must have exactly ceil(n_bits / 8) = {} bytes (got {})",
            n_bits.div_ceil(8),
            input.len()
        );

        let encryption_counter = self.current_counter();
        let mask = self.next_keystream_bits(n_bits)?;
        let bytes: Vec<u8> = input.iter().zip_checked(mask).map(|(i, m)| i ^ m).collect();

        Ok(StreamCiphertext {
            kind: self.kind(),
            encryption_counter,
            n_bits,
            bytes,
        })
    }

    /// XOR `input` with the next `8 * input.len()` keystream bits. Advances
    /// the counter.
    fn encrypt(&mut self, input: &[u8]) -> Result<StreamCiphertext, InsufficientKeystream> {
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
                session_kind: self.kind(),
                ciphertext_kind: encrypted.kind,
            });
        }
        if encrypted.encryption_counter != self.current_counter() {
            return Err(TranscipherError::CounterMismatch {
                session_counter: self.current_counter(),
                ciphertext_counter: encrypted.encryption_counter,
            });
        }

        let mask = self.next_keystream_bits(encrypted.n_bits)?;
        Ok(encrypted
            .bytes
            .iter()
            .zip_checked(mask)
            .map(|(i, m)| i ^ m)
            .collect())
    }

    /// Set the keystream bit position to `target_counter`. The new position can be
    /// anywhere in `[0, u64::MAX]`; backward-seek is supported and may be more expensive
    /// than forward depending on the cipher.
    fn seek(&mut self, target_counter: u64);

    /// Current keystream bit position.
    fn current_counter(&self) -> u64;
}

/// Server-side: a stateful FHE-side session that mirrors a StreamCipher.
/// Same shape as `StreamCipher`, FHE-evaluated.
pub trait Transcipherer {
    /// Cipher family this session belongs to. Must match the
    /// [`StreamCiphertext::kind`] of any input passed to [`Self::transcipher`].
    fn kind(&self) -> StreamCipherKind;

    /// Produce the next `n_bits` of FHE-encrypted keystream and advance the
    /// internal counter. Implementors are free to choose the number of bits they want to set per
    /// ciphertext (for performance or algorithmic reasons) and should set the [`KeyStreamLayout`]
    /// of the returned [`FheKeyStream`] accordingly.
    fn next_keystream_bits(
        &mut self,
        sks: &ServerKey,
        n_bits: usize,
    ) -> Result<FheKeyStream, FheKeyStreamError>;

    /// Transcipher `input` against `input.n_bits()` bits of keystream from
    /// this session, advancing the internal counter.
    ///
    /// This will produce a list of ciphertexts, according to the provided
    /// `output_layout`.
    fn transcipher(
        &mut self,
        sks: &ServerKey,
        input: &StreamCiphertext,
        output_layout: &TranscipheringOutputLayout,
    ) -> Result<Vec<Ciphertext>, TranscipherError> {
        check_transcipher_input(
            self.kind(),
            self.current_counter(),
            input,
            output_layout,
            sks.message_modulus,
        )?;

        let keystream = self.next_keystream_bits(sks, input.n_bits)?;
        apply_keystream(sks, &keystream, input, output_layout)
    }

    /// Set the keystream bit position to `target_counter`. Backward-seek is supported
    /// and may be more expensive than forward (see cipher-specific docs).
    fn seek(&mut self, sks: &ServerKey, target_counter: u64);

    fn current_counter(&self) -> u64;
}

/// Owning, runtime-dispatched [`Transcipherer`]. Lets higher layers keep a
/// single concrete type that can hold any in-tree cipher state ([`Self::Kreyvium`],
/// [`Self::Aes`]), plus arbitrary out-of-tree implementors via [`Self::Dynamic`].
pub enum TranscipherSession {
    Dynamic(Box<dyn Transcipherer + Send + Sync>),
    Kreyvium(KreyviumFheState),
    Aes(Box<AesFheState>),
    OneTimePad(OneTimePadFheState),
}

impl Transcipherer for TranscipherSession {
    fn kind(&self) -> StreamCipherKind {
        match self {
            Self::Dynamic(t) => t.kind(),
            Self::Kreyvium(t) => t.kind(),
            Self::Aes(t) => t.kind(),
            Self::OneTimePad(t) => t.kind(),
        }
    }

    fn next_keystream_bits(
        &mut self,
        sks: &ServerKey,
        n_bits: usize,
    ) -> Result<FheKeyStream, FheKeyStreamError> {
        match self {
            Self::Dynamic(t) => t.next_keystream_bits(sks, n_bits),
            Self::Kreyvium(t) => t.next_keystream_bits(sks, n_bits),
            Self::Aes(t) => t.next_keystream_bits(sks, n_bits),
            Self::OneTimePad(t) => t.next_keystream_bits(sks, n_bits),
        }
    }

    fn transcipher(
        &mut self,
        sks: &ServerKey,
        input: &StreamCiphertext,
        output_layout: &TranscipheringOutputLayout,
    ) -> Result<Vec<Ciphertext>, TranscipherError> {
        match self {
            Self::Dynamic(t) => t.transcipher(sks, input, output_layout),
            Self::Kreyvium(t) => t.transcipher(sks, input, output_layout),
            Self::Aes(t) => t.transcipher(sks, input, output_layout),
            Self::OneTimePad(t) => t.transcipher(sks, input, output_layout),
        }
    }

    fn seek(&mut self, sks: &ServerKey, target_counter: u64) {
        match self {
            Self::Dynamic(t) => t.seek(sks, target_counter),
            Self::Kreyvium(t) => t.seek(sks, target_counter),
            Self::Aes(t) => t.seek(sks, target_counter),
            Self::OneTimePad(t) => t.seek(sks, target_counter),
        }
    }

    fn current_counter(&self) -> u64 {
        match self {
            Self::Dynamic(t) => t.current_counter(),
            Self::Kreyvium(t) => t.current_counter(),
            Self::Aes(t) => t.current_counter(),
            Self::OneTimePad(t) => t.current_counter(),
        }
    }
}

/// An FHE encrypted keystream that can be xored with an input encrypted with a [`StreamCipher`].
pub struct FheKeyStream {
    /// The ciphertexts
    stream: Vec<Ciphertext>,
    /// Layout used for this stream
    layout: KeyStreamLayout,
}

impl FheKeyStream {
    /// Builds a keystream from its ciphertexts, laid out following `layout`.
    pub fn try_new(
        stream: Vec<Ciphertext>,
        layout: KeyStreamLayout,
    ) -> Result<Self, FheKeyStreamError> {
        let bits_per_ct = u32::from(layout.bits_per_ct.get());

        for (index, ct) in stream.iter().enumerate() {
            // degree == 2^bits_per_ct - 1, without overflowing the shift if bits_per_ct >= 64
            if bits_per_ct >= u64::BITS
                || ct.degree.get() != (1u64 << bits_per_ct) - 1
                || ct.noise_level() != NoiseLevel::NOMINAL
            {
                return Err(FheKeyStreamError::InvalidCiphertext {
                    index,
                    degree: ct.degree,
                    noise_level: ct.noise_level(),
                });
            }
        }

        Ok(Self { stream, layout })
    }

    pub fn into_raw_parts(self) -> (Vec<Ciphertext>, KeyStreamLayout) {
        let Self { stream, layout } = self;

        (stream, layout)
    }

    pub fn layout(&self) -> &KeyStreamLayout {
        &self.layout
    }

    pub fn iter(&self) -> std::slice::Iter<'_, Ciphertext> {
        self.stream.iter()
    }

    pub fn len(&self) -> usize {
        self.stream.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<'a> IntoIterator for &'a FheKeyStream {
    type Item = &'a Ciphertext;
    type IntoIter = std::slice::Iter<'a, Ciphertext>;
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Indicates, in a list of ciphertexts, which bits are used in each ciphertext.
///
/// Every ciphertext holds the same number of keystream bits, including the last one. If fewer
/// bits are needed, the high bits of the last ciphertext are ignored.
///
/// The number of bits per ciphertext must divide 8, so that the bits of a keystream ciphertext
/// never span two bytes of the input.
#[derive(Clone, Serialize, Deserialize, Versionize)]
#[versionize(KeyStreamLayoutVersions)]
pub struct KeyStreamLayout {
    // For simplicity, only "continuous" layouts, where all bits up to a point are used, are
    // supported.
    // In the future, this type could be extended to support more complex layouts if needed for
    // more efficient algo (for example, a periodic layout alternating used bit at pos 0 and 1).
    bits_per_ct: NonZeroU8,
}

impl KeyStreamLayout {
    /// A layout where the `bits_per_ct` least significant bits of each ct are used.
    ///
    /// Returns `None` if `bits_per_ct` does not divide 8.
    pub fn try_new(bits_per_ct: NonZeroU8) -> Option<Self> {
        (8u8.is_multiple_of(bits_per_ct.get())).then_some(Self { bits_per_ct })
    }

    /// A layout where only the least significant bit of each ct is used
    pub fn single_bit() -> Self {
        // 1 != 0 and 8.is_multiple_of(1) so ok to unwrap
        Self::try_new(NonZeroU8::new(1).unwrap()).unwrap()
    }

    /// A layout where all the available plaintext space is used.
    ///
    /// Returns `None` if the number of bits of the plaintext space does not divide 8, or
    /// if any of `msg_mod` or `carry_mod` is 0 or is not a power of 2.
    pub fn full_space(msg_mod: MessageModulus, carry_mod: CarryModulus) -> Option<Self> {
        if msg_mod.0 == 0
            || carry_mod.0 == 0
            || !msg_mod.0.is_power_of_two()
            || !carry_mod.0.is_power_of_two()
        {
            return None;
        }

        let bits_per_ct = u8::try_from(msg_mod.0.ilog2() + carry_mod.0.ilog2())
            .expect("the sum of two log2 of u64 fits in a u8");

        Self::try_new(NonZeroU8::new(bits_per_ct)?)
    }

    /// Number of keystream bits held by `ct_count` ciphertexts
    #[cfg(test)]
    pub fn bit_length(&self, ct_count: usize) -> usize {
        ct_count * usize::from(self.bits_per_ct.get())
    }

    pub fn bits_per_ct(&self) -> NonZeroU8 {
        self.bits_per_ct
    }

    /// Can this layout fit in ciphertexts with the corresponding message and carry moduli?
    pub fn can_fit(&self, message_modulus: MessageModulus, carry_modulus: CarryModulus) -> bool {
        message_modulus.0.ilog2() + carry_modulus.0.ilog2() >= u32::from(self.bits_per_ct.get())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyStreamLayoutConformanceParams {
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
}

impl ParameterSetConformant for KeyStreamLayout {
    type ParameterSet = KeyStreamLayoutConformanceParams;

    fn is_conformant(&self, params: &Self::ParameterSet) -> bool {
        8u8.is_multiple_of(self.bits_per_ct.get())
            && self.can_fit(params.message_modulus, params.carry_modulus)
    }
}

/// Describes how the keystream should be consumed to produce output ciphertexts
///
/// See [`TranscipheringOutputLayout`] for an example on how this is used.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TranscipheringOutputLayoutBits {
    /// Take n bits of keystream to produce one ciphertext block of output
    Block(NonZeroU8),
    /// Skip n bits of keystream and produce no output blocks
    Skip(NonZeroU8),
}

impl TranscipheringOutputLayoutBits {
    pub fn len(self) -> usize {
        match self {
            Self::Block(n) | Self::Skip(n) => usize::from(n.get()),
        }
    }

    pub fn is_empty(self) -> bool {
        self.len() == 0
    }
}

/// How the bits from the keystream should be used to produce the output ciphertexts
///
/// For example, if input is a list of [u8, bool, i4], aligned on 8 bits, this will be:
/// [Block(2), Block(2), Block(2), Block(2), Block(1), Skip(7), Block(2), Block(2), Skip(4)]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TranscipheringOutputLayout {
    layout: Vec<TranscipheringOutputLayoutBits>,
}

impl TranscipheringOutputLayout {
    /// An empty layout, that can be extended with [`Self::push_aligned`]
    pub fn new() -> Self {
        Self::default()
    }

    /// The entries of this layout, in stream order
    pub fn entries(&self) -> &[TranscipheringOutputLayoutBits] {
        &self.layout
    }

    /// The layout of a single boolean
    pub fn boolean() -> Self {
        Self {
            layout: vec![TranscipheringOutputLayoutBits::Block(
                NonZeroU8::new(1).unwrap(),
            )],
        }
    }

    /// The layout of a single radix ciphertext of `n_bits`, under `message_modulus`
    ///
    /// # Panics
    /// Panics if message_modulus is < 2
    pub fn radix(n_bits: usize, message_modulus: MessageModulus) -> Self {
        use TranscipheringOutputLayoutBits::Block;

        let bits_per_block = u8::try_from(message_modulus.0.ilog2())
            .expect("log2 of a u64 is at most 63, so it fits in a u8");
        let bits_per_block = NonZeroU8::new(bits_per_block).expect("message_modulus must be > 1");

        let full_blocks = n_bits / usize::from(bits_per_block.get());
        let rem = n_bits % usize::from(bits_per_block.get());

        let mut layout = std::iter::repeat_n(Block(bits_per_block), full_blocks).collect_vec();
        if let Some(rem) = NonZeroU8::new(
            u8::try_from(rem)
                .expect("rem is smaller than bits_per_block, which itself fits in a u8"),
        ) {
            layout.push(Block(rem))
        }

        Self { layout }
    }

    /// Appends `part` to this layout, then skips bits until the total length is a multiple of
    /// `alignment`.
    ///
    /// # Panics
    /// Panics if the total layout overflows a usize
    pub fn push_aligned(&mut self, part: Self, alignment: NonZeroU8) -> &mut Self {
        self.layout.extend(part.layout);

        let n_bits = self.bit_length();
        let pad = n_bits
            .checked_next_multiple_of(usize::from(alignment.get()))
            .expect("total layout size overflows a usize")
            - n_bits;

        if let Some(pad) =
            NonZeroU8::new(u8::try_from(pad).expect("pad < alignment, so it fits in a u8"))
        {
            self.layout.push(TranscipheringOutputLayoutBits::Skip(pad));
        }

        self
    }

    /// Total number of stream bits covered by this layout, including the skipped ones
    ///
    /// # Panics
    ///
    /// Panics if the length overflows a `usize`.
    pub fn bit_length(&self) -> usize {
        self.checked_bit_length()
            .expect("output layout length overflows usize")
    }

    /// Same as [`Self::bit_length`], but returns `None` on overflow
    fn checked_bit_length(&self) -> Option<usize> {
        self.layout
            .iter()
            .try_fold(0usize, |acc, entry| acc.checked_add(entry.len()))
    }

    /// Checks that this layout can be used to transcipher an input of `n_bits`, with a server key
    /// of `message_modulus`: it covers the input, and its blocks fit in the message space
    pub fn validate(
        &self,
        n_bits: usize,
        message_modulus: MessageModulus,
    ) -> Result<(), TranscipherError> {
        if self.checked_bit_length() != Some(n_bits) {
            return Err(TranscipherError::InvalidOutputLayout);
        }

        // The output blocks must fit in the message space
        let max_block_bits = message_modulus.0.ilog2();
        if !self.entries().iter().all(|entry| match entry {
            TranscipheringOutputLayoutBits::Block(bits) => u32::from(bits.get()) <= max_block_bits,
            TranscipheringOutputLayoutBits::Skip(_) => true,
        }) {
            return Err(TranscipherError::InvalidOutputLayout);
        }

        Ok(())
    }
}

/// Checks that `input` can be transciphered by a session of `session_kind` at `session_counter`,
/// into `output_layout`. Done before generating the keystream, so a rejected input does not
/// advance the counter.
pub(crate) fn check_transcipher_input(
    session_kind: StreamCipherKind,
    session_counter: u64,
    input: &StreamCiphertext,
    output_layout: &TranscipheringOutputLayout,
    message_modulus: MessageModulus,
) -> Result<(), TranscipherError> {
    if input.kind != session_kind {
        return Err(TranscipherError::KindMismatch {
            session_kind,
            ciphertext_kind: input.kind,
        });
    }
    if input.encryption_counter != session_counter {
        return Err(TranscipherError::CounterMismatch {
            session_counter,
            ciphertext_counter: input.encryption_counter,
        });
    }
    if input.bytes.len() != input.n_bits.div_ceil(8) {
        return Err(TranscipherError::InvalidStreamCiphertext);
    }

    // Also checked when applying the keystream, but checking it here avoids generating a
    // keystream (and advancing the counter) for an input that will be rejected
    output_layout.validate(input.n_bits, message_modulus)
}
