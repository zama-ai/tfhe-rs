use std::num::{NonZeroU32, NonZeroU8, NonZeroUsize};

use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

use crate::conformance::ParameterSetConformant;
use crate::core_crypto::prelude::Numeric;
use crate::integer::block_decomposition::{BlockDecomposer, DecomposableInto};
use crate::integer::ciphertext::{BooleanBlock, CompactCiphertextListExpander, DataKind};
use crate::integer::{RadixCiphertext, ServerKey, SignedRadixCiphertext};
use crate::shortint::{AtomicPatternParameters, MessageModulus};
use crate::transciphering::{
    InsufficientKeystream, StreamCipher, StreamCipherKind, StreamCiphertext,
    StreamCiphertextConformanceParams, TranscipherError, Transcipherer, TranscipheringOutputLayout,
};

use super::backward_compatibility::transciphering::{
    IntegerStreamCiphertextKindVersions, IntegerStreamCiphertextListVersions,
    IntegerStreamCiphertextPartVersions, IntegerStreamCiphertextVersions,
};

/// Signedness / shape tag attached to an [`IntegerStreamCiphertext`] so the
/// server can expand it into the correct integer type without extra hints.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Versionize)]
#[versionize(IntegerStreamCiphertextKindVersions)]
pub enum IntegerStreamCiphertextKind {
    Unsigned,
    Signed,
    Boolean,
}

impl IntegerStreamCiphertextKind {
    /// Combine this shape tag with a transcipher output block count to build
    /// the [`DataKind`] needed by [`crate::integer::ciphertext::Expandable`].
    ///
    /// Returns an error if `n_blocks == 0` for a radix kind.
    pub fn to_data_kind(self, n_blocks: usize) -> crate::Result<DataKind> {
        Ok(match self {
            Self::Unsigned => DataKind::Unsigned(
                NonZeroUsize::new(n_blocks)
                    .ok_or_else(|| crate::error!("empty transcipher output"))?,
            ),
            Self::Signed => DataKind::Signed(
                NonZeroUsize::new(n_blocks)
                    .ok_or_else(|| crate::error!("empty transcipher output"))?,
            ),
            Self::Boolean => {
                if n_blocks != 1 {
                    return Err(crate::error!(
                        "Tried to convert IntegerStreamCiphertextKind::Boolean \
                        to DataKind::Boolean with n_blocks != 1"
                    ));
                }
                DataKind::Boolean
            }
        })
    }
}

/// Kind and bit count of a value in an [`IntegerStreamCiphertextList`]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Versionize)]
#[versionize(IntegerStreamCiphertextPartVersions)]
pub enum IntegerStreamCiphertextPart {
    Unsigned(NonZeroU32),
    Signed(NonZeroU32),
    Boolean,
}

impl IntegerStreamCiphertextPart {
    pub fn n_bits(self) -> usize {
        match self {
            Self::Unsigned(n_bits) | Self::Signed(n_bits) => n_bits.get() as usize,
            Self::Boolean => 1,
        }
    }

    /// Number of stream bits used by this part, including the alignment padding
    fn checked_aligned_n_bits(self) -> Option<usize> {
        self.n_bits()
            .checked_next_multiple_of(usize::from(STREAM_LIST_PART_ALIGNMENT.get()))
    }

    /// The output layout and [`DataKind`] of this part, once transciphered with `message_modulus`
    ///
    /// Radix parts must fill whole blocks, as for [`IntegerStreamCiphertext::output_layout`].
    fn expansion_info(
        self,
        message_modulus: MessageModulus,
    ) -> Result<(TranscipheringOutputLayout, DataKind), IntegerTranscipherError> {
        if self == Self::Boolean {
            return Ok((TranscipheringOutputLayout::boolean(), DataKind::Boolean));
        }

        let n_bits = self.n_bits();
        let message_modulus_log = message_modulus.0.ilog2();
        let invalid_bit_count = || IntegerTranscipherError::RadixInvalidBitCount {
            ciphertext_bit_count: n_bits,
            message_modulus_log,
        };

        let layout = TranscipheringOutputLayout::radix(n_bits, message_modulus)
            .map_err(|_| invalid_bit_count())?;
        let n_blocks = NonZeroUsize::new(layout.entries().len()).ok_or_else(invalid_bit_count)?;

        let data_kind = if matches!(self, Self::Signed(_)) {
            DataKind::Signed(n_blocks)
        } else {
            DataKind::Unsigned(n_blocks)
        };

        Ok((layout, data_kind))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IntegerStreamCiphertextConformanceParams {
    pub cipher_kind: StreamCipherKind,
    pub kind: IntegerStreamCiphertextKind,
    pub n_bits: usize,
}

impl ParameterSetConformant for IntegerStreamCiphertext {
    type ParameterSet = IntegerStreamCiphertextConformanceParams;

    fn is_conformant(&self, params: &Self::ParameterSet) -> bool {
        let Self { inner, kind } = self;

        let IntegerStreamCiphertextConformanceParams {
            cipher_kind,
            kind: params_kind,
            n_bits,
        } = params;

        kind == params_kind
            && inner.is_conformant(&StreamCiphertextConformanceParams {
                kind: *cipher_kind,
                n_bits: *n_bits,
            })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Versionize)]
#[versionize(IntegerStreamCiphertextVersions)]
pub struct IntegerStreamCiphertext {
    inner: StreamCiphertext,
    kind: IntegerStreamCiphertextKind,
}

impl IntegerStreamCiphertext {
    pub fn into_raw_parts(self) -> (StreamCiphertext, IntegerStreamCiphertextKind) {
        (self.inner, self.kind)
    }

    pub fn from_raw_parts(inner: StreamCiphertext, kind: IntegerStreamCiphertextKind) -> Self {
        Self { inner, kind }
    }

    pub fn inner(&self) -> &StreamCiphertext {
        &self.inner
    }

    pub fn into_inner(self) -> StreamCiphertext {
        self.inner
    }

    pub fn kind(&self) -> IntegerStreamCiphertextKind {
        self.kind
    }

    pub fn n_bits(&self) -> usize {
        self.inner.n_bits()
    }

    /// The output layout this ciphertext should be transciphered into, based on its kind
    pub fn output_layout(
        &self,
        message_modulus: MessageModulus,
    ) -> Result<TranscipheringOutputLayout, IntegerTranscipherError> {
        match self.kind {
            IntegerStreamCiphertextKind::Unsigned | IntegerStreamCiphertextKind::Signed => {
                // If the input integer size is not a multiple of the block size, we return an
                // error. Accepting this means that we would have to handle sign extension in the
                // transciphering process.
                TranscipheringOutputLayout::radix(self.n_bits(), message_modulus).map_err(|_| {
                    IntegerTranscipherError::RadixInvalidBitCount {
                        ciphertext_bit_count: self.n_bits(),
                        message_modulus_log: message_modulus.0.ilog2(),
                    }
                })
            }
            IntegerStreamCiphertextKind::Boolean => {
                if self.n_bits() != 1 {
                    return Err(IntegerTranscipherError::BooleanInvalidBitCount {
                        ciphertext_bit_count: self.n_bits(),
                    });
                }
                Ok(TranscipheringOutputLayout::boolean())
            }
        }
    }
}

/// Each part of an [`IntegerStreamCiphertextList`] starts on a multiple of this number of bits
const STREAM_LIST_PART_ALIGNMENT: NonZeroU8 = NonZeroU8::new(u8::BITS as u8).unwrap();

/// A list of values encrypted with a single [`StreamCiphertext`], each part starting on a byte
/// boundary.
#[derive(Clone, Debug, Serialize, Deserialize, Versionize)]
#[versionize(IntegerStreamCiphertextListVersions)]
pub struct IntegerStreamCiphertextList {
    inner: StreamCiphertext,
    info: Vec<IntegerStreamCiphertextPart>,
}

impl IntegerStreamCiphertextList {
    pub fn builder() -> IntegerStreamCiphertextListBuilder {
        IntegerStreamCiphertextListBuilder::new()
    }

    pub fn inner(&self) -> &StreamCiphertext {
        &self.inner
    }

    pub fn len(&self) -> usize {
        self.info.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn get_kind_of(&self, index: usize) -> Option<IntegerStreamCiphertextPart> {
        self.info.get(index).copied()
    }

    /// Number of stream bits described by the parts, or None if it overflows
    fn expected_n_bits(&self) -> Option<usize> {
        self.info.iter().try_fold(0usize, |acc, part| {
            acc.checked_add(part.checked_aligned_n_bits()?)
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IntegerStreamCiphertextListConformanceParams {
    pub cipher_kind: StreamCipherKind,
    /// Maximum number of stream bits, including the alignment padding
    pub max_n_bits: usize,
    pub message_modulus: MessageModulus,
}

impl IntegerStreamCiphertextListConformanceParams {
    /// `params` are the parameters of the server key the list will be transciphered with
    pub fn from_parameters_and_max_n_bits(
        params: impl Into<AtomicPatternParameters>,
        cipher_kind: StreamCipherKind,
        max_n_bits: usize,
    ) -> Self {
        Self {
            cipher_kind,
            max_n_bits,
            message_modulus: params.into().message_modulus(),
        }
    }
}

impl ParameterSetConformant for IntegerStreamCiphertextList {
    type ParameterSet = IntegerStreamCiphertextListConformanceParams;

    fn is_conformant(&self, params: &Self::ParameterSet) -> bool {
        let Self { inner, info } = self;

        let IntegerStreamCiphertextListConformanceParams {
            cipher_kind,
            max_n_bits,
            message_modulus,
        } = params;

        let Some(n_bits) = self.expected_n_bits() else {
            return false;
        };

        n_bits <= *max_n_bits
            && info
                .iter()
                .all(|part| part.expansion_info(*message_modulus).is_ok())
            && inner.is_conformant(&StreamCiphertextConformanceParams {
                kind: *cipher_kind,
                n_bits,
            })
    }
}

/// Values that can be pushed in an [`IntegerStreamCiphertextListBuilder`]
pub trait StreamPackable {
    /// Appends the little-endian bytes of `self` to `bytes`, on `n_bits` if provided or on the
    /// natural bit width of `Self` otherwise
    ///
    /// # Panics
    /// Panics if `n_bits` is `Some(0)` or does not fit in a `u32`.
    fn pack_into(self, bytes: &mut Vec<u8>, n_bits: Option<usize>) -> IntegerStreamCiphertextPart;
}

impl StreamPackable for bool {
    fn pack_into(self, bytes: &mut Vec<u8>, _n_bits: Option<usize>) -> IntegerStreamCiphertextPart {
        bytes.push(u8::from(self));
        IntegerStreamCiphertextPart::Boolean
    }
}

impl<T> StreamPackable for T
where
    T: DecomposableInto<u8> + Numeric + std::ops::Shl<usize, Output = T>,
{
    fn pack_into(self, bytes: &mut Vec<u8>, n_bits: Option<usize>) -> IntegerStreamCiphertextPart {
        let n_bits = n_bits.unwrap_or(T::BITS);
        bytes.extend(le_bytes(self, n_bits));
        let n_bits = u32::try_from(n_bits)
            .ok()
            .and_then(NonZeroU32::new)
            .expect("n_bits must be in 1..=u32::MAX");

        // This works because rust always uses two's complement
        let is_signed = (T::ONE << (T::BITS - 1)) < T::ZERO;
        if is_signed {
            IntegerStreamCiphertextPart::Signed(n_bits)
        } else {
            IntegerStreamCiphertextPart::Unsigned(n_bits)
        }
    }
}

#[derive(Default)]
pub struct IntegerStreamCiphertextListBuilder {
    bytes: Vec<u8>,
    info: Vec<IntegerStreamCiphertextPart>,
}

impl IntegerStreamCiphertextListBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push<T>(&mut self, data: T) -> &mut Self
    where
        T: StreamPackable,
    {
        self.info.push(data.pack_into(&mut self.bytes, None));
        self
    }

    /// # Panics
    /// Panics if `n_bits == 0`.
    pub fn push_with_num_bits<T>(&mut self, data: T, n_bits: usize) -> &mut Self
    where
        // The extra `Numeric` bound is to prevent T from being `bool`
        T: StreamPackable + Numeric,
    {
        self.info
            .push(data.pack_into(&mut self.bytes, Some(n_bits)));
        self
    }

    pub fn extend<T>(&mut self, values: impl Iterator<Item = T>) -> &mut Self
    where
        T: StreamPackable,
    {
        for value in values {
            self.push(value);
        }
        self
    }

    /// # Panics
    /// Panics if `n_bits == 0`.
    pub fn extend_with_num_bits<T>(
        &mut self,
        values: impl Iterator<Item = T>,
        n_bits: usize,
    ) -> &mut Self
    where
        T: StreamPackable + Numeric,
    {
        for value in values {
            self.push_with_num_bits(value, n_bits);
        }
        self
    }

    /// Number of keystream bits needed to build the list
    pub fn n_bits(&self) -> usize {
        self.bytes.len() * 8
    }

    /// Encrypts the pushed values with the next [`Self::n_bits`] bits of keystream of `cipher`
    pub fn build<C>(
        &self,
        cipher: &mut C,
    ) -> Result<IntegerStreamCiphertextList, InsufficientKeystream>
    where
        C: StreamCipher + ?Sized,
    {
        Ok(IntegerStreamCiphertextList {
            inner: cipher.encrypt(&self.bytes)?,
            info: self.info.clone(),
        })
    }
}

/// Client-side extension of [`StreamCipher`] that produces
/// [`IntegerStreamCiphertext`] values carrying the plaintext's shape.
///
/// Signedness is detected at runtime from the type via a `ONE << (BITS-1)`
/// check, which folds to a compile-time constant for concrete `T`.
pub trait IntegerStreamCipher {
    /// Encrypt an integer as a radix stream ciphertext of width `T::BITS`.
    fn encrypt_integer<T>(
        &mut self,
        input: T,
    ) -> Result<IntegerStreamCiphertext, InsufficientKeystream>
    where
        T: DecomposableInto<u8> + Numeric + std::ops::Shl<usize, Output = T>;

    /// Encrypt an integer as a radix stream ciphertext of width `n_bits`.
    ///
    /// If `n_bits > T::BITS` the value is sign- or zero-extended (based on
    /// the sign of `T`), if `n_bits < T::BITS` it is truncated to the low
    /// `n_bits`.
    ///
    /// The server only accepts an `n_bits` that is a multiple of the number of message bits per
    /// block of its parameters (2 with the default parameters).
    ///
    /// # Panics
    /// Panics if `n_bits == 0`.
    fn encrypt_integer_with_num_bits<T>(
        &mut self,
        input: T,
        n_bits: usize,
    ) -> Result<IntegerStreamCiphertext, InsufficientKeystream>
    where
        T: DecomposableInto<u8> + Numeric + std::ops::Shl<usize, Output = T>;

    /// Encrypt a single boolean bit.
    fn encrypt_bool(
        &mut self,
        input: bool,
    ) -> Result<IntegerStreamCiphertext, InsufficientKeystream>;
}

impl<C: StreamCipher + ?Sized> IntegerStreamCipher for C {
    fn encrypt_integer<T>(
        &mut self,
        input: T,
    ) -> Result<IntegerStreamCiphertext, InsufficientKeystream>
    where
        T: DecomposableInto<u8> + Numeric + std::ops::Shl<usize, Output = T>,
    {
        self.encrypt_integer_with_num_bits(input, T::BITS)
    }

    fn encrypt_integer_with_num_bits<T>(
        &mut self,
        input: T,
        n_bits: usize,
    ) -> Result<IntegerStreamCiphertext, InsufficientKeystream>
    where
        T: DecomposableInto<u8> + Numeric + std::ops::Shl<usize, Output = T>,
    {
        assert!(
            n_bits > 0,
            "encrypt_integer_with_num_bits: n_bits must be > 0"
        );
        let is_signed = (T::ONE << (T::BITS - 1)) < T::ZERO;
        let kind = if is_signed {
            IntegerStreamCiphertextKind::Signed
        } else {
            IntegerStreamCiphertextKind::Unsigned
        };
        Ok(IntegerStreamCiphertext {
            inner: encrypt_le_bits(self, input, n_bits)?,
            kind,
        })
    }

    fn encrypt_bool(
        &mut self,
        input: bool,
    ) -> Result<IntegerStreamCiphertext, InsufficientKeystream> {
        Ok(IntegerStreamCiphertext {
            inner: self.encrypt_bits(&[u8::from(input)], 1)?,
            kind: IntegerStreamCiphertextKind::Boolean,
        })
    }
}

fn encrypt_le_bits<C, T>(
    cipher: &mut C,
    input: T,
    n_bits: usize,
) -> Result<StreamCiphertext, InsufficientKeystream>
where
    C: StreamCipher + ?Sized,
    T: DecomposableInto<u8>,
{
    cipher.encrypt_bits(&le_bytes(input, n_bits), n_bits)
}

/// Little-endian bytes of the low `n_bits` of `input`, with the bits above `n_bits` set to zero
fn le_bytes<T>(input: T, n_bits: usize) -> Vec<u8>
where
    T: DecomposableInto<u8>,
{
    let n_bytes = n_bits.div_ceil(8);
    let mut bytes: Vec<u8> = BlockDecomposer::with_block_count(input, 8, n_bytes)
        .iter_as::<u8>()
        .collect();
    debug_assert_eq!(bytes.len(), n_bytes);

    // Zero the bits above `n_bits` in the final partial byte to avoid any leak.
    let bits_in_last_byte = n_bits % 8;
    if bits_in_last_byte != 0 {
        bytes[n_bytes - 1] &= (1u8 << bits_in_last_byte) - 1;
    }

    bytes
}

/// Errors raised by [`IntegerTranscipherer`] operations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IntegerTranscipherError {
    /// Underlying stream-cipher transcipher error (kind / counter mismatch).
    Transcipher(TranscipherError),
    /// The stream ciphertext's shape tag does not match the requested output type.
    KindMismatch {
        expected: IntegerStreamCiphertextKind,
        got: IntegerStreamCiphertextKind,
    },
    /// The stream ciphertext did not have the right bit count for a boolean value.
    BooleanInvalidBitCount { ciphertext_bit_count: usize },
    /// The stream ciphertext did not have the right bit count for a radix value.
    RadixInvalidBitCount {
        ciphertext_bit_count: usize,
        message_modulus_log: u32,
    },
}

impl From<TranscipherError> for IntegerTranscipherError {
    fn from(e: TranscipherError) -> Self {
        Self::Transcipher(e)
    }
}

impl std::fmt::Display for IntegerTranscipherError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transcipher(e) => write!(f, "{e}"),
            Self::KindMismatch { expected, got } => write!(
                f,
                "integer stream ciphertext kind mismatch: expected {expected:?}, got {got:?}"
            ),
            Self::BooleanInvalidBitCount {
                ciphertext_bit_count,
            } => write!(
                f,
                "integer stream ciphertext bit count mismatch for boolean value. \
                Expected 1 bit, got {ciphertext_bit_count}"
            ),
            Self::RadixInvalidBitCount {
                ciphertext_bit_count,
                message_modulus_log,
            } => write!(
                f,
                "integer stream ciphertext bit count mismatch for radix value. \
                Got {ciphertext_bit_count}, expected a multiple of {message_modulus_log}"
            ),
        }
    }
}

impl std::error::Error for IntegerTranscipherError {}

/// Server-side extension of [`Transcipherer`] that turns an
/// [`IntegerStreamCiphertext`] into a `RadixCiphertext`, `SignedRadixCiphertext`,
/// or `BooleanBlock` depending on the ciphertext's shape tag.
///
/// Blanket-implemented for every [`Transcipherer`].
pub trait IntegerTranscipherer {
    fn transcipher_radix(
        &mut self,
        sks: &ServerKey,
        input: &IntegerStreamCiphertext,
    ) -> Result<RadixCiphertext, IntegerTranscipherError>;

    fn transcipher_signed_radix(
        &mut self,
        sks: &ServerKey,
        input: &IntegerStreamCiphertext,
    ) -> Result<SignedRadixCiphertext, IntegerTranscipherError>;

    fn transcipher_bool(
        &mut self,
        sks: &ServerKey,
        input: &IntegerStreamCiphertext,
    ) -> Result<BooleanBlock, IntegerTranscipherError>;

    fn transcipher_list(
        &mut self,
        sks: &ServerKey,
        input: &IntegerStreamCiphertextList,
    ) -> Result<CompactCiphertextListExpander, IntegerTranscipherError>;
}

impl<T: Transcipherer> IntegerTranscipherer for T {
    fn transcipher_radix(
        &mut self,
        sks: &ServerKey,
        input: &IntegerStreamCiphertext,
    ) -> Result<RadixCiphertext, IntegerTranscipherError> {
        check_kind(input, IntegerStreamCiphertextKind::Unsigned)?;
        let layout = input.output_layout(sks.message_modulus())?;
        let blocks = self.transcipher(&sks.key, &input.inner, &layout)?;
        Ok(RadixCiphertext::from(blocks))
    }

    fn transcipher_signed_radix(
        &mut self,
        sks: &ServerKey,
        input: &IntegerStreamCiphertext,
    ) -> Result<SignedRadixCiphertext, IntegerTranscipherError> {
        check_kind(input, IntegerStreamCiphertextKind::Signed)?;
        let layout = input.output_layout(sks.message_modulus())?;
        let blocks = self.transcipher(&sks.key, &input.inner, &layout)?;
        Ok(SignedRadixCiphertext::from(blocks))
    }

    fn transcipher_bool(
        &mut self,
        sks: &ServerKey,
        input: &IntegerStreamCiphertext,
    ) -> Result<BooleanBlock, IntegerTranscipherError> {
        check_kind(input, IntegerStreamCiphertextKind::Boolean)?;
        let layout = input.output_layout(sks.message_modulus())?;
        let mut blocks = self.transcipher(&sks.key, &input.inner, &layout)?;
        let block = blocks.pop().expect("boolean transcipher produced no block");
        Ok(BooleanBlock::new_unchecked(block))
    }

    fn transcipher_list(
        &mut self,
        sks: &ServerKey,
        input: &IntegerStreamCiphertextList,
    ) -> Result<CompactCiphertextListExpander, IntegerTranscipherError> {
        let mut layout = TranscipheringOutputLayout::new();
        let mut info = Vec::with_capacity(input.info.len());
        for part in &input.info {
            let (part_layout, data_kind) = part.expansion_info(sks.message_modulus())?;
            layout.push_aligned(part_layout, STREAM_LIST_PART_ALIGNMENT);
            info.push(data_kind);
        }

        let blocks = self.transcipher(&sks.key, &input.inner, &layout)?;
        Ok(CompactCiphertextListExpander::new(blocks, info))
    }
}

pub(crate) fn check_kind(
    input: &IntegerStreamCiphertext,
    expected: IntegerStreamCiphertextKind,
) -> Result<(), IntegerTranscipherError> {
    if input.kind == expected {
        Ok(())
    } else {
        Err(IntegerTranscipherError::KindMismatch {
            expected,
            got: input.kind,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transciphering::{OneTimePadPlainSecretMask, OneTimePadPlainState};

    /// Encrypting with an all-zero keystream makes the stream-ciphertext bytes equal the
    /// (masked) input bytes, so a plaintext bit above `n_bits` that survived encryption
    /// would show up directly.
    fn zero_keystream_otp(n_bits: usize) -> OneTimePadPlainState {
        let mask = OneTimePadPlainSecretMask::new(vec![0u8; n_bits.div_ceil(8)], n_bits);
        OneTimePadPlainState::new(mask)
    }

    #[test]
    fn encrypt_integer_zeroes_bits_above_n_bits() {
        // 0x8001 has only bit 0 and bit 15 set. At 12 bits, little-endian + LSB-first
        // keeps bit 0 and drops bit 15: [0x01, 0x80] masked to [0x01, 0x00]. An asymmetric
        // value so a wrong byte or bit order would give a different result.
        let ct = zero_keystream_otp(12)
            .encrypt_integer_with_num_bits(0x8001u16, 12)
            .unwrap();
        assert_eq!(ct.inner().bytes(), &[0x01, 0x00]);

        // All-ones, incl. a negative signed value: high bits above `n_bits` are dropped.
        let ct = zero_keystream_otp(12)
            .encrypt_integer_with_num_bits(u16::MAX, 12)
            .unwrap();
        assert_eq!(ct.inner().bytes(), &[0xFF, 0x0F]);
        let ct = zero_keystream_otp(12)
            .encrypt_integer_with_num_bits(-1i16, 12)
            .unwrap();
        assert_eq!(ct.inner().bytes(), &[0xFF, 0x0F]);
    }

    #[test]
    fn encrypt_integer_byte_aligned_is_untouched() {
        // A byte-aligned width must not be over-masked.
        let ct = zero_keystream_otp(16)
            .encrypt_integer_with_num_bits(u16::MAX, 16)
            .unwrap();
        assert_eq!(ct.inner().bytes(), &[0xFF, 0xFF]);
    }
}
