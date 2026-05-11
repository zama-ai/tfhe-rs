use std::num::NonZeroUsize;

use crate::core_crypto::prelude::{Container, Numeric};
use crate::integer::block_decomposition::{BlockDecomposer, DecomposableInto};
use crate::integer::ciphertext::{BooleanBlock, DataKind};
use crate::integer::oprf::{GenericOprfServerKey, OprfServerKey};
use crate::integer::{RadixCiphertext, ServerKey, SignedRadixCiphertext};
use crate::transciphering::{StreamCipher, StreamCiphertext, TranscipherError, Transcipherer};

/// Signedness / shape tag attached to an [`IntegerStreamCiphertext`] so the
/// server can expand it into the correct integer type without extra hints.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
            Self::Boolean => DataKind::Boolean,
        })
    }
}

// dbg!(dont forget serialization + backward)
#[derive(Clone, Debug)]
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
}

/// Client-side extension of [`StreamCipher`] that produces
/// [`IntegerStreamCiphertext`] values carrying the plaintext's shape.
///
/// Signedness is detected at runtime from the type via a `ONE << (BITS-1)`
/// check, which folds to a compile-time constant for concrete `T`.
pub trait IntegerStreamCipher {
    /// Encrypt an integer as a radix stream ciphertext of width `T::BITS`.
    fn encrypt_integer<T>(&mut self, input: T) -> IntegerStreamCiphertext
    where
        T: DecomposableInto<u8> + Numeric + std::ops::Shl<usize, Output = T>;

    /// Encrypt an integer as a radix stream ciphertext of width `n_bits`.
    ///
    /// If `n_bits > T::BITS` the value is sign- or zero-extended (based on
    /// the sign of `T`), if `n_bits < T::BITS` it is truncated to the low
    /// `n_bits`.
    ///
    /// # Panics
    /// Panics if `n_bits == 0`.
    fn encrypt_integer_with_num_bits<T>(
        &mut self,
        input: T,
        n_bits: usize,
    ) -> IntegerStreamCiphertext
    where
        T: DecomposableInto<u8> + Numeric + std::ops::Shl<usize, Output = T>;

    /// Encrypt a single boolean bit.
    fn encrypt_bool(&mut self, input: bool) -> IntegerStreamCiphertext;
}

impl<C: StreamCipher + ?Sized> IntegerStreamCipher for C {
    fn encrypt_integer<T>(&mut self, input: T) -> IntegerStreamCiphertext
    where
        T: DecomposableInto<u8> + Numeric + std::ops::Shl<usize, Output = T>,
    {
        self.encrypt_integer_with_num_bits(input, T::BITS)
    }

    fn encrypt_integer_with_num_bits<T>(
        &mut self,
        input: T,
        n_bits: usize,
    ) -> IntegerStreamCiphertext
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
        IntegerStreamCiphertext {
            inner: encrypt_le_bits(self, input, n_bits),
            kind,
        }
    }

    fn encrypt_bool(&mut self, input: bool) -> IntegerStreamCiphertext {
        IntegerStreamCiphertext {
            inner: self.encrypt_bits(&[u8::from(input)], 1),
            kind: IntegerStreamCiphertextKind::Boolean,
        }
    }
}

fn encrypt_le_bits<C, T>(cipher: &mut C, input: T, n_bits: usize) -> StreamCiphertext
where
    C: StreamCipher + ?Sized,
    T: DecomposableInto<u8>,
{
    let n_bytes = n_bits.div_ceil(8);
    let bytes: Vec<u8> = BlockDecomposer::with_block_count(input, 8, n_bytes)
        .iter_as::<u8>()
        .collect();
    debug_assert_eq!(bytes.len(), n_bytes);
    cipher.encrypt_bits(&bytes, n_bits)
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
}

impl<T: Transcipherer> IntegerTranscipherer for T {
    fn transcipher_radix(
        &mut self,
        sks: &ServerKey,
        input: &IntegerStreamCiphertext,
    ) -> Result<RadixCiphertext, IntegerTranscipherError> {
        check_kind(input, IntegerStreamCiphertextKind::Unsigned)?;
        let blocks = self.transcipher(&sks.key, &input.inner)?;
        Ok(RadixCiphertext::from(blocks))
    }

    fn transcipher_signed_radix(
        &mut self,
        sks: &ServerKey,
        input: &IntegerStreamCiphertext,
    ) -> Result<SignedRadixCiphertext, IntegerTranscipherError> {
        check_kind(input, IntegerStreamCiphertextKind::Signed)?;
        let blocks = self.transcipher(&sks.key, &input.inner)?;
        Ok(SignedRadixCiphertext::from(blocks))
    }

    fn transcipher_bool(
        &mut self,
        sks: &ServerKey,
        input: &IntegerStreamCiphertext,
    ) -> Result<BooleanBlock, IntegerTranscipherError> {
        check_kind(input, IntegerStreamCiphertextKind::Boolean)?;
        let mut blocks = self.transcipher(&sks.key, &input.inner)?;
        let block = blocks.pop().expect("boolean transcipher produced no block");
        Ok(BooleanBlock::new_unchecked(block))
    }
}

fn check_kind(
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
