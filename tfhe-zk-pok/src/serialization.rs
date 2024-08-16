use std::error::Error;
use std::fmt::Display;
use std::marker::PhantomData;

use ark_ec::short_weierstrass::{Affine, SWCurveConfig};
use ark_ec::AffineRepr;
use ark_ff::{BigInt, Field, Fp, Fp2, Fp6, Fp6Config, FpConfig, QuadExtConfig, QuadExtField};
use serde::{Deserialize, Serialize};

/// Error returned when a conversion from a vec to a fixed size array failed because the vec size is
/// incorrect
#[derive(Debug)]
pub struct InvalidArraySizeError {
    expected_len: usize,
    found_len: usize,
}

impl Display for InvalidArraySizeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Invalid serialized array: found array of size {}, expected {}",
            self.found_len, self.expected_len
        )
    }
}

impl Error for InvalidArraySizeError {}

/// Tries to convert a Vec into a constant size array, and returns an [`InvalidArraySizeError`] if
/// the size does not match
fn try_vec_to_array<T, const N: usize>(vec: Vec<T>) -> Result<[T; N], InvalidArraySizeError> {
    let len = vec.len();

    vec.try_into().map_err(|_| InvalidArraySizeError {
        expected_len: len,
        found_len: N,
    })
}

/// Serialization equivalent of the [`Fp`] struct, where the bigint is split into
/// multiple u64.
#[derive(Serialize, Deserialize)]
pub struct SerializableFp {
    val: Vec<u64>, // Use a Vec<u64> since serde does not support fixed size arrays with a generic
}

impl<P: FpConfig<N>, const N: usize> From<Fp<P, N>> for SerializableFp {
    fn from(value: Fp<P, N>) -> Self {
        Self {
            val: value.0 .0.to_vec(),
        }
    }
}

impl<P: FpConfig<N>, const N: usize> TryFrom<SerializableFp> for Fp<P, N> {
    type Error = InvalidArraySizeError;

    fn try_from(value: SerializableFp) -> Result<Self, Self::Error> {
        Ok(Fp(BigInt(try_vec_to_array(value.val)?), PhantomData))
    }
}

#[derive(Debug)]
pub enum InvalidSerializedAffineError {
    InvalidFp(InvalidArraySizeError),
    InvalidCompressedXCoordinate,
}

impl Display for InvalidSerializedAffineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InvalidSerializedAffineError::InvalidFp(fp_error) => {
                write!(f, "Invalid fp element in affine: {}", fp_error)
            }
            InvalidSerializedAffineError::InvalidCompressedXCoordinate => {
                write!(
                    f,
                    "Cannot uncompress affine: X coordinate does not belong to the curve"
                )
            }
        }
    }
}

impl Error for InvalidSerializedAffineError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            InvalidSerializedAffineError::InvalidFp(fp_error) => Some(fp_error),
            InvalidSerializedAffineError::InvalidCompressedXCoordinate => None,
        }
    }
}

impl From<InvalidArraySizeError> for InvalidSerializedAffineError {
    fn from(value: InvalidArraySizeError) -> Self {
        Self::InvalidFp(value)
    }
}

/// Serialization equivalent to the [`Affine`], which support an optional compression mode
/// where only the `x` coordinate is stored, and the `y` is computed on load.
#[derive(Serialize, Deserialize)]
pub(crate) enum SerializableAffine<F> {
    Infinity,
    Compressed { x: F, take_largest_y: bool },
    Uncompressed { x: F, y: F },
}

impl<F> SerializableAffine<F> {
    #[allow(unused)]
    pub fn uncompressed<BaseField: Into<F> + Field, C: SWCurveConfig<BaseField = BaseField>>(
        value: Affine<C>,
    ) -> Self {
        if value.is_zero() {
            Self::Infinity
        } else {
            Self::Uncompressed {
                x: value.x.into(),
                y: value.y.into(),
            }
        }
    }

    pub fn compressed<BaseField: Into<F> + Field, C: SWCurveConfig<BaseField = BaseField>>(
        value: Affine<C>,
    ) -> Self {
        if value.is_zero() {
            Self::Infinity
        } else {
            let take_largest_y = value.y > -value.y;
            Self::Compressed {
                x: value.x.into(),
                take_largest_y,
            }
        }
    }
}

impl<F, C: SWCurveConfig> TryFrom<SerializableAffine<F>> for Affine<C>
where
    F: TryInto<C::BaseField, Error = InvalidArraySizeError>,
{
    type Error = InvalidSerializedAffineError;

    fn try_from(value: SerializableAffine<F>) -> Result<Self, Self::Error> {
        match value {
            SerializableAffine::Infinity => Ok(Self::zero()),
            SerializableAffine::Compressed { x, take_largest_y } => {
                Self::get_point_from_x_unchecked(x.try_into()?, take_largest_y)
                    .ok_or(InvalidSerializedAffineError::InvalidCompressedXCoordinate)
            }
            SerializableAffine::Uncompressed { x, y } => {
                Ok(Self::new_unchecked(x.try_into()?, y.try_into()?))
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct SerializableQuadExtField<F> {
    c0: F,
    c1: F,
}

pub(crate) type SerializableFp2 = SerializableQuadExtField<SerializableFp>;

impl<F, P: QuadExtConfig> From<QuadExtField<P>> for SerializableQuadExtField<F>
where
    F: From<P::BaseField>,
{
    fn from(value: QuadExtField<P>) -> Self {
        Self {
            c0: value.c0.into(),
            c1: value.c1.into(),
        }
    }
}

impl<F, P: QuadExtConfig> TryFrom<SerializableQuadExtField<F>> for QuadExtField<P>
where
    F: TryInto<P::BaseField, Error = InvalidArraySizeError>,
{
    type Error = InvalidArraySizeError;

    fn try_from(value: SerializableQuadExtField<F>) -> Result<Self, Self::Error> {
        Ok(QuadExtField {
            c0: value.c0.try_into()?,
            c1: value.c1.try_into()?,
        })
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct SerializableCubicExtField<F> {
    c0: F,
    c1: F,
    c2: F,
}

type SerializableFp6 = SerializableCubicExtField<SerializableFp2>;

impl<F, P6: Fp6Config> From<Fp6<P6>> for SerializableCubicExtField<F>
where
    F: From<Fp2<P6::Fp2Config>>,
{
    fn from(value: Fp6<P6>) -> Self {
        Self {
            c0: value.c0.into(),
            c1: value.c1.into(),
            c2: value.c2.into(),
        }
    }
}

impl<F, P6: Fp6Config> TryFrom<SerializableCubicExtField<F>> for Fp6<P6>
where
    F: TryInto<Fp2<P6::Fp2Config>, Error = InvalidArraySizeError>,
{
    type Error = InvalidArraySizeError;

    fn try_from(value: SerializableCubicExtField<F>) -> Result<Self, Self::Error> {
        Ok(Fp6 {
            c0: value.c0.try_into()?,
            c1: value.c1.try_into()?,
            c2: value.c2.try_into()?,
        })
    }
}

pub(crate) type SerializableFp12 = SerializableQuadExtField<SerializableFp6>;
