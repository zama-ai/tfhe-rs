#![allow(non_snake_case)]

use std::error::Error;
use std::fmt::Display;
use std::marker::PhantomData;

use crate::backward_compatibility::{
    SerializableAffineVersions, SerializableCubicExtFieldVersions, SerializableFpVersions,
    SerializableGroupElementsVersions, SerializablePKEv1PublicParamsVersions,
    SerializablePKEv2PublicParamsVersions, SerializableQuadExtFieldVersions,
};
use ark_ec::short_weierstrass::{Affine, SWCurveConfig};
use ark_ec::AffineRepr;
use ark_ff::{BigInt, Field, Fp, Fp2, Fp6, Fp6Config, FpConfig, QuadExtConfig, QuadExtField};
use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

use crate::curve_api::{Curve, CurveGroupOps};
use crate::proofs::pke::PublicParams as PKEv1PublicParams;
use crate::proofs::pke_v2::{Bound, PublicParams as PKEv2PublicParams};
use crate::proofs::GroupElements;

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
pub(crate) fn try_vec_to_array<T, const N: usize>(
    vec: Vec<T>,
) -> Result<[T; N], InvalidArraySizeError> {
    let len = vec.len();

    vec.try_into().map_err(|_| InvalidArraySizeError {
        expected_len: len,
        found_len: N,
    })
}

/// Serialization equivalent of the [`Fp`] struct, where the bigint is split into
/// multiple u64.
#[derive(Serialize, Deserialize, Versionize)]
#[versionize(SerializableFpVersions)]
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
#[derive(Serialize, Deserialize, Versionize)]
#[versionize(SerializableAffineVersions)]
pub enum SerializableAffine<F> {
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

pub(crate) type SerializableG1Affine = SerializableAffine<SerializableFp>;

#[derive(Serialize, Deserialize, Versionize)]
#[versionize(SerializableQuadExtFieldVersions)]
pub struct SerializableQuadExtField<F> {
    c0: F,
    c1: F,
}

pub(crate) type SerializableFp2 = SerializableQuadExtField<SerializableFp>;
pub type SerializableG2Affine = SerializableAffine<SerializableFp2>;

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

#[derive(Serialize, Deserialize, Versionize)]
#[versionize(SerializableCubicExtFieldVersions)]
pub struct SerializableCubicExtField<F> {
    c0: F,
    c1: F,
    c2: F,
}

pub(crate) type SerializableFp6 = SerializableCubicExtField<SerializableFp2>;

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

#[derive(Debug)]
pub enum InvalidSerializedGroupElementsError {
    InvalidAffine(InvalidSerializedAffineError),
    InvalidGlistDimension(InvalidArraySizeError),
}

impl Display for InvalidSerializedGroupElementsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InvalidSerializedGroupElementsError::InvalidAffine(affine_error) => {
                write!(f, "Invalid Affine in GroupElement: {}", affine_error)
            }
            InvalidSerializedGroupElementsError::InvalidGlistDimension(arr_error) => {
                write!(f, "invalid number of elements in g_list: {}", arr_error)
            }
        }
    }
}

impl Error for InvalidSerializedGroupElementsError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            InvalidSerializedGroupElementsError::InvalidAffine(affine_error) => Some(affine_error),
            InvalidSerializedGroupElementsError::InvalidGlistDimension(arr_error) => {
                Some(arr_error)
            }
        }
    }
}

impl From<InvalidSerializedAffineError> for InvalidSerializedGroupElementsError {
    fn from(value: InvalidSerializedAffineError) -> Self {
        Self::InvalidAffine(value)
    }
}

#[derive(Serialize, Deserialize, Versionize)]
#[versionize(SerializableGroupElementsVersions)]
pub(crate) struct SerializableGroupElements {
    pub(crate) g_list: Vec<SerializableG1Affine>,
    pub(crate) g_hat_list: Vec<SerializableG2Affine>,
}

impl<G: Curve> From<GroupElements<G>> for SerializableGroupElements
where
    <G::G1 as CurveGroupOps<G::Zp>>::Affine: Into<SerializableG1Affine>,
    <G::G2 as CurveGroupOps<G::Zp>>::Affine: Into<SerializableG2Affine>,
{
    fn from(value: GroupElements<G>) -> Self {
        let mut g_list = Vec::new();
        let mut g_hat_list = Vec::new();
        for idx in 0..value.message_len {
            g_list.push(value.g_list[(idx * 2) + 1].into());
            g_list.push(value.g_list[(idx * 2) + 2].into());
            g_hat_list.push(value.g_hat_list[idx + 1].into())
        }

        Self { g_list, g_hat_list }
    }
}

impl<G: Curve> TryFrom<SerializableGroupElements> for GroupElements<G>
where
    <G::G1 as CurveGroupOps<G::Zp>>::Affine:
        TryFrom<SerializableG1Affine, Error = InvalidSerializedAffineError>,
    <G::G2 as CurveGroupOps<G::Zp>>::Affine:
        TryFrom<SerializableG2Affine, Error = InvalidSerializedAffineError>,
{
    type Error = InvalidSerializedGroupElementsError;

    fn try_from(value: SerializableGroupElements) -> Result<Self, Self::Error> {
        if value.g_list.len() != value.g_hat_list.len() * 2 {
            return Err(InvalidSerializedGroupElementsError::InvalidGlistDimension(
                InvalidArraySizeError {
                    expected_len: value.g_hat_list.len() * 2,
                    found_len: value.g_list.len(),
                },
            ));
        }

        let g_list = value
            .g_list
            .into_iter()
            .map(<G::G1 as CurveGroupOps<G::Zp>>::Affine::try_from)
            .collect::<Result<_, InvalidSerializedAffineError>>()?;
        let g_hat_list = value
            .g_hat_list
            .into_iter()
            .map(<G::G2 as CurveGroupOps<G::Zp>>::Affine::try_from)
            .collect::<Result<_, InvalidSerializedAffineError>>()?;

        Ok(Self::from_vec(g_list, g_hat_list))
    }
}

#[derive(Debug)]
pub enum InvalidSerializedPublicParamsError {
    InvalidGroupElements(InvalidSerializedGroupElementsError),
    InvalidHashDimension(InvalidArraySizeError),
}

impl Display for InvalidSerializedPublicParamsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InvalidSerializedPublicParamsError::InvalidGroupElements(group_error) => {
                write!(f, "Invalid PublicParams: {}", group_error)
            }
            InvalidSerializedPublicParamsError::InvalidHashDimension(arr_error) => {
                write!(f, "invalid size of hash: {}", arr_error)
            }
        }
    }
}

impl Error for InvalidSerializedPublicParamsError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            InvalidSerializedPublicParamsError::InvalidGroupElements(group_error) => {
                Some(group_error)
            }
            InvalidSerializedPublicParamsError::InvalidHashDimension(arr_error) => Some(arr_error),
        }
    }
}

impl From<InvalidSerializedGroupElementsError> for InvalidSerializedPublicParamsError {
    fn from(value: InvalidSerializedGroupElementsError) -> Self {
        Self::InvalidGroupElements(value)
    }
}

impl From<InvalidArraySizeError> for InvalidSerializedPublicParamsError {
    fn from(value: InvalidArraySizeError) -> Self {
        Self::InvalidHashDimension(value)
    }
}

#[derive(serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(SerializablePKEv2PublicParamsVersions)]
pub struct SerializablePKEv2PublicParams {
    pub(crate) g_lists: SerializableGroupElements,
    pub(crate) D: usize,
    pub n: usize,
    pub d: usize,
    pub k: usize,
    pub B_bound_squared: u128,
    pub B_inf: u64,
    pub q: u64,
    pub t: u64,
    pub msbs_zero_padding_bit_count: u64,
    pub bound_type: Bound,
    // We use Vec<u8> since serde does not support fixed size arrays of 256 elements
    pub(crate) hash: Vec<u8>,
    pub(crate) hash_R: Vec<u8>,
    pub(crate) hash_t: Vec<u8>,
    pub(crate) hash_w: Vec<u8>,
    pub(crate) hash_agg: Vec<u8>,
    pub(crate) hash_lmap: Vec<u8>,
    pub(crate) hash_phi: Vec<u8>,
    pub(crate) hash_xi: Vec<u8>,
    pub(crate) hash_z: Vec<u8>,
    pub(crate) hash_chi: Vec<u8>,
}

impl<G: Curve> From<PKEv2PublicParams<G>> for SerializablePKEv2PublicParams
where
    GroupElements<G>: Into<SerializableGroupElements>,
{
    fn from(value: PKEv2PublicParams<G>) -> Self {
        let PKEv2PublicParams {
            g_lists,
            D,
            n,
            d,
            k,
            B_bound_squared,
            B_inf,
            q,
            t,
            msbs_zero_padding_bit_count,
            bound_type,
            hash,
            hash_R,
            hash_t,
            hash_w,
            hash_agg,
            hash_lmap,
            hash_phi,
            hash_xi,
            hash_z,
            hash_chi,
        } = value;
        Self {
            g_lists: g_lists.into(),
            D,
            n,
            d,
            k,
            B_bound_squared,
            B_inf,
            q,
            t,
            msbs_zero_padding_bit_count,
            bound_type,
            hash: hash.to_vec(),
            hash_R: hash_R.to_vec(),
            hash_t: hash_t.to_vec(),
            hash_w: hash_w.to_vec(),
            hash_agg: hash_agg.to_vec(),
            hash_lmap: hash_lmap.to_vec(),
            hash_phi: hash_phi.to_vec(),
            hash_xi: hash_xi.to_vec(),
            hash_z: hash_z.to_vec(),
            hash_chi: hash_chi.to_vec(),
        }
    }
}

impl<G: Curve> TryFrom<SerializablePKEv2PublicParams> for PKEv2PublicParams<G>
where
    GroupElements<G>:
        TryFrom<SerializableGroupElements, Error = InvalidSerializedGroupElementsError>,
{
    type Error = InvalidSerializedPublicParamsError;

    fn try_from(value: SerializablePKEv2PublicParams) -> Result<Self, Self::Error> {
        let SerializablePKEv2PublicParams {
            g_lists,
            D,
            n,
            d,
            k,
            B_bound_squared,
            B_inf,
            q,
            t,
            msbs_zero_padding_bit_count,
            bound_type,
            hash,
            hash_R,
            hash_t,
            hash_w,
            hash_agg,
            hash_lmap,
            hash_phi,
            hash_xi,
            hash_z,
            hash_chi,
        } = value;
        Ok(Self {
            g_lists: g_lists.try_into()?,
            D,
            n,
            d,
            k,
            B_bound_squared,
            B_inf,
            q,
            t,
            msbs_zero_padding_bit_count,
            bound_type,
            hash: try_vec_to_array(hash)?,
            hash_R: try_vec_to_array(hash_R)?,
            hash_t: try_vec_to_array(hash_t)?,
            hash_w: try_vec_to_array(hash_w)?,
            hash_agg: try_vec_to_array(hash_agg)?,
            hash_lmap: try_vec_to_array(hash_lmap)?,
            hash_phi: try_vec_to_array(hash_phi)?,
            hash_xi: try_vec_to_array(hash_xi)?,
            hash_z: try_vec_to_array(hash_z)?,
            hash_chi: try_vec_to_array(hash_chi)?,
        })
    }
}

#[derive(serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(SerializablePKEv1PublicParamsVersions)]
pub struct SerializablePKEv1PublicParams {
    pub(crate) g_lists: SerializableGroupElements,
    pub(crate) big_d: usize,
    pub n: usize,
    pub d: usize,
    pub k: usize,
    pub b: u64,
    pub b_r: u64,
    pub q: u64,
    pub t: u64,
    pub msbs_zero_padding_bit_count: u64,
    // We use Vec<u8> since serde does not support fixed size arrays of 256 elements
    pub(crate) hash: Vec<u8>,
    pub(crate) hash_t: Vec<u8>,
    pub(crate) hash_agg: Vec<u8>,
    pub(crate) hash_lmap: Vec<u8>,
    pub(crate) hash_z: Vec<u8>,
    pub(crate) hash_w: Vec<u8>,
}

impl<G: Curve> From<PKEv1PublicParams<G>> for SerializablePKEv1PublicParams
where
    GroupElements<G>: Into<SerializableGroupElements>,
{
    fn from(value: PKEv1PublicParams<G>) -> Self {
        let PKEv1PublicParams {
            g_lists,
            big_d,
            n,
            d,
            k,
            b,
            b_r,
            q,
            t,
            msbs_zero_padding_bit_count,
            hash,
            hash_t,
            hash_agg,
            hash_lmap,
            hash_z,
            hash_w,
        } = value;
        Self {
            g_lists: g_lists.into(),
            big_d,
            n,
            d,
            k,
            b,
            b_r,
            q,
            t,
            msbs_zero_padding_bit_count,
            hash: hash.to_vec(),
            hash_t: hash_t.to_vec(),
            hash_agg: hash_agg.to_vec(),
            hash_lmap: hash_lmap.to_vec(),
            hash_z: hash_z.to_vec(),
            hash_w: hash_w.to_vec(),
        }
    }
}

impl<G: Curve> TryFrom<SerializablePKEv1PublicParams> for PKEv1PublicParams<G>
where
    GroupElements<G>:
        TryFrom<SerializableGroupElements, Error = InvalidSerializedGroupElementsError>,
{
    type Error = InvalidSerializedPublicParamsError;

    fn try_from(value: SerializablePKEv1PublicParams) -> Result<Self, Self::Error> {
        let SerializablePKEv1PublicParams {
            g_lists,
            big_d,
            n,
            d,
            k,
            b,
            b_r,
            q,
            t,
            msbs_zero_padding_bit_count,
            hash,
            hash_t,
            hash_agg,
            hash_lmap,
            hash_z,
            hash_w,
        } = value;
        Ok(Self {
            g_lists: g_lists.try_into()?,
            big_d,
            n,
            d,
            k,
            b,
            b_r,
            q,
            t,
            msbs_zero_padding_bit_count,
            hash: try_vec_to_array(hash)?,
            hash_t: try_vec_to_array(hash_t)?,
            hash_agg: try_vec_to_array(hash_agg)?,
            hash_lmap: try_vec_to_array(hash_lmap)?,
            hash_z: try_vec_to_array(hash_z)?,
            hash_w: try_vec_to_array(hash_w)?,
        })
    }
}
