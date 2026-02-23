use ark_ec::pairing::PairingOutput;
use ark_ec::short_weierstrass::Affine;
use ark_ec::{AdditiveGroup as Group, CurveGroup, VariableBaseMSM};
use ark_ff::{BigInt, Field, MontFp, Zero};
use ark_poly::univariate::DensePolynomial;
use core::fmt;
use core::ops::{Add, AddAssign, Div, Mul, Neg, Sub, SubAssign};
use serde::{Deserialize, Serialize};
use tfhe_versionable::NotVersioned;

use crate::serialization::{SerializableAffine, SerializableFp, SerializableFp12, SerializableFp2};

struct MontIntDisplay<'a, T>(&'a T);

impl<T: fmt::Display + PartialEq + Field> fmt::Debug for MontIntDisplay<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if *self.0 == T::ZERO {
            f.write_str("0")
        } else {
            f.write_fmt(format_args!("{}", self.0))
        }
    }
}

pub mod msm;

pub mod bls12_381;
pub mod bls12_446;

pub trait FieldOps:
    Copy
    + Send
    + Sync
    + core::fmt::Debug
    + core::ops::AddAssign<Self>
    + core::ops::SubAssign<Self>
    + core::ops::Add<Self, Output = Self>
    + core::ops::Sub<Self, Output = Self>
    + core::ops::Mul<Self, Output = Self>
    + core::ops::Div<Self, Output = Self>
    + core::ops::Neg<Output = Self>
    + core::iter::Sum
{
    const ZERO: Self;
    const ONE: Self;

    fn from_u128(n: u128) -> Self;
    fn from_u64(n: u64) -> Self;
    fn from_i64(n: i64) -> Self;
    fn to_le_bytes(self) -> impl AsRef<[u8]>;
    fn rand(rng: &mut impl rand::RngExt) -> Self;
    fn hash(values: &mut [Self], data: &[&[u8]]);
    fn hash_128bit(values: &mut [Self], data: &[&[u8]]);
    fn poly_mul(p: &[Self], q: &[Self]) -> Vec<Self>;
    fn poly_sub(p: &[Self], q: &[Self]) -> Vec<Self> {
        use core::iter::zip;
        let mut out = vec![Self::ZERO; Ord::max(p.len(), q.len())];

        for (out, (p, q)) in zip(
            &mut out,
            zip(
                p.iter().copied().chain(core::iter::repeat(Self::ZERO)),
                q.iter().copied().chain(core::iter::repeat(Self::ZERO)),
            ),
        ) {
            *out = p - q;
        }

        out
    }
    fn poly_add(p: &[Self], q: &[Self]) -> Vec<Self> {
        use core::iter::zip;
        let mut out = vec![Self::ZERO; Ord::max(p.len(), q.len())];

        for (out, (p, q)) in zip(
            &mut out,
            zip(
                p.iter().copied().chain(core::iter::repeat(Self::ZERO)),
                q.iter().copied().chain(core::iter::repeat(Self::ZERO)),
            ),
        ) {
            *out = p + q;
        }

        out
    }
}

pub trait CurveGroupOps<Zp>:
    Copy
    + Send
    + Sync
    + core::fmt::Debug
    + core::ops::AddAssign<Self>
    + core::ops::SubAssign<Self>
    + core::ops::Add<Self, Output = Self>
    + core::ops::Sub<Self, Output = Self>
    + core::ops::Neg<Output = Self>
    + core::iter::Sum
    + PartialEq
{
    const ZERO: Self;
    const GENERATOR: Self;
    const BYTE_SIZE: usize;

    type Affine: Copy
        + Send
        + Sync
        + core::fmt::Debug
        + serde::Serialize
        + for<'de> serde::Deserialize<'de>;

    fn projective(affine: Self::Affine) -> Self;

    fn mul_scalar(self, scalar: Zp) -> Self;
    fn multi_mul_scalar(bases: &[Self::Affine], scalars: &[Zp]) -> Self;
    fn to_le_bytes(self) -> impl AsRef<[u8]>;
    fn double(self) -> Self;
    fn normalize(self) -> Self::Affine;
    fn validate_projective(&self) -> bool {
        Self::validate_affine(&self.normalize())
    }
    fn validate_affine(affine: &Self::Affine) -> bool;
}

/// Mark that an element can be compressed, by storing only the 'x' coordinates of the affine
/// representation and getting the 'y' from the curve.
pub trait Compressible: Sized {
    type Compressed;
    type UncompressError;

    fn compress(&self) -> Self::Compressed;
    fn uncompress(compressed: Self::Compressed) -> Result<Self, Self::UncompressError>;
}

pub type CompressedG1<G> = <<G as Curve>::G1 as Compressible>::Compressed;
pub type CompressedG2<G> = <<G as Curve>::G2 as Compressible>::Compressed;

pub trait PairingGroupOps<Zp, G1, G2>:
    Copy
    + Send
    + Sync
    + PartialEq
    + core::fmt::Debug
    + core::ops::AddAssign<Self>
    + core::ops::SubAssign<Self>
    + core::ops::Add<Self, Output = Self>
    + core::ops::Sub<Self, Output = Self>
    + core::ops::Neg<Output = Self>
{
    fn mul_scalar(self, scalar: Zp) -> Self;
    fn pairing(x: G1, y: G2) -> Self;
}

pub trait Curve: Clone {
    type Zp: FieldOps;
    type G1: CurveGroupOps<Self::Zp>;
    type G2: CurveGroupOps<Self::Zp>;
    type Gt: PairingGroupOps<Self::Zp, Self::G1, Self::G2>;
}

impl FieldOps for bls12_381::Zp {
    const ZERO: Self = Self::ZERO;
    const ONE: Self = Self::ONE;

    fn from_u128(n: u128) -> Self {
        Self::from_bigint([n as u64, (n >> 64) as u64, 0, 0])
    }
    fn from_u64(n: u64) -> Self {
        Self::from_u64(n)
    }
    fn from_i64(n: i64) -> Self {
        Self::from_i64(n)
    }
    fn to_le_bytes(self) -> impl AsRef<[u8]> {
        self.to_le_bytes()
    }
    fn rand(rng: &mut impl rand::RngExt) -> Self {
        Self::rand(rng)
    }
    fn hash(values: &mut [Self], data: &[&[u8]]) {
        Self::hash(values, data)
    }
    fn hash_128bit(values: &mut [Self], data: &[&[u8]]) {
        Self::hash_128bit(values, data)
    }

    fn poly_mul(p: &[Self], q: &[Self]) -> Vec<Self> {
        let p = p.iter().map(|x| x.inner).collect();
        let q = q.iter().map(|x| x.inner).collect();
        let p = DensePolynomial { coeffs: p };
        let q = DensePolynomial { coeffs: q };
        (&p * &q)
            .coeffs
            .into_iter()
            .map(|inner| bls12_381::Zp { inner })
            .collect()
    }
}

impl CurveGroupOps<bls12_381::Zp> for bls12_381::G1 {
    const ZERO: Self = Self::ZERO;
    const GENERATOR: Self = Self::GENERATOR;
    const BYTE_SIZE: usize = Self::BYTE_SIZE;
    type Affine = bls12_381::G1Affine;

    fn projective(affine: Self::Affine) -> Self {
        Self {
            inner: affine.inner.into(),
        }
    }

    fn mul_scalar(self, scalar: bls12_381::Zp) -> Self {
        if scalar.inner == MontFp!("2") {
            self.double()
        } else {
            self.mul_scalar(scalar)
        }
    }

    #[track_caller]
    fn multi_mul_scalar(bases: &[Self::Affine], scalars: &[bls12_381::Zp]) -> Self {
        Self::Affine::multi_mul_scalar(bases, scalars)
    }

    fn to_le_bytes(self) -> impl AsRef<[u8]> {
        self.to_le_bytes()
    }

    fn double(self) -> Self {
        self.double()
    }

    fn normalize(self) -> Self::Affine {
        Self::Affine {
            inner: self.inner.into_affine(),
        }
    }

    fn validate_affine(affine: &Self::Affine) -> bool {
        affine.validate()
    }
}

impl CurveGroupOps<bls12_381::Zp> for bls12_381::G2 {
    const ZERO: Self = Self::ZERO;
    const GENERATOR: Self = Self::GENERATOR;
    const BYTE_SIZE: usize = Self::BYTE_SIZE;
    type Affine = bls12_381::G2Affine;

    fn projective(affine: Self::Affine) -> Self {
        Self {
            inner: affine.inner.into(),
        }
    }

    fn mul_scalar(self, scalar: bls12_381::Zp) -> Self {
        if scalar.inner == MontFp!("2") {
            self.double()
        } else {
            self.mul_scalar(scalar)
        }
    }

    #[track_caller]
    fn multi_mul_scalar(bases: &[Self::Affine], scalars: &[bls12_381::Zp]) -> Self {
        Self::Affine::multi_mul_scalar(bases, scalars)
    }

    fn to_le_bytes(self) -> impl AsRef<[u8]> {
        self.to_le_bytes()
    }

    fn double(self) -> Self {
        self.double()
    }

    fn normalize(self) -> Self::Affine {
        Self::Affine {
            inner: self.inner.into_affine(),
        }
    }

    fn validate_affine(affine: &Self::Affine) -> bool {
        affine.validate()
    }
}

impl PairingGroupOps<bls12_381::Zp, bls12_381::G1, bls12_381::G2> for bls12_381::Gt {
    fn mul_scalar(self, scalar: bls12_381::Zp) -> Self {
        self.mul_scalar(scalar)
    }

    fn pairing(x: bls12_381::G1, y: bls12_381::G2) -> Self {
        if x == bls12_381::G1::ZERO || y == bls12_381::G2::ZERO {
            return Self::pairing(bls12_381::G1::ZERO, bls12_381::G2::GENERATOR);
        }
        Self::pairing(x, y)
    }
}

impl FieldOps for bls12_446::Zp {
    const ZERO: Self = Self::ZERO;
    const ONE: Self = Self::ONE;

    fn from_u128(n: u128) -> Self {
        Self::from_bigint([n as u64, (n >> 64) as u64, 0, 0, 0])
    }
    fn from_u64(n: u64) -> Self {
        Self::from_u64(n)
    }
    fn from_i64(n: i64) -> Self {
        Self::from_i64(n)
    }
    fn to_le_bytes(self) -> impl AsRef<[u8]> {
        self.to_le_bytes()
    }
    fn rand(rng: &mut impl rand::RngExt) -> Self {
        Self::rand(rng)
    }
    fn hash(values: &mut [Self], data: &[&[u8]]) {
        Self::hash(values, data)
    }
    fn hash_128bit(values: &mut [Self], data: &[&[u8]]) {
        Self::hash_128bit(values, data)
    }

    fn poly_mul(p: &[Self], q: &[Self]) -> Vec<Self> {
        let p = p.iter().map(|x| x.inner).collect();
        let q = q.iter().map(|x| x.inner).collect();
        let p = DensePolynomial { coeffs: p };
        let q = DensePolynomial { coeffs: q };
        (&p * &q)
            .coeffs
            .into_iter()
            .map(|inner| bls12_446::Zp { inner })
            .collect()
    }
}

impl CurveGroupOps<bls12_446::Zp> for bls12_446::G1 {
    const ZERO: Self = Self::ZERO;
    const GENERATOR: Self = Self::GENERATOR;
    const BYTE_SIZE: usize = Self::BYTE_SIZE;
    type Affine = bls12_446::G1Affine;

    fn projective(affine: Self::Affine) -> Self {
        Self {
            inner: affine.inner.into(),
        }
    }

    fn mul_scalar(self, scalar: bls12_446::Zp) -> Self {
        if scalar.inner == MontFp!("2") {
            self.double()
        } else {
            self.mul_scalar(scalar)
        }
    }

    #[track_caller]
    fn multi_mul_scalar(bases: &[Self::Affine], scalars: &[bls12_446::Zp]) -> Self {
        // overhead seems to not be worth it outside of wasm
        if cfg!(target_family = "wasm") {
            msm::msm_wnaf_g1_446(bases, scalars)
        } else {
            Self::Affine::multi_mul_scalar(bases, scalars)
        }
    }

    fn to_le_bytes(self) -> impl AsRef<[u8]> {
        self.to_le_bytes()
    }

    fn double(self) -> Self {
        self.double()
    }

    fn normalize(self) -> Self::Affine {
        Self::Affine {
            inner: self.inner.into_affine(),
        }
    }

    fn validate_affine(affine: &Self::Affine) -> bool {
        affine.validate()
    }
}

impl CurveGroupOps<bls12_446::Zp> for bls12_446::G2 {
    const ZERO: Self = Self::ZERO;
    const GENERATOR: Self = Self::GENERATOR;
    const BYTE_SIZE: usize = Self::BYTE_SIZE;
    type Affine = bls12_446::G2Affine;

    fn projective(affine: Self::Affine) -> Self {
        Self {
            inner: affine.inner.into(),
        }
    }

    fn mul_scalar(self, scalar: bls12_446::Zp) -> Self {
        if scalar.inner == MontFp!("2") {
            self.double()
        } else {
            self.mul_scalar(scalar)
        }
    }

    #[track_caller]
    fn multi_mul_scalar(bases: &[Self::Affine], scalars: &[bls12_446::Zp]) -> Self {
        Self::Affine::multi_mul_scalar(bases, scalars)
    }

    fn to_le_bytes(self) -> impl AsRef<[u8]> {
        self.to_le_bytes()
    }

    fn double(self) -> Self {
        self.double()
    }

    fn normalize(self) -> Self::Affine {
        Self::Affine {
            inner: self.inner.into_affine(),
        }
    }

    fn validate_affine(affine: &Self::Affine) -> bool {
        affine.validate()
    }
}

impl PairingGroupOps<bls12_446::Zp, bls12_446::G1, bls12_446::G2> for bls12_446::Gt {
    fn mul_scalar(self, scalar: bls12_446::Zp) -> Self {
        self.mul_scalar(scalar)
    }

    fn pairing(x: bls12_446::G1, y: bls12_446::G2) -> Self {
        if x == bls12_446::G1::ZERO || y == bls12_446::G2::ZERO {
            return Self::pairing(bls12_446::G1::ZERO, bls12_446::G2::GENERATOR);
        }
        Self::pairing(x, y)
    }
}

// These are just ZSTs that are not actually produced and are only used for their
// associated types. So it's ok to derive "NotVersioned" for them.
#[derive(Debug, Copy, Clone, serde::Serialize, serde::Deserialize, NotVersioned)]
pub struct Bls12_381;
#[derive(Debug, Copy, Clone, serde::Serialize, serde::Deserialize, NotVersioned)]
pub struct Bls12_446;

impl Curve for Bls12_381 {
    type Zp = bls12_381::Zp;
    type G1 = bls12_381::G1;
    type G2 = bls12_381::G2;
    type Gt = bls12_381::Gt;
}
impl Curve for Bls12_446 {
    type Zp = bls12_446::Zp;
    type G1 = bls12_446::G1;
    type G2 = bls12_446::G2;
    type Gt = bls12_446::Gt;
}
