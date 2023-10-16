//! Converting to torus values.
//!
//! The theory behind some of the homomorphic operators of the library, uses the real torus
//! $\mathbb{T} = \mathbb{R} / \mathbb{Z}$, or the set or real numbers modulo 1 (elements of the
//! torus are in $[0,1)$). In practice, floating-point number are not well suited to performing
//! operations on the torus, and we prefer to use unsigned integer values to represent them.
//! Indeed, unsigned integer can be used to encode the decimal part of the torus element with a
//! fixed precision.
//!
//! Still, in some cases, we may need to represent an unsigned integer as a torus value in
//! floating point representation. For this reason we provide the [`IntoTorus`] and [`FromTorus`]
//! traits which allow to go back and forth between an unsigned integer representation and a
//! floating point representation.

use crate::core_crypto::commons::math::random::{
    Gaussian, RandomGenerable, Uniform, UniformBinary, UniformTernary,
};
pub use crate::core_crypto::commons::numeric::{CastInto, FloatingPoint, Numeric, UnsignedInteger};
use std::fmt::{Debug, Display};

/// A trait that converts a torus element in unsigned integer representation to the closest
/// torus element in floating point representation.
pub trait IntoTorus<F>: Sized
where
    F: FloatingPoint,
    Self: UnsignedInteger,
{
    /// Consume `self` and returns its closest floating point representation.
    fn into_torus(self) -> F;
    /// Consume `self` and returns its closest floating point representation for a given modulus.
    fn into_torus_custom_mod(self, custom_modulus: Self) -> F;
}

/// A trait that converts a torus element in floating point representation into the closest torus
/// element in unsigned integer representation.
pub trait FromTorus<F>: Sized
where
    F: FloatingPoint,
    Self: UnsignedInteger,
{
    /// Consume `input` and returns its closest unsigned integer representation.
    fn from_torus(input: F) -> Self;
    /// Consume `input` and returns its closest unsigned integer representation for a given modulus.
    ///
    /// It is the caller's reponsibility to provide a custom_modulus that is a safe approximation of
    /// the integer modulus they want to use in the floating point domain.
    ///
    /// If the approximate floating point modulus is too big then some values will be out of the
    /// proper range for the given integer modulus.
    fn from_torus_custom_modulus(input: F, custom_modulus: F) -> Self;
}

macro_rules! implement {
    ($Type: tt) => {
        impl<F> IntoTorus<F> for $Type
        where
            F: FloatingPoint + CastInto<Self>,
            Self: CastInto<F>,
        {
            #[inline]
            fn into_torus(self) -> F {
                let self_f: F = self.cast_into();
                return self_f * (F::TWO.powi(-(<Self as Numeric>::BITS as i32)));
            }
            #[inline]
            fn into_torus_custom_mod(self, custom_modulus: Self) -> F {
                let self_f: F = self.cast_into();
                let custom_modulus_f: F = custom_modulus.cast_into();
                return self_f / custom_modulus_f;
            }
        }
        impl<F> FromTorus<F> for $Type
        where
            F: FloatingPoint + CastInto<Self> + CastInto<Self::Signed>,
            Self: CastInto<F>,
        {
            #[inline]
            fn from_torus(input: F) -> Self {
                let mut fract = input - F::round(input);
                fract *= F::TWO.powi(<Self as Numeric>::BITS as i32);
                fract = F::round(fract);
                let signed: Self::Signed = fract.cast_into();
                return signed.cast_into();
            }
            #[inline]
            // WARNING from documentation reproduced here
            // It is the caller's reponsibility to provide a custom_modulus that is a safe
            // approximation of the integer modulus they want to use in the floating point
            // domain.
            //
            // If the approximate floating point modulus is too big then some values will be out of
            // the proper range for the given integer modulus.
            fn from_torus_custom_modulus(input: F, custom_modulus: F) -> Self {
                // This is in [-0.5, 0.5[
                let mut fract = input - F::round(input);
                // Scale to the modulus
                fract *= custom_modulus;
                // This allows to map the negative part of the [-0.5, 0.5[ torus to the upper part
                // of the [0, 1[ torus in a single operation.
                // Also this is better done here to avoid epsilon issues as input can be very very
                // small (i.e. if input is very small adding 1.0 to input to map it to the positive
                // values would always produce 1.0, and therefore a noise of 0.0 if this value is
                // used for noise generation, big yikes)
                fract = F::round(fract).rem_euclid(custom_modulus);
                return fract.cast_into();
            }
        }
    };
}

implement!(u8);
implement!(u16);
implement!(u32);
implement!(u64);
implement!(u128);

/// A marker trait for unsigned integer types that can be used in ciphertexts, keys etc.
pub trait UnsignedTorus:
    UnsignedInteger
    + FromTorus<f64>
    + IntoTorus<f64>
    + RandomGenerable<Gaussian<f64>, CustomModulus = f64>
    + RandomGenerable<UniformBinary, CustomModulus = Self>
    + RandomGenerable<UniformTernary, CustomModulus = Self>
    + RandomGenerable<Uniform, CustomModulus = Self>
    + Display
    + Debug
{
}

impl UnsignedTorus for u32 {}

impl UnsignedTorus for u64 {}

impl UnsignedTorus for u128 {}
