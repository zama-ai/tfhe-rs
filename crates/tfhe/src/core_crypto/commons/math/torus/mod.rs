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
    Gaussian, RandomGenerable, TUniform, Uniform, UniformBinary, UniformTernary,
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
    fn from_torus_custom_mod(input: F, custom_modulus: Self) -> Self;
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
            fn from_torus_custom_mod(input: F, custom_modulus: Self) -> Self {
                // TODO: there is a question around rounded Gaussian vs. discrete Gaussian that
                // warrants a reflection on what the rounding behavior should be for q to scale the
                // Gaussian value to the correct range.
                let custom_modulus_float: F = custom_modulus.cast_into();

                // This is in [-0.5, 0.5[
                // We do not do the mapping to [0, 1[ here as some values can be extremely small
                // (think 2^-127 for u128 and custom power of 2 moduli) and would be crushed by
                // adding 1 to them, creating artificial zeros (not good for noise generation)
                let mut fract = input - F::round(input);
                // Scale to the modulus
                fract *= custom_modulus_float;
                fract = F::round(fract);

                // Cast to signed integer to retain as much information as possible and apply an
                // exact modulus in the integer domain, doing so in the float domain leads to
                // approximations and values that can be out of range for the selected modulus,
                // which is not good (depending on how the values are handled it could result in 0s)
                let signed: Self::Signed = fract.cast_into();
                if signed >= 0 {
                    signed.cast_into()
                } else {
                    // Get the abs value of the signed value we got
                    let unsigned: Self = (-signed).cast_into();
                    // As it was a negative value we subtract it from the modulus to get the proper
                    // representant under our modulus
                    custom_modulus - unsigned
                }
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
    + RandomGenerable<Gaussian<f64>, CustomModulus = Self>
    + RandomGenerable<UniformBinary, CustomModulus = Self>
    + RandomGenerable<UniformTernary, CustomModulus = Self>
    + RandomGenerable<Uniform, CustomModulus = Self>
    + RandomGenerable<TUniform<Self>, CustomModulus = Self>
    + Display
    + Debug
{
}

impl UnsignedTorus for u32 {}

impl UnsignedTorus for u64 {}

impl UnsignedTorus for u128 {}
