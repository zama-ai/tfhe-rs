//! Generic numeric traits.
//!
//! This module contains types and traits to manipulate numeric types in a generic manner. For
//! instance, in the standard library, the `f32` and `f64` trait share a lot of methods of the
//! same name and same semantics. Still, it is not possible to use them generically. This module
//! provides the [`FloatingPoint`] trait, implemented by both of those type, to remedy the
//! situation.
//!
//! # Note
//!
//! The current implementation of those traits does not strive to be general, in the sense that
//! not all the common methods of the same kind of types are exposed. Only were included the ones
//! that are used in the rest of the library.

pub use float::*;
pub use signed::*;
pub use unsigned::*;

mod float;
mod signed;
mod unsigned;

/// A trait implemented by any generic numeric type suitable for computations.
pub trait Numeric:
    Sized
    + Copy
    + PartialEq
    + PartialOrd
    + CastFrom<Self>
    + bytemuck::Pod
    + std::fmt::Debug
    + Sync
    + Send
    + 'static
{
    /// This size of the type in bits.
    const BITS: usize;

    /// The null element of the type.
    const ZERO: Self;

    /// The identity element of the type.
    const ONE: Self;

    /// A value of two.
    const TWO: Self;

    /// The largest value that can be encoded by the type.
    const MAX: Self;
}

/// A numeric type whose width is a property of the value rather than of the type.
/// i.e the bitwidth is set at runtime, not compile time.
///
/// This is the counterpart of [`Numeric`] for types like the dynamically sized clear integers,
/// which have no `BITS` or `ZERO` constants because their width is only known at runtime.
pub trait DynamicNumeric: Clone + PartialEq + std::fmt::Debug + Send + Sync {
    /// Number of bits of the value (`T::BITS` for fixed width types).
    fn bit_width(&self) -> u32;

    /// The null element, with the given number of bits.
    ///
    /// Fixed width types ignore `bit_width`.
    fn zero_with_width(bit_width: u32) -> Self;

    fn is_zero(&self) -> bool;
}

impl<T: Numeric> DynamicNumeric for T {
    #[inline]
    fn bit_width(&self) -> u32 {
        T::BITS as u32
    }

    #[inline]
    fn zero_with_width(_bit_width: u32) -> Self {
        T::ZERO
    }

    #[inline]
    fn is_zero(&self) -> bool {
        *self == T::ZERO
    }
}

pub trait UnsignedNumeric: Numeric {
    /// The signed type of the same precision
    ///
    /// The name is long and explicit to avoid clash with the
    /// same associated type in [UnsignedInteger]
    type NumericSignedType: SignedNumeric<NumericUnsignedType = Self> + CastFrom<Self>;
}
pub trait SignedNumeric: Numeric {
    /// The unsigned type of the same precision
    ///
    /// The name is long and explicit to avoid clash with the
    /// same associated type in [SignedInteger]
    type NumericUnsignedType: UnsignedNumeric<NumericSignedType = Self> + CastFrom<Self>;
}

/// A trait that allows to generically cast one type from another.
///
/// This type is similar to the [`std::convert::From`] trait, but the conversion between the two
/// types is deferred to the individual `as` casting. If in doubt about the semantics of such a
/// casting, refer to
/// [the rust reference](https://doc.rust-lang.org/reference/expressions/operator-expr.html#type-cast-expressions).
pub trait CastFrom<Input> {
    fn cast_from(input: Input) -> Self;
}

/// A trait that allows to generically cast one type into another.
///
/// This type is similar to the [`std::convert::Into`] trait, but the conversion between the two
/// types is deferred to the individual `as` casting. If in doubt about the semantics of such a
/// casting, refer to
/// [the rust reference](https://doc.rust-lang.org/reference/expressions/operator-expr.html#type-cast-expressions).
pub trait CastInto<Output> {
    fn cast_into(self) -> Output;
}

impl<Input, Output> CastInto<Output> for Input
where
    Output: CastFrom<Input>,
{
    fn cast_into(self) -> Output {
        Output::cast_from(self)
    }
}

macro_rules! implement_cast {
    ($Input:ty, {$($Output:ty),*}) => {
        $(
        impl CastFrom<$Input> for $Output {
            #[inline]
            fn cast_from(input: $Input) -> $Output {
                input as $Output
            }
        }
        )*
    };
    ($Input: ty) => {
        implement_cast!($Input, {f32, f64, usize, u8, u16, u32, u64, u128, isize, i8, i16, i32,
        i64, i128});
    };
    ($($Input: ty),*) => {
        $(
        implement_cast!($Input);
        )*
    }
}

implement_cast!(f32, f64, u8, u16, u32, u64, u128, i8, i16, i32, i64, i128, usize, isize);

impl<Num> CastFrom<bool> for Num
where
    Num: Numeric,
{
    #[inline]
    fn cast_from(input: bool) -> Num {
        if input {
            Num::ONE
        } else {
            Num::ZERO
        }
    }
}

pub trait OverflowingAdd<Rhs> {
    type Output;

    fn overflowing_add(self, other: Rhs) -> (Self::Output, bool);
}
