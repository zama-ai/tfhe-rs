#[cfg(feature = "boolean")]
pub mod boolean;
pub mod core_crypto;
#[cfg(feature = "integer")]
pub mod high_level_api;
#[cfg(feature = "integer")]
pub mod integer;
#[cfg(feature = "shortint")]
pub mod shortint;

pub trait ConvertFrom<T>: Sized {
    fn convert_from(value: T) -> Self;
}

pub trait ConvertInto<T>: Sized {
    fn convert_into(self) -> T;
}

impl<T, U> ConvertInto<U> for T
where
    U: ConvertFrom<T>,
{
    #[inline]
    fn convert_into(self) -> U {
        U::convert_from(self)
    }
}

macro_rules! impl_for_native_type {
    ($($Type: ty),* $(,)?) => {
        $(
            impl ConvertFrom<$Type> for $Type {
                #[inline(always)]
                fn convert_from(value: $Type) -> Self {
                    value
                }
            }
        )*
    };
}

// The blanket implementation for ConvertFrom<T> for T was causing issues, so the trait is
// implemented "manually" for basic types to make our lives easier
impl_for_native_type!(
    bool, u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize, f32, f64
);
