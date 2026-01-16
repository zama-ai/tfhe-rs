pub trait NumConsts {
    fn zero() -> Self;
    fn one() -> Self;
}

macro_rules! impl_numconsts_for_ints {
    ($($t:ty),* $(,)?) => {
        $(impl NumConsts for $t {
            fn zero() -> Self { 0 }
            fn one() -> Self { 1 }
        })*
    };
}

impl_numconsts_for_ints!(u8, u16, u32, u64, u128, i8, i16, i32, i64, i128);
