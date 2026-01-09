use std::marker::PhantomData;
use tfhe::named::Named;
use tfhe::{FheIntegerType, FheUintId, IntegerId};

pub trait TypeDisplay {
    fn fmt(f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = std::any::type_name::<Self>();
        let pos = name.rfind(":").map_or(0, |p| p + 1);
        write!(f, "{}", &name[pos..])
    }
}

impl TypeDisplay for u8 {}
impl TypeDisplay for u16 {}
impl TypeDisplay for u32 {}
impl TypeDisplay for u64 {}
impl TypeDisplay for u128 {}

impl TypeDisplay for i8 {}
impl TypeDisplay for i16 {}
impl TypeDisplay for i32 {}
impl TypeDisplay for i64 {}
impl TypeDisplay for i128 {}

impl<Id: FheUintId> TypeDisplay for tfhe::FheUint<Id> {
    fn fmt(f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write_fhe_type_name::<Self>(f)
    }
}

impl<Id: tfhe::FheIntId> TypeDisplay for tfhe::FheInt<Id> {
    fn fmt(f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write_fhe_type_name::<Self>(f)
    }
}

pub struct TypeDisplayer<T: TypeDisplay>(PhantomData<T>);

impl<T: TypeDisplay> Default for TypeDisplayer<T> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<T: TypeDisplay> std::fmt::Display for TypeDisplayer<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        T::fmt(f)
    }
}

fn write_fhe_type_name<'a, FheType>(f: &mut std::fmt::Formatter<'a>) -> std::fmt::Result
where
    FheType: FheIntegerType + Named,
{
    let full_name = FheType::NAME;
    let i = full_name.rfind(":").map_or(0, |p| p + 1);

    write!(f, "{}{}", &full_name[i..], FheType::Id::num_bits())
}
