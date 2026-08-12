use benchmark_spec::{FheType, TypeTag};
use tfhe::FheUintId;

/// The type a benchmark measures, as the spec names it.
///
/// Implementors supply the values only. The spelling belongs to [`FheType`], so
/// that a bench id is written in one place.
pub trait TypeDisplay {
    /// Clear integers are read back from their Rust name, which [`FheType`]
    /// already parses. Ciphertext types override this: their width comes from
    /// their id, not from their name.
    fn fhe_type() -> FheType {
        let name = std::any::type_name::<Self>();
        let short = &name[name.rfind(':').map_or(0, |p| p + 1)..];
        short
            .parse()
            .unwrap_or_else(|e| panic!("{short:?} is not a type the spec knows: {e:?}"))
    }
}

pub trait TypeTagExt: TypeDisplay {
    fn type_tag() -> TypeTag;
}

impl<T: TypeDisplay + ?Sized> TypeTagExt for T {
    fn type_tag() -> TypeTag {
        Self::fhe_type().into()
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
    fn fhe_type() -> FheType {
        FheType::Uint(Id::num_bits() as u32)
    }
}

impl<Id: tfhe::FheIntId> TypeDisplay for tfhe::FheInt<Id> {
    fn fhe_type() -> FheType {
        FheType::Int(Id::num_bits() as u32)
    }
}
