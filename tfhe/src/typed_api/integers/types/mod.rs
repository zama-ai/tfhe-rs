pub use base::GenericInteger;
pub use static_::{
    CompressedFheUint10, CompressedFheUint12, CompressedFheUint14, CompressedFheUint16,
    CompressedFheUint256, CompressedFheUint8, FheUint10, FheUint12, FheUint14, FheUint16,
    FheUint256, FheUint8,
};

pub(super) mod base;
pub(super) mod compressed;
pub(super) mod static_;
