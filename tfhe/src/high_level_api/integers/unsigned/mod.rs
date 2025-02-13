pub use base::{FheUint, FheUintId};

expand_pub_use_fhe_type!(
    pub use static_{
        FheUint2, FheUint4, FheUint6, FheUint8, FheUint10, FheUint12, FheUint14, FheUint16,
        FheUint24, FheUint32, FheUint40, FheUint48, FheUint56, FheUint64, FheUint72, FheUint80,
        FheUint88, FheUint96, FheUint104, FheUint112, FheUint120, FheUint128, FheUint136,
        FheUint144, FheUint152, FheUint160, FheUint168, FheUint176, FheUint184, FheUint192,
        FheUint200, FheUint208, FheUint216, FheUint224, FheUint232, FheUint240, FheUint248,
        FheUint256, FheUint512, FheUint1024, FheUint2048,
    };
);

pub use compressed::CompressedFheUint;

pub(in crate::high_level_api) use compressed::CompressedRadixCiphertext;
pub(in crate::high_level_api) use inner::{RadixCiphertext, RadixCiphertextVersionOwned};

mod base;
mod compressed;
mod static_;

mod encrypt;
mod inner;
mod ops;
mod overflowing_ops;
pub(crate) mod scalar_ops;
#[cfg(test)]
pub(crate) mod tests;
