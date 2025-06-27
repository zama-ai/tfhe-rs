pub use base::{FheUint, FheUintId};

expand_pub_use_fhe_type!(
    pub use static_{
        FheUint2, FheUint4, FheUint6, FheUint8, FheUint10, FheUint12, FheUint14, FheUint16,
        FheUint32, FheUint64, FheUint128, FheUint160, FheUint256, FheUint512, FheUint1024,
        FheUint2048,
    };
);
#[cfg(feature = "extended-types")]
expand_pub_use_fhe_type!(
    pub use static_{
        FheUint24, FheUint40, FheUint48, FheUint56, FheUint72, FheUint80, FheUint88, FheUint96,
        FheUint104, FheUint112, FheUint120, FheUint136, FheUint144, FheUint152, FheUint168,
        FheUint176, FheUint184, FheUint192, FheUint200, FheUint208, FheUint216, FheUint224,
        FheUint232, FheUint240, FheUint248,
    };
);

pub use compressed::CompressedFheUint;
pub use squashed_noise::SquashedNoiseFheUint;

pub(in crate::high_level_api) use compressed::CompressedRadixCiphertext;
pub(in crate::high_level_api) use inner::{RadixCiphertext, RadixCiphertextVersionOwned};
pub(in crate::high_level_api) use squashed_noise::{
    InnerSquashedNoiseRadixCiphertext, InnerSquashedNoiseRadixCiphertextVersionOwned,
};

mod base;
mod compressed;
mod squashed_noise;
mod static_;

mod encrypt;
mod inner;
mod ops;
mod overflowing_ops;
pub(crate) mod scalar_ops;
#[cfg(test)]
pub(crate) mod tests;
