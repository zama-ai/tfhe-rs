mod base;
mod compressed;
mod squashed_noise;

mod encrypt;
mod inner;
mod ops;
mod overflowing_ops;
mod scalar_ops;
mod static_;
#[cfg(test)]
mod tests;

pub use base::{FheInt, FheIntId};
pub use compressed::CompressedFheInt;
pub(in crate::high_level_api) use compressed::CompressedSignedRadixCiphertext;
pub(in crate::high_level_api) use inner::{
    SignedRadixCiphertext, SignedRadixCiphertextVersionOwned,
};
pub use squashed_noise::SquashedNoiseFheInt;
pub(in crate::high_level_api) use squashed_noise::{
    InnerSquashedNoiseSignedRadixCiphertext, InnerSquashedNoiseSignedRadixCiphertextVersionOwned,
};

expand_pub_use_fhe_type!(
    pub use static_{
        FheInt2, FheInt4, FheInt6, FheInt8, FheInt10, FheInt12, FheInt14, FheInt16, FheInt32,
        FheInt64,FheInt128, FheInt160, FheInt256, FheInt512, FheInt1024, FheInt2048
    };
);
#[cfg(feature = "extended-types")]
expand_pub_use_fhe_type!(
    pub use static_{
        FheInt24, FheInt40, FheInt48, FheInt56, FheInt72, FheInt80, FheInt88, FheInt96, FheInt104,
        FheInt112, FheInt120, FheInt136, FheInt144, FheInt152, FheInt168, FheInt176, FheInt184,
        FheInt192, FheInt200, FheInt208, FheInt216, FheInt224, FheInt232, FheInt240, FheInt248
    };
);
