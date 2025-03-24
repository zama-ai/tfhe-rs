expand_pub_use_fhe_type!(
    pub use unsigned{
        FheUint2, FheUint4, FheUint6, FheUint8, FheUint10, FheUint12, FheUint14, FheUint16,
        FheUint32, FheUint64, FheUint128, FheUint160, FheUint256, FheUint512, FheUint1024,
        FheUint2048,
    };
);
#[cfg(feature = "extended-types")]
expand_pub_use_fhe_type!(
    pub use unsigned{
        FheUint24, FheUint40, FheUint48, FheUint56, FheUint72, FheUint80,FheUint88, FheUint96,
        FheUint104, FheUint112, FheUint120, FheUint136, FheUint144, FheUint152, FheUint168,
        FheUint176, FheUint184, FheUint192, FheUint200, FheUint208, FheUint216, FheUint224,
        FheUint232, FheUint240, FheUint248,
    };
);

expand_pub_use_fhe_type!(
    pub use signed{
        FheInt2, FheInt4, FheInt6, FheInt8, FheInt10, FheInt12, FheInt14, FheInt16, FheInt32,
        FheInt64, FheInt128, FheInt160, FheInt256, FheInt512, FheInt1024, FheInt2048,
    };
);
#[cfg(feature = "extended-types")]
expand_pub_use_fhe_type!(
    pub use signed{
        FheInt24, FheInt40, FheInt48, FheInt56, FheInt72, FheInt80, FheInt88, FheInt96, FheInt104,
        FheInt112, FheInt120, FheInt136, FheInt144, FheInt152, FheInt168, FheInt176, FheInt184,
        FheInt192, FheInt200, FheInt208, FheInt216, FheInt224, FheInt232, FheInt240, FheInt248,
    };
);

pub(in crate::high_level_api) use signed::{
    CompressedSignedRadixCiphertext, FheIntId, InnerSquashedNoiseSignedRadixCiphertextVersionOwned,
    SignedRadixCiphertextVersionOwned,
};
pub(in crate::high_level_api) use unsigned::{
    CompressedRadixCiphertext, FheUintId, InnerSquashedNoiseRadixCiphertextVersionOwned,
    RadixCiphertextVersionOwned as UnsignedRadixCiphertextVersionOwned,
};
// These are pub-exported so that their doc can appear in generated rust docs
use crate::high_level_api::traits::FheId;
use crate::shortint::MessageModulus;
pub use signed::{CompressedFheInt, FheInt, SquashedNoiseFheInt};
pub use unsigned::{CompressedFheUint, FheUint, SquashedNoiseFheUint};

pub mod oprf;
pub(super) mod signed;
pub(super) mod unsigned;

/// Trait to mark ID type for integers
// The 'static restrains implementor from holding non-static refs
// which is ok as it is meant to be impld by zero sized types.
pub trait IntegerId: FheId + 'static {
    fn num_bits() -> usize;

    fn num_blocks(message_modulus: MessageModulus) -> usize {
        Self::num_bits() / message_modulus.0.ilog2() as usize
    }
}
