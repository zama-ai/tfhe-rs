expand_pub_use_fhe_type!(
    pub use unsigned{
        FheUint2, FheUint4, FheUint6, FheUint8, FheUint10, FheUint12, FheUint14, FheUint16,
        FheUint32, FheUint64, FheUint128, FheUint160, FheUint256
    };
);

expand_pub_use_fhe_type!(
    pub use signed{
        FheInt2, FheInt4, FheInt6, FheInt8, FheInt10, FheInt12, FheInt14, FheInt16,
        FheInt32, FheInt64, FheInt128, FheInt160, FheInt256
    };
);

pub(in crate::high_level_api) use signed::{
    CompressedSignedRadixCiphertext, FheIntId,
    RadixCiphertextVersionOwned as SignedRadixCiphertextVersionOwned,
};
pub(in crate::high_level_api) use unsigned::{
    CompressedRadixCiphertext, FheUintId,
    RadixCiphertextVersionOwned as UnsignedRadixCiphertextVersionOwned,
};
// These are pub-exported so that their doc can appear in generated rust docs
use crate::shortint::MessageModulus;
pub use signed::{CompactFheInt, CompactFheIntList, CompressedFheInt, FheInt};
pub use unsigned::{CompactFheUint, CompactFheUintList, CompressedFheUint, FheUint};

pub mod oprf;
mod signed;
mod unsigned;

/// Trait to mark ID type for integers
// The 'static restrains implementor from holding non-static refs
// which is ok as it is meant to be impld by zero sized types.
pub trait IntegerId: Copy + Default + 'static {
    fn num_bits() -> usize;

    fn num_blocks(message_modulus: MessageModulus) -> usize {
        Self::num_bits() / message_modulus.0.ilog2() as usize
    }
}
