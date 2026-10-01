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

use crate::prelude::Tagged;
use crate::ReRandomizationMetadata;
pub(in crate::high_level_api) use signed::{
    CompressedSignedRadixCiphertext, InnerSquashedNoiseSignedRadixCiphertextVersionOwned,
    SignedRadixCiphertextVersionOwned,
};
pub(in crate::high_level_api) use unsigned::{
    CompressedRadixCiphertext, InnerSquashedNoiseRadixCiphertextVersionOwned,
    RadixCiphertextVersionOwned as UnsignedRadixCiphertextVersionOwned,
};
// These are pub-exported so that their doc can appear in generated rust docs
use crate::high_level_api::details::MaybeCloned;
use crate::high_level_api::traits::FheId;
use crate::shortint::MessageModulus;
use crate::Tag;
pub use signed::{CompressedFheInt, FheInt, FheIntId, SquashedNoiseFheInt};
pub use unsigned::{CompressedFheUint, FheUint, FheUintId, SquashedNoiseFheUint};

pub mod oprf;
pub mod shuffle;
pub(super) mod signed;
pub(super) mod unsigned;

/// Trait to mark ID type for integers
// The 'static restrains implementor from holding non-static refs
// which is ok as it is meant to be impld by zero sized types.
pub trait IntegerId: FheId + 'static {
    type InnerCpu: crate::integer::IntegerRadixCiphertext;

    #[cfg(feature = "gpu")]
    type InnerGpu: crate::integer::gpu::ciphertext::CudaIntegerRadixCiphertext;
    #[cfg(not(feature = "gpu"))]
    type InnerGpu;

    type InnerHpu;

    fn num_bits() -> usize;

    fn num_blocks(message_modulus: MessageModulus) -> usize {
        Self::num_bits().div_ceil(message_modulus.0.ilog2() as usize)
    }
}

mod private {
    pub trait Sealed {}

    impl<Id> Sealed for crate::high_level_api::FheUint<Id> where Id: super::FheUintId {}

    impl<Id> Sealed for crate::high_level_api::FheInt<Id> where Id: super::FheIntId {}
}

/// Narrows a clear shift amount to a `u64`, saturating at the ciphertext's bit width.
pub(crate) fn saturated_scalar_shift_amount<FheType, Scalar>(_lhs: &FheType, rhs: Scalar) -> u64
where
    FheType: FheIntegerType,
    Scalar: crate::core_crypto::prelude::CastFrom<u64> + PartialEq + Copy,
    u64: crate::core_crypto::prelude::CastFrom<Scalar>,
{
    use crate::core_crypto::prelude::CastFrom;
    let num_bits = <FheType::Id as IntegerId>::num_bits() as u64;

    let narrowed = u64::cast_from(rhs);
    if Scalar::cast_from(narrowed) == rhs {
        // The amount fits in a u64, compare it with the width there.
        narrowed.min(num_bits)
    } else {
        // The amount does not fit in a u64
        // None of our ciphertext have this (>= u64::MAX) amount of bits
        num_bits
    }
}

/// Narrows a clear rotation amount to a `u64`, reduced modulo the ciphertext's bit width.
///
/// Rotations are cyclic, so no amount is ever "too large".
pub(crate) fn reduced_scalar_rotate_amount<FheType, Scalar>(_lhs: &FheType, rhs: Scalar) -> u64
where
    FheType: FheIntegerType,
    Scalar: crate::core_crypto::prelude::CastFrom<u64>
        + PartialEq
        + Copy
        + std::ops::Rem<Scalar, Output = Scalar>,
    u64: crate::core_crypto::prelude::CastFrom<Scalar>,
{
    use crate::core_crypto::prelude::CastFrom;
    let num_bits = <FheType::Id as IntegerId>::num_bits() as u64;

    let narrowed = u64::cast_from(rhs);
    if Scalar::cast_from(narrowed) == rhs {
        // The amount fits in a u64, reduce it there.
        narrowed % num_bits
    } else {
        // The amount needs more than 64 bits, so `Scalar` is wider than `u64`
        // And as we don't have such large ciphertext (and likely never will)
        // the Scalar::cast_from is safe from truncations
        u64::cast_from(rhs % Scalar::cast_from(num_bits))
    }
}

pub trait FheIntegerType: Tagged + private::Sealed {
    type Id: IntegerId;

    fn on_cpu(&self) -> MaybeCloned<'_, <Self::Id as IntegerId>::InnerCpu>;

    fn into_cpu(self) -> <Self::Id as IntegerId>::InnerCpu;

    fn from_cpu(
        inner: <Self::Id as IntegerId>::InnerCpu,
        tag: Tag,
        re_randomization_metadata: ReRandomizationMetadata,
    ) -> Self;

    #[cfg(feature = "gpu")]
    fn on_gpu(
        &self,
        streams: &crate::core_crypto::gpu::CudaStreams,
    ) -> MaybeCloned<'_, <Self::Id as IntegerId>::InnerGpu>;

    #[cfg(feature = "gpu")]
    fn into_gpu(
        self,
        streams: &crate::core_crypto::gpu::CudaStreams,
    ) -> <Self::Id as IntegerId>::InnerGpu;

    #[cfg(feature = "gpu")]
    fn from_gpu(
        inner: <Self::Id as IntegerId>::InnerGpu,
        tag: Tag,
        re_randomization_metadata: ReRandomizationMetadata,
    ) -> Self;
}
