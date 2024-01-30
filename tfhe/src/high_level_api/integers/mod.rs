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

pub(in crate::high_level_api) use signed::FheIntId;
pub(in crate::high_level_api) use unsigned::FheUintId;
// These are pub-exported so that their doc can appear in generated rust docs
use crate::shortint::MessageModulus;
pub use signed::{CompactFheInt, CompactFheIntList, CompressedFheInt, FheInt};
pub use unsigned::{CompactFheUint, CompactFheUintList, CompressedFheUint, FheUint};

pub mod oprf;
mod signed;
mod unsigned;

/// Trait to mark Id type for integers
// The 'static restrains implementor from holding non static refs
// which is ok as it is meant to be impld by zero sized types.
pub trait IntegerId: Copy + Default + 'static {
    fn num_bits() -> usize;

    fn num_blocks(message_modulus: MessageModulus) -> usize {
        Self::num_bits() / message_modulus.0.ilog2() as usize
    }
}

pub mod safe_serialize {
    use super::signed::{CompactFheInt, CompressedFheInt};
    use super::unsigned::{CompactFheUint, CompressedFheUint, FheUint};
    use super::FheUintId;
    use crate::conformance::ParameterSetConformant;
    use crate::high_level_api::integers::{FheInt, FheIntId};
    use crate::integer::parameters::RadixCiphertextConformanceParams;
    use crate::named::Named;
    use crate::shortint::MessageModulus;
    use crate::{CompactFheBool, CompressedFheBool, FheBool, ServerKey};
    use serde::de::DeserializeOwned;
    use serde::Serialize;

    pub trait ExpectedNumBlocks {
        fn expected_num_blocks(message_modulus: MessageModulus) -> usize;
    }

    impl ExpectedNumBlocks for FheBool {
        fn expected_num_blocks(_message_modulus: MessageModulus) -> usize {
            1
        }
    }

    impl ExpectedNumBlocks for CompressedFheBool {
        fn expected_num_blocks(_message_modulus: MessageModulus) -> usize {
            1
        }
    }

    impl ExpectedNumBlocks for CompactFheBool {
        fn expected_num_blocks(_message_modulus: MessageModulus) -> usize {
            1
        }
    }

    impl<Id: FheUintId> ExpectedNumBlocks for FheUint<Id> {
        fn expected_num_blocks(message_modulus: MessageModulus) -> usize {
            Id::num_blocks(message_modulus)
        }
    }

    impl<Id: FheUintId> ExpectedNumBlocks for CompressedFheUint<Id> {
        fn expected_num_blocks(message_modulus: MessageModulus) -> usize {
            Id::num_blocks(message_modulus)
        }
    }

    impl<Id: FheUintId> ExpectedNumBlocks for CompactFheUint<Id> {
        fn expected_num_blocks(message_modulus: MessageModulus) -> usize {
            Id::num_blocks(message_modulus)
        }
    }

    impl<Id: FheIntId> ExpectedNumBlocks for FheInt<Id> {
        fn expected_num_blocks(message_modulus: MessageModulus) -> usize {
            Id::num_blocks(message_modulus)
        }
    }

    impl<Id: FheIntId> ExpectedNumBlocks for CompressedFheInt<Id> {
        fn expected_num_blocks(message_modulus: MessageModulus) -> usize {
            Id::num_blocks(message_modulus)
        }
    }

    impl<Id: FheIntId> ExpectedNumBlocks for CompactFheInt<Id> {
        fn expected_num_blocks(message_modulus: MessageModulus) -> usize {
            Id::num_blocks(message_modulus)
        }
    }

    pub fn safe_serialize<T>(
        a: &T,
        writer: impl std::io::Write,
        serialized_size_limit: u64,
    ) -> Result<(), String>
    where
        T: Named + Serialize,
    {
        crate::safe_deserialization::safe_serialize(a, writer, serialized_size_limit)
            .map_err(|err| err.to_string())
    }
    pub fn safe_deserialize_conformant<T>(
        reader: impl std::io::Read,
        serialized_size_limit: u64,
        sk: &ServerKey,
    ) -> Result<T, String>
    where
        T: Named
            + DeserializeOwned
            + ParameterSetConformant<ParameterSet = RadixCiphertextConformanceParams>
            + ExpectedNumBlocks,
    {
        let parameter_set = RadixCiphertextConformanceParams {
            shortint_params: sk.key.pbs_key().key.conformance_params(),
            num_blocks_per_integer: T::expected_num_blocks(sk.key.message_modulus()),
        };

        crate::safe_deserialization::safe_deserialize_conformant(
            reader,
            serialized_size_limit,
            &parameter_set,
        )
    }
}
