expand_pub_use_fhe_type!(
    pub use types{
        FheUint8, FheUint10, FheUint12, FheUint14, FheUint16, FheUint32, FheUint64, FheUint128,
        FheUint256, FheInt8, FheInt16, FheInt32, FheInt64, FheInt128, FheInt256
    };
);

pub(in crate::high_level_api) use keys::{
    IntegerClientKey, IntegerCompactPublicKey, IntegerCompressedCompactPublicKey,
    IntegerCompressedServerKey, IntegerConfig, IntegerServerKey,
};

pub(in crate::high_level_api) use parameters::IntegerId;
pub(in crate::high_level_api) use types::GenericInteger;

mod client_key;
mod keys;
mod parameters;
mod server_key;
#[cfg(test)]
mod tests_signed;
#[cfg(test)]
mod tests_unsigned;
mod types;

#[cfg(feature = "safe-deserialization")]
pub mod safe_serialize {
    use super::parameters::IntegerId;
    use super::types::compact::GenericCompactInteger;
    use super::types::compressed::CompressedGenericInteger;
    use super::types::GenericInteger;
    use crate::conformance::ParameterSetConformant;
    use crate::integer::parameters::RadixCiphertextConformanceParams;
    use crate::named::Named;
    use crate::shortint::parameters::CiphertextConformanceParams;
    use crate::ServerKey;
    use serde::de::DeserializeOwned;
    use serde::Serialize;

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
            + ParameterSetConformant<ParameterSet = CiphertextConformanceParams>,
    {
        let parameter_set = sk.integer_key.pbs_key().key.conformance_params();

        crate::safe_deserialization::safe_deserialize_conformant(
            reader,
            serialized_size_limit,
            &parameter_set,
        )
    }

    pub fn safe_deserialize_conformant_integer<Id>(
        reader: impl std::io::Read,
        serialized_size_limit: u64,
        sk: &ServerKey,
    ) -> Result<GenericInteger<Id>, String>
    where
        Id: IntegerId + DeserializeOwned,
        Id::InnerCiphertext: ParameterSetConformant<ParameterSet = RadixCiphertextConformanceParams>
            + DeserializeOwned,
    {
        let parameter_set = RadixCiphertextConformanceParams {
            shortint_params: sk.integer_key.pbs_key().key.conformance_params(),
            num_blocks_per_integer: Id::num_blocks(),
        };

        crate::safe_deserialization::safe_deserialize_conformant(
            reader,
            serialized_size_limit,
            &parameter_set,
        )
    }

    pub fn safe_deserialize_conformant_compressed_integer<Id>(
        reader: impl std::io::Read,
        serialized_size_limit: u64,
        sk: &ServerKey,
    ) -> Result<CompressedGenericInteger<Id>, String>
    where
        Id: IntegerId + DeserializeOwned,
        Id::InnerCompressedCiphertext: ParameterSetConformant<ParameterSet = RadixCiphertextConformanceParams>
            + DeserializeOwned,
    {
        let parameter_set = RadixCiphertextConformanceParams {
            shortint_params: sk.integer_key.pbs_key().key.conformance_params(),
            num_blocks_per_integer: Id::num_blocks(),
        };

        crate::safe_deserialization::safe_deserialize_conformant(
            reader,
            serialized_size_limit,
            &parameter_set,
        )
    }

    pub fn safe_deserialize_conformant_compact_integer<Id>(
        reader: impl std::io::Read,
        serialized_size_limit: u64,
        sk: &ServerKey,
    ) -> Result<GenericCompactInteger<Id>, String>
    where
        Id: IntegerId + DeserializeOwned,
    {
        let parameter_set = RadixCiphertextConformanceParams {
            shortint_params: sk.integer_key.pbs_key().key.conformance_params(),
            num_blocks_per_integer: Id::num_blocks(),
        };

        crate::safe_deserialization::safe_deserialize_conformant(
            reader,
            serialized_size_limit,
            &parameter_set,
        )
    }
}
