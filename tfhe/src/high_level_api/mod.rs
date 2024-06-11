#![allow(unused_doc_comments)]

// internal helper macro to make it easier to `pub use`
// all necessary stuff tied to a FheUint/FheInt from the given `module_path`.
#[allow(unused)]
macro_rules! expand_pub_use_fhe_type(
    (
        pub use $module_path:path { $($fhe_type_name:ident),* $(,)? };
    )=> {

        ::paste::paste! {
            pub use $module_path::{
                $(
                    $fhe_type_name,
                    [<Compressed $fhe_type_name>],
                    [<$fhe_type_name Id>],

                    // ConformanceParams
                    [<$fhe_type_name ConformanceParams>],
                )*
            };
        }
    }
);

pub use crate::core_crypto::commons::math::random::Seed;
pub use crate::integer::oprf::SignedRandomizationSpec;
pub use config::{Config, ConfigBuilder};
pub use global_state::{set_server_key, unset_server_key, with_server_key_as_context};

pub use integers::{CompressedFheInt, CompressedFheUint, FheInt, FheUint, IntegerId};
#[cfg(feature = "gpu")]
pub use keys::CudaServerKey;
pub use keys::{
    generate_keys, ClientKey, CompactPublicKey, CompressedCompactPublicKey, CompressedPublicKey,
    CompressedServerKey, KeySwitchingKey, PublicKey, ServerKey,
};

#[cfg(test)]
mod tests;

pub use crate::high_level_api::booleans::{CompressedFheBool, FheBool, FheBoolConformanceParams};
expand_pub_use_fhe_type!(
    pub use crate::high_level_api::integers{
        FheUint2, FheUint4, FheUint6, FheUint8, FheUint10, FheUint12, FheUint14, FheUint16,
        FheUint32, FheUint64, FheUint128, FheUint160, FheUint256, FheUint512, FheUint1024, FheUint2048,

        FheInt2, FheInt4, FheInt6, FheInt8, FheInt10, FheInt12, FheInt14, FheInt16,
        FheInt32, FheInt64, FheInt128, FheInt160, FheInt256
    };
);

pub use crate::integer::parameters::CompactCiphertextListConformanceParams;
#[cfg(feature = "zk-pok-experimental")]
pub use compact_list::ProvenCompactCiphertextList;
pub use compact_list::{
    CompactCiphertextList, CompactCiphertextListBuilder, CompactCiphertextListExpander,
};
pub use safe_serialize::safe_serialize;

mod config;
mod global_state;
mod keys;
mod traits;

mod booleans;
mod errors;
mod integers;

pub mod array;
mod compact_list;
pub(in crate::high_level_api) mod details;
/// The tfhe prelude.
pub mod prelude;
#[cfg(feature = "zk-pok-experimental")]
mod zk;

/// Devices supported by tfhe-rs
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Device {
    Cpu,
    #[cfg(feature = "gpu")]
    CudaGpu,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum FheTypes {
    Bool,
    Uint2,
    Uint4,
    Uint6,
    Uint8,
    Uint10,
    Uint12,
    Uint14,
    Uint16,
    Uint32,
    Uint64,
    Uint128,
    Uint160,
    Uint256,
    Int2,
    Int4,
    Int6,
    Int8,
    Int10,
    Int12,
    Int14,
    Int16,
    Int32,
    Int64,
    Int128,
    Int160,
    Int256,
}

pub mod safe_serialize {
    use crate::named::Named;
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
}
