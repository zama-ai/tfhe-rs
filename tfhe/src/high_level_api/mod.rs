#![allow(unused_doc_comments)]

// internal helper macro to make it easier to `pub use`
// all necessary stuff tied to a FheUint/FheInt from the given `module_path`.
//
// Note: This is for Integers not Shortints
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
                    [<Compact $fhe_type_name>],
                    [<Compact $fhe_type_name List>],
                )*
            };

        }
    }
);

pub use crate::core_crypto::commons::math::random::Seed;
pub use config::{Config, ConfigBuilder};
pub use errors::{Error, OutOfRangeError};
pub use global_state::{set_server_key, unset_server_key, with_server_key_as_context};
pub use keys::{
    generate_keys, ClientKey, CompactPublicKey, CompressedCompactPublicKey, CompressedPublicKey,
    CompressedServerKey, PublicKey, ServerKey,
};

#[cfg(test)]
mod tests;

#[cfg(feature = "boolean")]
pub use crate::high_level_api::booleans::{CompressedFheBool, FheBool, FheBoolParameters};
#[cfg(feature = "integer")]
expand_pub_use_fhe_type!(
    pub use crate::high_level_api::integers{
        FheUint8, FheUint10, FheUint12, FheUint14, FheUint16, FheUint32, FheUint64, FheUint128,
        FheUint256, FheInt8, FheInt16, FheInt32, FheInt64, FheInt128, FheInt256
    };
);
#[cfg(feature = "shortint")]
pub use crate::high_level_api::shortints::{
    CompressedFheUint2, CompressedFheUint3, CompressedFheUint4, FheUint2, FheUint2Parameters,
    FheUint3, FheUint3Parameters, FheUint4, FheUint4Parameters,
};
#[cfg(feature = "integer")]
#[cfg(feature = "safe-deserialization")]
pub use integers::safe_serialize::{
    safe_deserialize_conformant, safe_deserialize_conformant_compact_integer, safe_serialize,
};

#[macro_use]
mod details;
#[macro_use]
mod global_state;
#[macro_use]
mod keys;
mod config;
mod internal_traits;
mod traits;

#[cfg(feature = "boolean")]
mod booleans;
pub mod errors;
#[cfg(feature = "integer")]
mod integers;
/// The tfhe prelude.
pub mod prelude;
#[cfg(feature = "shortint")]
mod shortints;

pub mod parameters {}
