#![allow(unused_doc_comments)]
pub use config::{Config, ConfigBuilder};
pub use errors::{Error, OutOfRangeError};
pub use global_state::{set_server_key, unset_server_key, with_server_key_as_context};
pub use keys::{generate_keys, ClientKey, CompressedPublicKey, PublicKey, ServerKey};

#[cfg(test)]
mod tests;

#[cfg(feature = "boolean")]
pub use crate::high_level_api::booleans::{CompressedFheBool, FheBool, FheBoolParameters};
#[cfg(feature = "integer")]
pub use crate::high_level_api::integers::{
    CompressedFheUint10, CompressedFheUint12, CompressedFheUint128, CompressedFheUint14,
    CompressedFheUint16, CompressedFheUint256, CompressedFheUint32, CompressedFheUint64,
    CompressedFheUint8, CrtParameters, FheUint10, FheUint12, FheUint128, FheUint14, FheUint16,
    FheUint256, FheUint32, FheUint64, FheUint8, GenericInteger, RadixParameters,
};
#[cfg(feature = "shortint")]
pub use crate::high_level_api::shortints::{
    CompressedFheUint2, CompressedFheUint3, CompressedFheUint4, FheUint2, FheUint2Parameters,
    FheUint3, FheUint3Parameters, FheUint4, FheUint4Parameters,
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
