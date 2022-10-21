//! A module containing the [engines](crate::core_crypto::specification::engines) exposed by
//! the default backend.

mod default_engine;
pub use default_engine::*;

#[cfg(feature = "backend_default_parallel")]
mod default_parallel_engine;
#[cfg(feature = "backend_default_parallel")]
pub use default_parallel_engine::*;

#[cfg(feature = "backend_default_serialization")]
mod default_serialization_engine;
#[cfg(feature = "backend_default_serialization")]
pub use default_serialization_engine::*;

mod activated_generator;
pub use activated_generator::ActivatedRandomGenerator;
