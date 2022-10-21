//! A module containing specifications of FHE engines.
//!
//! In essence, __engines__ are types which can be used to perform operations on fhe entities. These
//! engines contain all the side-resources needed to execute the operations they declare.
//! An engine must implement at least the [`AbstractEngine`] super-trait, and can implement any
//! number of `*Engine` traits.
//!
//! Every fhe operation is defined by a `*Engine` operation trait which always expose two entry
//! points:
//!
//! + A safe entry point, returning a result, with an [operation-dedicated](#engine-errors) error.
//! When using this entry point, the user relies on the backend to check that the necessary
//! preconditions are verified by the inputs, at the cost of a small overhead.
//! + An unsafe entry point, returning the raw result if any. When using this entry point, it is the
//! user responsibility to ensure that the necessary preconditions are verified by the inputs.
//! Breaking one of those preconditions will result in either a panic, or an FHE UB.
//!
//! # Engine errors
//!
//! Implementing the [`AbstractEngine`] trait for a given type implies specifying an associated
//! [`EngineError`](`AbstractEngine::EngineError`) which should be able to represent all the
//! possible error cases specific to this engine.
//!
//! Each `*Engine` trait is associated with a specialized `*Error<E>` type (for example
//! [`LweCiphertextDiscardingKeyswitchError`] is associated with
//! [`LweCiphertextDiscardingKeyswitchEngine`]), which contains:
//!
//! + Multiple __general__ error variants which can be potentially produced by any backend
//! (see the
//! [`LweCiphertextDiscardingKeyswitchError::InputLweDimensionMismatch`] variant for an example)
//! + One __specific__ variant which encapsulate the generic argument error `E`
//! (see the [`Engine`](`LweCiphertextDiscardingKeyswitchError::Engine`) variant for an example)
//!
//! When implementing a particular `*Engine` trait, this `E` argument will be forced to be the
//! [`EngineError`](`AbstractEngine::EngineError`) from the [`AbstractEngine`] super-trait, by the
//! signature of the operation entry point
//! (see [`LweCiphertextDiscardingKeyswitchEngine::discard_keyswitch_lwe_ciphertext`] for instance).
//!
//! This design makes it possible for each operation, to match the error exhaustively against both
//! general error variants, and backend-related error variants.
//!
//! # A word about Generation and Creation engines
//!
//! We have two families of engines to make entities:
//! - Generation engines which generate new entities with non trivial algorithms, e.g. a bootstrap
//!   key generation
//! - Creation engines which wrap/re-interpret data to create entities from them without involving
//!   non trivial algorithms, like creating a `Cleartext64` from a `u64` by simply wrapping the
//!   value.
//!
//! # Operation semantics
//!
//! For each possible operation, we try to support the three following semantics:
//!
//! + __Pure operations__ take their inputs as arguments, allocate an object
//! holding the result, and return it (example: [`LweCiphertextEncryptionEngine`]). They usually
//! require more resources than other, because of the allocation.
//! + __Discarding operations__ take both their inputs and outputs as arguments
//! (example: [`LweCiphertextDiscardingAdditionEngine`]). In those operations, the data originally
//! available in the outputs is not used for the computation. They are usually the fastest ones.
//! + __Fusing operations__ take both their inputs and outputs as arguments
//! (example: [`LweCiphertextFusingAdditionEngine`]). In those operations though, the data
//! originally contained in the output is used for computation.

// This makes it impossible for types outside this crate to implement operations.
pub(crate) mod sealed {
    pub trait AbstractEngineSeal {}
}

/// A top-level abstraction for engines.
///
/// An `AbstractEngine` is nothing more than a type with an associated error type
/// [`EngineError`](`AbstractEngine::EngineError`) and a default constructor.
///
/// The associated error type is expected to encode all the failure cases which can occur while
/// using an engine.
pub trait AbstractEngine: sealed::AbstractEngineSeal {
    // # Why put the error type in an abstract super trait ?
    //
    // This error is supposed to be reduced to only engine related errors, and not ones related to
    // the operations. For this reason, it is better for an engine to only have one error shared
    // among all the operations. If a variant of this error can only be triggered for a single
    // operation implemented by the engine, then it should probably be moved upstream, in the
    // operation-dedicated error.

    /// The error associated to the engine.
    type EngineError: std::error::Error;

    /// The constructor parameters type.
    type Parameters;

    /// A constructor for the engine.
    fn new(parameter: Self::Parameters) -> Result<Self, Self::EngineError>
    where
        Self: Sized;
}

macro_rules! engine_error {
    ($name:ident for $trait:ident @) => {
        #[doc=concat!("An error used with the [`", stringify!($trait), "`] trait.")]
        #[non_exhaustive]
        #[derive(Debug, Clone, Eq, PartialEq)]
        pub enum $name<EngineError: std::error::Error> {
            #[doc="_Specific_ error to the implementing engine."]
            Engine(EngineError),
        }
        impl<EngineError: std::error::Error> std::fmt::Display for $name<EngineError>{
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    Self::Engine(error) => write!(f, "Error occurred in the engine: {}", error),
                }
            }
        }
        impl<EngineError: std::error::Error> std::error::Error for $name<EngineError>{}
    };
    ($name:ident for $trait:ident @ $($variants:ident => $messages:literal),*) => {
        #[doc=concat!("An error used with the [`", stringify!($trait), "`] trait.")]
        #[doc=""]
        #[doc="This type provides a "]
        #[doc=concat!("[`", stringify!($name), "::perform_generic_checks`] ")]
        #[doc="function that does error checking for the general cases, returning an `Ok(())` "]
        #[doc="if the inputs are valid, meaning that engine implementors would then only "]
        #[doc="need to check for their own specific errors."]
        #[doc="Otherwise an `Err(..)` with the proper error variant is returned."]
        #[non_exhaustive]
        #[derive(Debug, Clone, Eq, PartialEq)]
        pub enum $name<EngineError: std::error::Error> {
            $(
                #[doc="_Generic_ error: "]
                #[doc=$messages]
                $variants,
            )*
            #[doc="_Specific_ error to the implementing engine."]
            Engine(EngineError),
        }
        impl<EngineError: std::error::Error> std::fmt::Display for $name<EngineError>{
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    $(
                        Self::$variants => write!(f, $messages),
                    )*
                    Self::Engine(error) => write!(f, "Error occurred in the engine: {}", error),
                }
            }
        }
        impl<EngineError: std::error::Error> std::error::Error for $name<EngineError>{}
    };
}
pub(crate) use engine_error;

mod cleartext_creation;
mod entity_deserialization;
mod entity_serialization;
mod glwe_ciphertext_consuming_retrieval;
mod glwe_ciphertext_conversion;
mod glwe_ciphertext_creation;
mod glwe_ciphertext_trivial_encryption;
mod glwe_secret_key_generation;
mod glwe_to_lwe_secret_key_transformation;
mod lwe_bootstrap_key_conversion;
mod lwe_bootstrap_key_generation;
mod lwe_ciphertext_cleartext_fusing_multiplication;
mod lwe_ciphertext_consuming_retrieval;
mod lwe_ciphertext_conversion;
mod lwe_ciphertext_creation;
mod lwe_ciphertext_decryption;
mod lwe_ciphertext_discarding_addition;
mod lwe_ciphertext_discarding_bit_extraction;
mod lwe_ciphertext_discarding_bootstrap;
mod lwe_ciphertext_discarding_conversion;
mod lwe_ciphertext_discarding_encryption;
mod lwe_ciphertext_discarding_keyswitch;
mod lwe_ciphertext_discarding_public_key_encryption;
mod lwe_ciphertext_encryption;
mod lwe_ciphertext_fusing_addition;
mod lwe_ciphertext_fusing_opposite;
mod lwe_ciphertext_fusing_subtraction;
mod lwe_ciphertext_plaintext_fusing_addition;
mod lwe_ciphertext_trivial_encryption;
mod lwe_ciphertext_vector_consuming_retrieval;
mod lwe_ciphertext_vector_creation;
mod lwe_ciphertext_vector_discarding_circuit_bootstrap_boolean_vertical_packing;
mod lwe_ciphertext_vector_zero_encryption;
mod lwe_ciphertext_zero_encryption;
mod lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_generation;
mod lwe_keyswitch_key_conversion;
mod lwe_keyswitch_key_generation;
mod lwe_public_key_generation;
mod lwe_secret_key_generation;
mod plaintext_creation;
mod plaintext_discarding_retrieval;
mod plaintext_vector_creation;

pub use cleartext_creation::*;
pub use entity_deserialization::*;
pub use entity_serialization::*;
pub use glwe_ciphertext_consuming_retrieval::*;
pub use glwe_ciphertext_conversion::*;
pub use glwe_ciphertext_creation::*;
pub use glwe_ciphertext_trivial_encryption::*;
pub use glwe_secret_key_generation::*;
pub use glwe_to_lwe_secret_key_transformation::*;
pub use lwe_bootstrap_key_conversion::*;
pub use lwe_bootstrap_key_generation::*;
pub use lwe_ciphertext_cleartext_fusing_multiplication::*;
pub use lwe_ciphertext_consuming_retrieval::*;
pub use lwe_ciphertext_conversion::*;
pub use lwe_ciphertext_creation::*;
pub use lwe_ciphertext_decryption::*;
pub use lwe_ciphertext_discarding_addition::*;
pub use lwe_ciphertext_discarding_bit_extraction::*;
pub use lwe_ciphertext_discarding_bootstrap::*;
pub use lwe_ciphertext_discarding_conversion::*;
pub use lwe_ciphertext_discarding_encryption::*;
pub use lwe_ciphertext_discarding_keyswitch::*;
pub use lwe_ciphertext_discarding_public_key_encryption::*;
pub use lwe_ciphertext_encryption::*;
pub use lwe_ciphertext_fusing_addition::*;
pub use lwe_ciphertext_fusing_opposite::*;
pub use lwe_ciphertext_fusing_subtraction::*;
pub use lwe_ciphertext_plaintext_fusing_addition::*;
pub use lwe_ciphertext_trivial_encryption::*;
pub use lwe_ciphertext_vector_consuming_retrieval::*;
pub use lwe_ciphertext_vector_creation::*;
pub use lwe_ciphertext_vector_discarding_circuit_bootstrap_boolean_vertical_packing::*;
pub use lwe_ciphertext_vector_zero_encryption::*;
pub use lwe_ciphertext_zero_encryption::*;
pub use lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_generation::*;
pub use lwe_keyswitch_key_conversion::*;
pub use lwe_keyswitch_key_generation::*;
pub use lwe_public_key_generation::*;
pub use lwe_secret_key_generation::*;
pub use plaintext_creation::*;
pub use plaintext_discarding_retrieval::*;
pub use plaintext_vector_creation::*;
