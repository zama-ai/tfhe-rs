//! A module containing specifications of the `concrete` FHE entities.
//!
//! In practice, __Entities__ are types which implement:
//!
//! + The [`AbstractEntity`] super-trait.
//! + One of the `*Entity` traits.

pub mod markers;

use markers::*;
use std::fmt::Debug;

/// A top-level abstraction for entities of the concrete scheme.
///
/// An `AbstractEntity` type is nothing more than a type with an associated
/// [`Kind`](`AbstractEntity::Kind`) marker type (implementing the [`EntityKindMarker`] trait),
/// which encodes in the type system, the abstract nature of the object.
pub trait AbstractEntity: Debug {
    // # Why associated types and not generic parameters ?
    //
    // With generic parameters you can have one type implement a variety of abstract entity. With
    // associated types, a type can only implement one abstract entity. Hence, using generic
    // parameters, would encourage broadly generic types representing various entities (say an
    // array) while using associated types encourages narrowly defined types representing a single
    // entity. We think it is preferable for the user if the backends expose narrowly defined
    // types, as it makes the api cleaner and the signatures leaner. The downside is probably a bit
    // more boilerplate though.
    //
    // Also, this prevents a single type to implement different downstream traits (a type being both
    // a GGSW ciphertext vector and an LWE bootstrap key). Again, I think this is for the best, as
    // it will help us design better backend-level apis.

    /// The _kind_ of the entity.
    type Kind: EntityKindMarker;
}

mod cleartext;
mod cleartext_vector;
mod encoder;
mod encoder_vector;
mod ggsw_ciphertext;
mod ggsw_ciphertext_vector;
mod ggsw_seeded_ciphertext;
mod glwe_ciphertext;
mod glwe_ciphertext_vector;
mod glwe_secret_key;
mod glwe_seeded_ciphertext;
mod glwe_seeded_ciphertext_vector;
mod lwe_bootstrap_key;
mod lwe_ciphertext;
mod lwe_ciphertext_vector;
mod lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys;
mod lwe_keyswitch_key;
mod lwe_packing_keyswitch_key;
mod lwe_private_functional_packing_keyswitch_key;
mod lwe_public_key;
mod lwe_secret_key;
mod lwe_seeded_bootstrap_key;
mod lwe_seeded_ciphertext;
mod lwe_seeded_ciphertext_vector;
mod lwe_seeded_keyswitch_key;
mod plaintext;
mod plaintext_vector;

pub use cleartext::*;
pub use cleartext_vector::*;
pub use encoder::*;
pub use encoder_vector::*;
pub use ggsw_ciphertext::*;
pub use ggsw_ciphertext_vector::*;
pub use ggsw_seeded_ciphertext::*;
pub use glwe_ciphertext::*;
pub use glwe_ciphertext_vector::*;
pub use glwe_secret_key::*;
pub use glwe_seeded_ciphertext::*;
pub use glwe_seeded_ciphertext_vector::*;
pub use lwe_bootstrap_key::*;
pub use lwe_ciphertext::*;
pub use lwe_ciphertext_vector::*;
pub use lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys::*;
pub use lwe_keyswitch_key::*;
pub use lwe_packing_keyswitch_key::*;
pub use lwe_private_functional_packing_keyswitch_key::*;
pub use lwe_public_key::*;
pub use lwe_secret_key::*;
pub use lwe_seeded_bootstrap_key::*;
pub use lwe_seeded_ciphertext::*;
pub use lwe_seeded_ciphertext_vector::*;
pub use lwe_seeded_keyswitch_key::*;
pub use plaintext::*;
pub use plaintext_vector::*;
