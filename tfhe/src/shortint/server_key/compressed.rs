//! Module with the definition of the CompressedServerKey.

use super::MaxDegree;
use crate::core_crypto::prelude::*;
use crate::shortint::engine::ShortintEngine;
use crate::shortint::parameters::{CarryModulus, CiphertextModulus, MessageModulus};
use crate::shortint::{ClientKey, PBSOrder};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum ShortintCompressedBootstrappingKey {
    Classic(SeededLweBootstrapKeyOwned<u64>),
    MultiBit(SeededLweMultiBitBootstrapKeyOwned<u64>),
}

/// A structure containing a compressed server public key.
///
/// The server key is generated by the client and is meant to be published: the client
/// sends it to the server so it can compute homomorphic circuits.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CompressedServerKey {
    pub key_switching_key: SeededLweKeyswitchKeyOwned<u64>,
    pub bootstrapping_key: ShortintCompressedBootstrappingKey,
    // Size of the message buffer
    pub message_modulus: MessageModulus,
    // Size of the carry buffer
    pub carry_modulus: CarryModulus,
    // Maximum number of operations that can be done before emptying the operation buffer
    pub max_degree: MaxDegree,
    pub ciphertext_modulus: CiphertextModulus,
    pub pbs_order: PBSOrder,
}

impl CompressedServerKey {
    /// Generate a compressed server key.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::client_key::ClientKey;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    /// use tfhe::shortint::server_key::CompressedServerKey;
    ///
    /// // Generate the client key:
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2);
    ///
    /// let sks = CompressedServerKey::new(&cks);
    /// ```
    pub fn new(client_key: &ClientKey) -> CompressedServerKey {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.new_compressed_server_key(client_key).unwrap()
        })
    }
}
