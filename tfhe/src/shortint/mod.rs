#![allow(clippy::let_and_return)]
//! # Description
//!
//! This library makes it possible to execute modular operations over encrypted short integer.
//!
//! It allows to execute an integer circuit on an untrusted server because both circuit inputs and
//! outputs are kept private.
//!
//! Data are encrypted on the client side, before being sent to the server.
//! On the server side every computation is performed on ciphertexts.
//!
//! The server however, has to know the integer circuit to be evaluated.
//! At the end of the computation, the server returns the encryption of the result to the user.
//!
//! # Keys
//!
//! This crates exposes two type of keys:
//! * The [`ClientKey`](crate::shortint::client_key::ClientKey) is used to encrypt and decrypt and
//!   has to be kept secret;
//! * The [`DServerKey`](crate::shortint::server_key::DServerKey) is used to perform homomorphic
//!   operations on the server side and it is meant to be published (the client sends it to the
//!   server).
//!
//!
//! # Quick Example
//!
//! The following piece of code shows how to generate keys and run a small integer circuit
//! homomorphically.
//!
//! ```rust
//! use tfhe::shortint::gen_keys;
//! use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
//!
//! // We generate a set of client/server keys, using the default parameters:
//! let (mut client_key, mut server_key) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
//!
//! let msg1 = 1;
//! let msg2 = 0;
//!
//! // We use the client key to encrypt two messages:
//! let ct_1 = client_key.encrypt(msg1);
//! let ct_2 = client_key.encrypt(msg2);
//!
//! // We use the server public key to execute an integer circuit:
//! let ct_3 = server_key.unchecked_add(&ct_1, &ct_2);
//!
//! // We use the client key to decrypt the output of the circuit:
//! let output = client_key.decrypt(&ct_3);
//! assert_eq!(output, 1);
//! ```
pub mod ciphertext;
pub mod client_key;
pub mod engine;
pub mod key_switching_key;
#[cfg(any(test, doctest, feature = "internal-keycache"))]
pub mod keycache;
pub mod parameters;
pub mod prelude;
pub mod public_key;
pub mod server_key;
pub mod wopbs;

use self::server_key::LookupTableOwned;
pub use ciphertext::{Ciphertext, CompressedCiphertext, PBSOrder};
pub use client_key::ClientKey;
pub use key_switching_key::KeySwitchingKey;
use lamellar::{AmData, Darc};
pub use parameters::{
    CarryModulus, CiphertextModulus, ClassicPBSParameters, EncryptionKeyChoice, MessageModulus,
    MultiBitPBSParameters, PBSParameters, ShortintParameterSet, WopbsParameters,
};
pub use public_key::{
    CompactPublicKey, CompressedCompactPublicKey, CompressedPublicKey, PublicKey,
};
use serde::{Deserialize, Serialize};
pub use server_key::{CheckError, CompressedServerKey, ServerKey};
use std::sync::atomic::AtomicUsize;

/// Generate a couple of client and server keys.
///
/// # Example
///
/// Generating a pair of [ClientKey] and [DServerKey] using the default parameters.
///
/// ```rust
/// use tfhe::shortint::gen_keys;
/// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
///
/// // generate the client key and the server key:
/// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
/// ```
pub fn gen_keys<P>(parameters_set: P) -> (ClientKey, DServerKey)
where
    P: TryInto<ShortintParameterSet>,
    <P as TryInto<ShortintParameterSet>>::Error: std::fmt::Debug,
{
    let shortint_parameters_set: ShortintParameterSet = parameters_set.try_into().unwrap();

    let is_wopbs_only_params = shortint_parameters_set.wopbs_only();

    // TODO
    // Manually manage the wopbs only case as a workaround pending wopbs rework
    let shortint_parameters_set = if is_wopbs_only_params {
        let wopbs_params = shortint_parameters_set.wopbs_parameters().unwrap();
        let pbs_params = ClassicPBSParameters {
            lwe_dimension: wopbs_params.lwe_dimension,
            glwe_dimension: wopbs_params.glwe_dimension,
            polynomial_size: wopbs_params.polynomial_size,
            lwe_modular_std_dev: wopbs_params.lwe_modular_std_dev,
            glwe_modular_std_dev: wopbs_params.glwe_modular_std_dev,
            pbs_base_log: wopbs_params.pbs_base_log,
            pbs_level: wopbs_params.pbs_level,
            ks_base_log: wopbs_params.ks_base_log,
            ks_level: wopbs_params.ks_level,
            message_modulus: wopbs_params.message_modulus,
            carry_modulus: wopbs_params.carry_modulus,
            ciphertext_modulus: wopbs_params.ciphertext_modulus,
            encryption_key_choice: wopbs_params.encryption_key_choice,
        };

        ShortintParameterSet::try_new_pbs_and_wopbs_param_set((pbs_params, wopbs_params)).unwrap()
    } else {
        shortint_parameters_set
    };

    let cks = ClientKey::new(shortint_parameters_set);
    let sks = DServerKey::new(ServerKey::new(&cks));

    (cks, sks)
}

pub struct PbsDispatcher {
    pub pe_index: AtomicUsize,
    pub number_pe: usize,
    pub world: lamellar::LamellarWorld,
}

pub static DISPATCHER: once_cell::sync::Lazy<PbsDispatcher> = once_cell::sync::Lazy::new(|| {
    let world = lamellar::LamellarWorldBuilder::new().build();

    let number_pe = world.num_pes();

    PbsDispatcher {
        world,
        pe_index: AtomicUsize::new(0),
        number_pe,
    }
});

#[AmData(Clone)] // `AmData` is a macro used in place of `derive`
pub(crate) struct Pbs {
    //the "input data" we are sending with our active message
    pub(crate) ct: Ciphertext,
    pub(crate) acc: LookupTableOwned,
    pub(crate) sk: Darc<ServerKey>,
}

#[lamellar::am] // at a highlevel registers this LamellarAM implemenatation with the runtime for remote execution
impl LamellarAM for Pbs {
    async fn exec(&self) -> Ciphertext {
        let mut ct = self.ct.clone();

        match self.sk.pbs_order {
            PBSOrder::KeyswitchBootstrap => {
                self.sk
                    .keyswitch_programmable_bootstrap_assign(&mut ct, &self.acc);
            }
            PBSOrder::BootstrapKeyswitch => {
                self.sk
                    .programmable_bootstrap_keyswitch_assign(&mut ct, &self.acc);
            }
        };

        ct
    }
}

#[derive(Clone, Debug)]
pub struct DServerKey(pub Darc<ServerKey>);

impl Serialize for DServerKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        (*self.0).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for DServerKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        ServerKey::deserialize(deserializer)
            .map(|sk| Self(Darc::new(&DISPATCHER.world, sk).unwrap()))
    }
}

impl AsRef<ServerKey> for DServerKey {
    fn as_ref(&self) -> &ServerKey {
        &self.0
    }
}

impl DServerKey {
    pub fn new(sk: ServerKey) -> Self {
        Self(Darc::new(&DISPATCHER.world, sk).unwrap())
    }

    pub fn create_trivial(&self, value: u64) -> Ciphertext {
        self.0.create_trivial(value)
    }

    pub fn create_trivial_assign(&self, ct: &mut Ciphertext, value: u64) {
        self.0.create_trivial_assign(ct, value);
    }
}

#[test]
fn test_d_pbs() {
    use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    use crate::shortint::{gen_keys, Ciphertext};

    // Generate the client key and the server key:
    let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);

    let msg = 1;

    // Trivial encryption
    let ct1: Ciphertext = cks.encrypt(msg);

    let lut = sks.generate_lookup_table(|a| a + 1);

    let ct2 = sks.apply_lookup_table(ct1, lut);

    let msg2 = cks.decrypt(&ct2);

    assert_eq!(msg2, 2);
}
