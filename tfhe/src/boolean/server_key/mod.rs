//! The public key for homomorphic computation.
//!
//! This module implements the generation of the server's public key, together with all the
//! available homomorphic Boolean gates ($\mathrm{AND}$, $\mathrm{MUX}$, $\mathrm{NAND}$,
//! $\mathrm{NOR}$,
//! $\mathrm{NOT}$, $\mathrm{OR}$, $\mathrm{XNOR}$, $\mathrm{XOR}$).

#[cfg(test)]
mod tests;

use crate::boolean::ciphertext::Ciphertext;
use crate::boolean::client_key::ClientKey;
pub use crate::boolean::engine::bootstrapping::{CompressedServerKey, ServerKey};
use crate::boolean::engine::{
    BinaryGatesAssignEngine, BinaryGatesEngine, BooleanEngine, WithThreadLocalEngine,
};

pub trait BinaryBooleanGates<L, R> {
    fn and(&self, ct_left: L, ct_right: R) -> Ciphertext;
    fn nand(&self, ct_left: L, ct_right: R) -> Ciphertext;
    fn nor(&self, ct_left: L, ct_right: R) -> Ciphertext;
    fn or(&self, ct_left: L, ct_right: R) -> Ciphertext;
    fn xor(&self, ct_left: L, ct_right: R) -> Ciphertext;
    fn xnor(&self, ct_left: L, ct_right: R) -> Ciphertext;
}

pub trait BinaryBooleanGatesAssign<L, R> {
    fn and_assign(&self, ct_left: L, ct_right: R);
    fn nand_assign(&self, ct_left: L, ct_right: R);
    fn nor_assign(&self, ct_left: L, ct_right: R);
    fn or_assign(&self, ct_left: L, ct_right: R);
    fn xor_assign(&self, ct_left: L, ct_right: R);
    fn xnor_assign(&self, ct_left: L, ct_right: R);
}

trait DefaultImplementation {
    type Engine: WithThreadLocalEngine;
}

mod implementation {
    use super::*;

    impl DefaultImplementation for ServerKey {
        type Engine = BooleanEngine;
    }
}

impl<Lhs, Rhs> BinaryBooleanGates<Lhs, Rhs> for ServerKey
where
    <Self as DefaultImplementation>::Engine: BinaryGatesEngine<Lhs, Rhs, Self>,
{
    fn and(&self, ct_left: Lhs, ct_right: Rhs) -> Ciphertext {
        <Self as DefaultImplementation>::Engine::with_thread_local_mut(|engine| {
            engine.and(ct_left, ct_right, self)
        })
    }

    fn nand(&self, ct_left: Lhs, ct_right: Rhs) -> Ciphertext {
        <Self as DefaultImplementation>::Engine::with_thread_local_mut(|engine| {
            engine.nand(ct_left, ct_right, self)
        })
    }

    fn nor(&self, ct_left: Lhs, ct_right: Rhs) -> Ciphertext {
        <Self as DefaultImplementation>::Engine::with_thread_local_mut(|engine| {
            engine.nor(ct_left, ct_right, self)
        })
    }

    fn or(&self, ct_left: Lhs, ct_right: Rhs) -> Ciphertext {
        <Self as DefaultImplementation>::Engine::with_thread_local_mut(|engine| {
            engine.or(ct_left, ct_right, self)
        })
    }

    fn xor(&self, ct_left: Lhs, ct_right: Rhs) -> Ciphertext {
        <Self as DefaultImplementation>::Engine::with_thread_local_mut(|engine| {
            engine.xor(ct_left, ct_right, self)
        })
    }

    fn xnor(&self, ct_left: Lhs, ct_right: Rhs) -> Ciphertext {
        <Self as DefaultImplementation>::Engine::with_thread_local_mut(|engine| {
            engine.xnor(ct_left, ct_right, self)
        })
    }
}

impl<Lhs, Rhs> BinaryBooleanGatesAssign<Lhs, Rhs> for ServerKey
where
    <Self as DefaultImplementation>::Engine: BinaryGatesAssignEngine<Lhs, Rhs, Self>,
{
    fn and_assign(&self, ct_left: Lhs, ct_right: Rhs) {
        <Self as DefaultImplementation>::Engine::with_thread_local_mut(|engine| {
            engine.and_assign(ct_left, ct_right, self);
        });
    }

    fn nand_assign(&self, ct_left: Lhs, ct_right: Rhs) {
        <Self as DefaultImplementation>::Engine::with_thread_local_mut(|engine| {
            engine.nand_assign(ct_left, ct_right, self);
        });
    }

    fn nor_assign(&self, ct_left: Lhs, ct_right: Rhs) {
        <Self as DefaultImplementation>::Engine::with_thread_local_mut(|engine| {
            engine.nor_assign(ct_left, ct_right, self);
        });
    }

    fn or_assign(&self, ct_left: Lhs, ct_right: Rhs) {
        <Self as DefaultImplementation>::Engine::with_thread_local_mut(|engine| {
            engine.or_assign(ct_left, ct_right, self);
        });
    }

    fn xor_assign(&self, ct_left: Lhs, ct_right: Rhs) {
        <Self as DefaultImplementation>::Engine::with_thread_local_mut(|engine| {
            engine.xor_assign(ct_left, ct_right, self);
        });
    }

    fn xnor_assign(&self, ct_left: Lhs, ct_right: Rhs) {
        <Self as DefaultImplementation>::Engine::with_thread_local_mut(|engine| {
            engine.xnor_assign(ct_left, ct_right, self);
        });
    }
}

impl ServerKey {
    pub fn new(cks: &ClientKey) -> Self {
        BooleanEngine::with_thread_local_mut(|engine| engine.create_server_key(cks))
    }

    pub fn trivial_encrypt(&self, message: bool) -> Ciphertext {
        Ciphertext::Trivial(message)
    }

    pub fn not(&self, ct: &Ciphertext) -> Ciphertext {
        BooleanEngine::with_thread_local_mut(|engine| engine.not(ct))
    }

    pub fn not_assign(&self, ct: &mut Ciphertext) {
        BooleanEngine::with_thread_local_mut(|engine| engine.not_assign(ct));
    }

    pub fn mux(
        &self,
        ct_condition: &Ciphertext,
        ct_then: &Ciphertext,
        ct_else: &Ciphertext,
    ) -> Ciphertext {
        BooleanEngine::with_thread_local_mut(|engine| {
            engine.mux(ct_condition, ct_then, ct_else, self)
        })
    }
}

impl CompressedServerKey {
    pub fn new(cks: &ClientKey) -> Self {
        BooleanEngine::with_thread_local_mut(|engine| engine.create_compressed_server_key(cks))
    }
}
