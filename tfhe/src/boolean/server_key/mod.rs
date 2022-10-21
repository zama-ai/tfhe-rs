//! The public key for homomorphic computation.
//!
//! This module implements the generation of the server's public key, together with all the
//! available homomorphic Boolean gates ($\mathrm{AND}$, $\mathrm{MUX}$, $\mathrm{NAND}$,
//! $\mathrm{NOR}$,
//! $\mathrm{NOT}$, $\mathrm{OR}$, $\mathrm{XNOR}$, $\mathrm{XOR}$).

#[cfg(test)]
mod tests;

use serde::{Deserialize, Serialize};

use crate::boolean::ciphertext::Ciphertext;
use crate::boolean::client_key::ClientKey;
use crate::boolean::engine::bootstrapping::CpuBootstrapKey;
#[cfg(feature = "cuda")]
use crate::boolean::engine::{bootstrapping::CudaBootstrapKey, CudaBooleanEngine};
use crate::boolean::engine::{
    BinaryGatesAssignEngine, BinaryGatesEngine, CpuBooleanEngine, WithThreadLocalEngine,
};
#[cfg(feature = "cuda")]
use std::sync::Arc;

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

trait RefFromServerKey {
    fn get_ref(server_key: &ServerKey) -> &Self;
}

trait DefaultImplementation {
    type Engine: WithThreadLocalEngine;
    type BootsrapKey: RefFromServerKey;
}

#[derive(Clone)]
pub struct ServerKey {
    cpu_key: CpuBootstrapKey,
    #[cfg(feature = "cuda")]
    cuda_key: Arc<CudaBootstrapKey>,
}

#[cfg(not(feature = "cuda"))]
mod implementation {
    use super::*;

    impl RefFromServerKey for CpuBootstrapKey {
        fn get_ref(server_key: &ServerKey) -> &Self {
            &server_key.cpu_key
        }
    }

    impl DefaultImplementation for ServerKey {
        type Engine = CpuBooleanEngine;
        type BootsrapKey = CpuBootstrapKey;
    }
}

#[cfg(feature = "cuda")]
mod implementation {
    use super::*;

    impl RefFromServerKey for CudaBootstrapKey {
        fn get_ref(server_key: &ServerKey) -> &Self {
            &server_key.cuda_key
        }
    }

    impl DefaultImplementation for ServerKey {
        type Engine = CudaBooleanEngine;
        type BootsrapKey = CudaBootstrapKey;
    }
}

impl<Lhs, Rhs> BinaryBooleanGates<Lhs, Rhs> for ServerKey
where
    <ServerKey as DefaultImplementation>::Engine:
        BinaryGatesEngine<Lhs, Rhs, <ServerKey as DefaultImplementation>::BootsrapKey>,
{
    fn and(&self, ct_left: Lhs, ct_right: Rhs) -> Ciphertext {
        let bootstrap_key = <ServerKey as DefaultImplementation>::BootsrapKey::get_ref(self);
        <ServerKey as DefaultImplementation>::Engine::with_thread_local_mut(|engine| {
            engine.and(ct_left, ct_right, bootstrap_key)
        })
    }

    fn nand(&self, ct_left: Lhs, ct_right: Rhs) -> Ciphertext {
        let bootstrap_key = <ServerKey as DefaultImplementation>::BootsrapKey::get_ref(self);
        <ServerKey as DefaultImplementation>::Engine::with_thread_local_mut(|engine| {
            engine.nand(ct_left, ct_right, bootstrap_key)
        })
    }

    fn nor(&self, ct_left: Lhs, ct_right: Rhs) -> Ciphertext {
        let bootstrap_key = <ServerKey as DefaultImplementation>::BootsrapKey::get_ref(self);
        <ServerKey as DefaultImplementation>::Engine::with_thread_local_mut(|engine| {
            engine.nor(ct_left, ct_right, bootstrap_key)
        })
    }

    fn or(&self, ct_left: Lhs, ct_right: Rhs) -> Ciphertext {
        let bootstrap_key = <ServerKey as DefaultImplementation>::BootsrapKey::get_ref(self);
        <ServerKey as DefaultImplementation>::Engine::with_thread_local_mut(|engine| {
            engine.or(ct_left, ct_right, bootstrap_key)
        })
    }

    fn xor(&self, ct_left: Lhs, ct_right: Rhs) -> Ciphertext {
        let bootstrap_key = <ServerKey as DefaultImplementation>::BootsrapKey::get_ref(self);
        <ServerKey as DefaultImplementation>::Engine::with_thread_local_mut(|engine| {
            engine.xor(ct_left, ct_right, bootstrap_key)
        })
    }

    fn xnor(&self, ct_left: Lhs, ct_right: Rhs) -> Ciphertext {
        let bootstrap_key = <ServerKey as DefaultImplementation>::BootsrapKey::get_ref(self);
        <ServerKey as DefaultImplementation>::Engine::with_thread_local_mut(|engine| {
            engine.xnor(ct_left, ct_right, bootstrap_key)
        })
    }
}

impl<Lhs, Rhs> BinaryBooleanGatesAssign<Lhs, Rhs> for ServerKey
where
    <ServerKey as DefaultImplementation>::Engine:
        BinaryGatesAssignEngine<Lhs, Rhs, <ServerKey as DefaultImplementation>::BootsrapKey>,
{
    fn and_assign(&self, ct_left: Lhs, ct_right: Rhs) {
        let bootstrap_key = <ServerKey as DefaultImplementation>::BootsrapKey::get_ref(self);
        <ServerKey as DefaultImplementation>::Engine::with_thread_local_mut(|engine| {
            engine.and_assign(ct_left, ct_right, bootstrap_key)
        })
    }

    fn nand_assign(&self, ct_left: Lhs, ct_right: Rhs) {
        let bootstrap_key = <ServerKey as DefaultImplementation>::BootsrapKey::get_ref(self);
        <ServerKey as DefaultImplementation>::Engine::with_thread_local_mut(|engine| {
            engine.nand_assign(ct_left, ct_right, bootstrap_key)
        })
    }

    fn nor_assign(&self, ct_left: Lhs, ct_right: Rhs) {
        let bootstrap_key = <ServerKey as DefaultImplementation>::BootsrapKey::get_ref(self);
        <ServerKey as DefaultImplementation>::Engine::with_thread_local_mut(|engine| {
            engine.nor_assign(ct_left, ct_right, bootstrap_key)
        })
    }

    fn or_assign(&self, ct_left: Lhs, ct_right: Rhs) {
        let bootstrap_key = <ServerKey as DefaultImplementation>::BootsrapKey::get_ref(self);
        <ServerKey as DefaultImplementation>::Engine::with_thread_local_mut(|engine| {
            engine.or_assign(ct_left, ct_right, bootstrap_key)
        })
    }

    fn xor_assign(&self, ct_left: Lhs, ct_right: Rhs) {
        let bootstrap_key = <ServerKey as DefaultImplementation>::BootsrapKey::get_ref(self);
        <ServerKey as DefaultImplementation>::Engine::with_thread_local_mut(|engine| {
            engine.xor_assign(ct_left, ct_right, bootstrap_key)
        })
    }

    fn xnor_assign(&self, ct_left: Lhs, ct_right: Rhs) {
        let bootstrap_key = <ServerKey as DefaultImplementation>::BootsrapKey::get_ref(self);
        <ServerKey as DefaultImplementation>::Engine::with_thread_local_mut(|engine| {
            engine.xnor_assign(ct_left, ct_right, bootstrap_key)
        })
    }
}

impl ServerKey {
    pub fn new(cks: &ClientKey) -> Self {
        let cpu_key =
            CpuBooleanEngine::with_thread_local_mut(|engine| engine.create_server_key(cks));

        Self::from(cpu_key)
    }

    pub fn trivial_encrypt(&self, message: bool) -> Ciphertext {
        Ciphertext::Trivial(message)
    }

    pub fn not(&self, ct: &Ciphertext) -> Ciphertext {
        CpuBooleanEngine::with_thread_local_mut(|engine| engine.not(ct))
    }

    pub fn not_assign(&self, ct: &mut Ciphertext) {
        CpuBooleanEngine::with_thread_local_mut(|engine| engine.not_assign(ct))
    }

    pub fn mux(
        &self,
        ct_condition: &Ciphertext,
        ct_then: &Ciphertext,
        ct_else: &Ciphertext,
    ) -> Ciphertext {
        #[cfg(feature = "cuda")]
        {
            CudaBooleanEngine::with_thread_local_mut(|engine| {
                engine.mux(ct_condition, ct_then, ct_else, &self.cuda_key)
            })
        }
        #[cfg(not(feature = "cuda"))]
        {
            CpuBooleanEngine::with_thread_local_mut(|engine| {
                engine.mux(ct_condition, ct_then, ct_else, &self.cpu_key)
            })
        }
    }
}

impl From<CpuBootstrapKey> for ServerKey {
    fn from(cpu_key: CpuBootstrapKey) -> Self {
        #[cfg(feature = "cuda")]
        {
            let cuda_key = CudaBooleanEngine::with_thread_local_mut(|engine| {
                engine.create_server_key(&cpu_key)
            });

            let cuda_key = Arc::new(cuda_key);

            Self { cpu_key, cuda_key }
        }
        #[cfg(not(feature = "cuda"))]
        {
            Self { cpu_key }
        }
    }
}

impl Serialize for ServerKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.cpu_key.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ServerKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let cpu_key = CpuBootstrapKey::deserialize(deserializer)?;

        Ok(Self::from(cpu_key))
    }
}
