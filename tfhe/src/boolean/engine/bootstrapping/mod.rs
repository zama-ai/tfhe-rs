use crate::boolean::ciphertext::Ciphertext;
use crate::core_crypto::prelude::{LweCiphertext32, LweSize};
mod cpu;
#[cfg(feature = "cuda")]
mod cuda;

#[cfg(feature = "cuda")]
pub(crate) use cuda::{CudaBootstrapKey, CudaBootstrapper};

pub(crate) use cpu::{CpuBootstrapKey, CpuBootstrapper};

pub trait BooleanServerKey {
    /// The LweSize of the Ciphertexts that this key can bootstrap
    fn lwe_size(&self) -> LweSize;
}

/// Trait for types which implement the bootstrapping + key switching
/// of a ciphertext.
///
/// Meant to be implemented for different hardware (CPU, GPU) or for other bootstrapping
/// technics.
pub(crate) trait Bootstrapper: Default {
    type ServerKey: BooleanServerKey;

    /// Shall return the result of the bootstrapping of the
    /// input ciphertext or an error if any
    fn bootstrap(
        &mut self,
        input: &LweCiphertext32,
        server_key: &Self::ServerKey,
    ) -> Result<LweCiphertext32, Box<dyn std::error::Error>>;

    /// Shall return the result of the key switching of the
    /// input ciphertext or an error if any
    fn keyswitch(
        &mut self,
        input: &LweCiphertext32,
        server_key: &Self::ServerKey,
    ) -> Result<LweCiphertext32, Box<dyn std::error::Error>>;

    /// Shall do the bootstrapping and key switching of the ciphertext.
    /// The result is returned as a new value.
    fn bootstrap_keyswitch(
        &mut self,
        ciphertext: LweCiphertext32,
        server_key: &Self::ServerKey,
    ) -> Result<Ciphertext, Box<dyn std::error::Error>>;
}
