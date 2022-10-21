use super::ActivatedRandomGenerator;
use crate::core_crypto::commons::crypto::secret::generators::{
    DeterministicSeeder as ImplDeterministicSeeder,
    EncryptionRandomGenerator as ImplEncryptionRandomGenerator,
};
use crate::core_crypto::specification::engines::sealed::AbstractEngineSeal;
use crate::core_crypto::specification::engines::AbstractEngine;
use concrete_csprng::seeders::Seeder;
use std::error::Error;
use std::fmt::{Display, Formatter};

/// The error which can occur in the execution of FHE operations, due to the default
/// parallel implementation.
///
/// # Note:
///
/// There is currently no such case, as the default parallel implementation is not expected to
/// undergo major issues unrelated to FHE.
#[derive(Debug)]
pub enum DefaultParallelError {}

impl Display for DefaultParallelError {
    fn fmt(&self, _f: &mut Formatter<'_>) -> std::fmt::Result {
        match *self {}
    }
}

impl Error for DefaultParallelError {}

pub struct DefaultParallelEngine {
    /// A structure containing two CSPRNGs to generate material for encryption like public masks
    /// and secret errors.
    ///
    /// The [`ImplEncryptionRandomGenerator`] contains two CSPRNGs, one publicly seeded used to
    /// generate mask coefficients and one privately seeded used to generate errors during
    /// encryption.
    pub(crate) encryption_generator: ImplEncryptionRandomGenerator<ActivatedRandomGenerator>,
    // /// A seeder that can be called to generate 128 bits seeds, useful to create new
    // /// [`ImplEncryptionRandomGenerator`] to encrypt seeded types.
    // seeder: ImplDeterministicSeeder<ActivatedRandomGenerator>,
}

impl AbstractEngineSeal for DefaultParallelEngine {}

impl AbstractEngine for DefaultParallelEngine {
    type EngineError = DefaultParallelError;

    type Parameters = Box<dyn Seeder>;

    fn new(mut parameters: Self::Parameters) -> Result<Self, Self::EngineError> {
        let mut deterministic_seeder =
            ImplDeterministicSeeder::<ActivatedRandomGenerator>::new(parameters.seed());

        Ok(DefaultParallelEngine {
            encryption_generator: ImplEncryptionRandomGenerator::new(
                deterministic_seeder.seed(),
                &mut deterministic_seeder,
            ),
            // seeder: deterministic_seeder,
        })
    }
}

mod lwe_bootstrap_key_generation;
mod lwe_ciphertext_vector_zero_encryption;
mod lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_generation;
mod lwe_public_key_generation;
// mod lwe_seeded_bootstrap_key_generation;
