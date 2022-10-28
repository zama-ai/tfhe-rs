use super::ActivatedRandomGenerator;
use crate::core_crypto::commons::crypto::secret::generators::{
    DeterministicSeeder as ImplDeterministicSeeder,
    EncryptionRandomGenerator as ImplEncryptionRandomGenerator,
    SecretRandomGenerator as ImplSecretRandomGenerator,
};
use crate::core_crypto::specification::engines::sealed::AbstractEngineSeal;
use crate::core_crypto::specification::engines::AbstractEngine;
use concrete_csprng::seeders::Seeder;
use std::error::Error;
use std::fmt::{Display, Formatter};

/// The error which can occur in the execution of FHE operations, due to the default implementation.
///
/// # Note:
///
/// There is currently no such case, as the default implementation is not expected to undergo some
/// major issues unrelated to FHE.
#[derive(Debug)]
pub enum DefaultError {}

impl Display for DefaultError {
    fn fmt(&self, _f: &mut Formatter<'_>) -> std::fmt::Result {
        Ok(())
    }
}

impl Error for DefaultError {}

pub struct DefaultEngine {
    /// A structure containing a single CSPRNG to generate secret key coefficients.
    secret_generator: ImplSecretRandomGenerator<ActivatedRandomGenerator>,
    /// A structure containing two CSPRNGs to generate material for encryption like public masks
    /// and secret errors.
    ///
    /// The [`ImplEncryptionRandomGenerator`] contains two CSPRNGs, one publicly seeded used to
    /// generate mask coefficients and one privately seeded used to generate errors during
    /// encryption.
    encryption_generator: ImplEncryptionRandomGenerator<ActivatedRandomGenerator>,
    /// A seeder that can be called to generate 128 bits seeds, useful to create new
    /// [`ImplEncryptionRandomGenerator`] to encrypt seeded types.
    seeder: ImplDeterministicSeeder<ActivatedRandomGenerator>,
}
impl AbstractEngineSeal for DefaultEngine {}

impl AbstractEngine for DefaultEngine {
    type EngineError = DefaultError;

    type Parameters = Box<dyn Seeder>;

    fn new(mut parameters: Self::Parameters) -> Result<Self, Self::EngineError> {
        let mut deterministic_seeder =
            ImplDeterministicSeeder::<ActivatedRandomGenerator>::new(parameters.seed());

        // Note that the operands are evaluated from left to right for Rust Struct expressions
        // See: https://doc.rust-lang.org/stable/reference/expressions.html?highlight=left#evaluation-order-of-operands
        // So parameters is moved in seeder after the calls to seed and the potential calls when it
        // is passed as_mut in ImplEncryptionRandomGenerator::new
        Ok(DefaultEngine {
            secret_generator: ImplSecretRandomGenerator::new(deterministic_seeder.seed()),
            encryption_generator: ImplEncryptionRandomGenerator::new(
                deterministic_seeder.seed(),
                &mut deterministic_seeder,
            ),
            seeder: deterministic_seeder,
        })
    }
}

mod cleartext_creation;
mod glwe_ciphertext_creation;
mod glwe_ciphertext_trivial_encryption;
mod glwe_secret_key_generation;
mod glwe_to_lwe_secret_key_transformation;
mod lwe_bootstrap_key_generation;
mod lwe_ciphertext_cleartext_fusing_multiplication;
mod lwe_ciphertext_consuming_retrieval;
mod lwe_ciphertext_creation;
mod lwe_ciphertext_decryption;
mod lwe_ciphertext_discarding_addition;
mod lwe_ciphertext_discarding_keyswitch;
mod lwe_ciphertext_encryption;
mod lwe_ciphertext_fusing_addition;
mod lwe_ciphertext_fusing_opposite;
mod lwe_ciphertext_fusing_subtraction;
mod lwe_ciphertext_plaintext_fusing_addition;
mod lwe_ciphertext_trivial_encryption;
mod lwe_ciphertext_vector_consuming_retrieval;
mod lwe_ciphertext_vector_creation;
mod lwe_ciphertext_zero_encryption;
mod lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_generation;
mod lwe_keyswitch_key_generation;
mod lwe_secret_key_generation;
mod plaintext_creation;
mod plaintext_discarding_retrieval;
mod plaintext_vector_creation;

// mod cleartext_discarding_retrieval;
// mod cleartext_retrieval;
// mod cleartext_vector_creation;
// mod cleartext_vector_discarding_retrieval;
// mod cleartext_vector_retrieval;
// mod ggsw_ciphertext_scalar_discarding_encryption;
// mod ggsw_ciphertext_scalar_encryption;
// mod ggsw_ciphertext_scalar_trivial_encryption;
// mod glwe_ciphertext_consuming_retrieval;
// mod glwe_ciphertext_decryption;
// mod glwe_ciphertext_discarding_decryption;
// mod glwe_ciphertext_discarding_encryption;
// mod glwe_ciphertext_discarding_trivial_encryption;
// mod glwe_ciphertext_encryption;
// mod glwe_ciphertext_trivial_decryption;
// mod glwe_ciphertext_vector_consuming_retrieval;
// mod glwe_ciphertext_vector_creation;
// mod glwe_ciphertext_vector_decryption;
// mod glwe_ciphertext_vector_discarding_decryption;
// mod glwe_ciphertext_vector_discarding_encryption;
// mod glwe_ciphertext_vector_encryption;
// mod glwe_ciphertext_vector_trivial_decryption;
// mod glwe_ciphertext_vector_trivial_encryption;
// mod glwe_ciphertext_vector_zero_encryption;
// mod glwe_ciphertext_zero_encryption;
// mod glwe_seeded_ciphertext_encryption;
// mod glwe_seeded_ciphertext_to_glwe_ciphertext_transformation;
// mod glwe_seeded_ciphertext_vector_encryption;
// mod glwe_seeded_vector_to_glwe_ciphertext_vector_transformation;
// mod lwe_bootstrap_key_consuming_retrieval;
// mod lwe_bootstrap_key_creation;
// mod lwe_bootstrap_key_discarding_conversion;
// mod lwe_ciphertext_cleartext_discarding_multiplication;
// mod lwe_ciphertext_discarding_decryption;
// mod lwe_ciphertext_discarding_encryption;
// mod lwe_ciphertext_discarding_extraction;
// mod lwe_ciphertext_discarding_opposite;
// mod lwe_ciphertext_discarding_public_key_encryption;
// mod lwe_ciphertext_discarding_subtraction;
// mod lwe_ciphertext_plaintext_discarding_addition;
// mod lwe_ciphertext_plaintext_discarding_subtraction;
// mod lwe_ciphertext_plaintext_fusing_subtraction;
// mod lwe_ciphertext_trivial_decryption;
// mod lwe_ciphertext_vector_decryption;
// mod lwe_ciphertext_vector_discarding_addition;
// mod lwe_ciphertext_vector_discarding_affine_transformation;
// mod lwe_ciphertext_vector_discarding_decryption;
// mod lwe_ciphertext_vector_discarding_encryption;
// mod lwe_ciphertext_vector_discarding_subtraction;
// mod lwe_ciphertext_vector_encryption;
// mod lwe_ciphertext_vector_fusing_addition;
// mod lwe_ciphertext_vector_fusing_subtraction;
// mod lwe_ciphertext_vector_glwe_ciphertext_discarding_packing_keyswitch;
// mod lwe_ciphertext_vector_glwe_ciphertext_discarding_private_functional_packing_keyswitch;
// mod lwe_ciphertext_vector_trivial_decryption;
// mod lwe_ciphertext_vector_trivial_encryption;
// mod lwe_ciphertext_vector_zero_encryption;
// mod lwe_keyswitch_key_consuming_retrieval;
// mod lwe_keyswitch_key_creation;
// mod lwe_keyswitch_key_discarding_conversion;
// mod lwe_packing_keyswitch_key_generation;
// mod lwe_private_functional_packing_keyswitch_key_generation;
// mod lwe_public_key_generation;
// mod lwe_seeded_bootstrap_key_generation;
// mod lwe_seeded_bootstrap_key_to_lwe_bootstrap_key_transformation;
// mod lwe_seeded_ciphertext_encryption;
// mod lwe_seeded_ciphertext_vector_encryption;
// mod lwe_seeded_ciphertext_vector_to_lwe_ciphertext_vector_transformation;
// mod lwe_seeded_keyswitch_key_generation;
// mod lwe_seeded_keyswitch_key_to_lwe_keyswitch_key_transformation;
// mod lwe_seeded_to_lwe_ciphertext_transformation;
// mod lwe_to_glwe_secret_key_transformation;
// mod plaintext_retrieval;
// mod plaintext_vector_discarding_retrieval;
// mod plaintext_vector_retrieval;
