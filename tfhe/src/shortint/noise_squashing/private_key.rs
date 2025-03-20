use crate::core_crypto::algorithms::glwe_secret_key_generation::allocate_and_generate_new_binary_glwe_secret_key;
use crate::core_crypto::algorithms::lwe_encryption::decrypt_lwe_ciphertext;
use crate::core_crypto::entities::glwe_secret_key::GlweSecretKeyOwned;
use crate::shortint::backward_compatibility::noise_squashing::NoiseSquashingPrivateKeyVersions;
use crate::shortint::ciphertext::SquashedNoiseCiphertext;
use crate::shortint::encoding::{PaddingBit, ShortintEncoding};
use crate::shortint::engine::ShortintEngine;
use crate::shortint::parameters::noise_squashing::NoiseSquashingParameters;
use crate::shortint::parameters::CarryModulus;
use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

#[derive(Clone, Debug, Serialize, Deserialize, Versionize)]
#[versionize(NoiseSquashingPrivateKeyVersions)]
pub struct NoiseSquashingPrivateKey {
    post_noise_squashing_secret_key: GlweSecretKeyOwned<u128>,
    params: NoiseSquashingParameters,
}

impl NoiseSquashingPrivateKey {
    pub fn new(params: NoiseSquashingParameters) -> Self {
        let post_noise_squashing_secret_key = ShortintEngine::with_thread_local_mut(|engine| {
            allocate_and_generate_new_binary_glwe_secret_key(
                params.glwe_dimension,
                params.polynomial_size,
                &mut engine.secret_generator,
            )
        });

        Self {
            post_noise_squashing_secret_key,
            params,
        }
    }

    pub fn decrypt_squashed_noise_ciphertext(&self, ciphertext: &SquashedNoiseCiphertext) -> u128 {
        let plaintext = decrypt_lwe_ciphertext(
            &self.post_noise_squashing_secret_key.as_lwe_secret_key(),
            ciphertext.lwe_ciphertext(),
        );

        let encoding = ShortintEncoding {
            ciphertext_modulus: self.params.ciphertext_modulus,
            message_modulus: ciphertext.message_modulus(),
            carry_modulus: CarryModulus(1),
            padding_bit: PaddingBit::Yes,
        };

        encoding.decode(plaintext).0
    }

    pub fn post_noise_squashing_secret_key(&self) -> &GlweSecretKeyOwned<u128> {
        &self.post_noise_squashing_secret_key
    }

    pub fn noise_squashing_parameters(&self) -> NoiseSquashingParameters {
        self.params
    }
}
