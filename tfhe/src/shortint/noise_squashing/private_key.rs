use crate::core_crypto::algorithms::glwe_secret_key_generation::allocate_and_generate_new_binary_glwe_secret_key;
use crate::core_crypto::algorithms::lwe_encryption::decrypt_lwe_ciphertext;
use crate::core_crypto::entities::glwe_secret_key::GlweSecretKeyOwned;
use crate::core_crypto::entities::lwe_secret_key::LweSecretKeyView;
use crate::shortint::backward_compatibility::noise_squashing::NoiseSquashingPrivateKeyVersions;
use crate::shortint::ciphertext::SquashedNoiseCiphertext;
use crate::shortint::encoding::{PaddingBit, ShortintEncoding};
use crate::shortint::engine::ShortintEngine;
use crate::shortint::list_compression::NoiseSquashingCompressionPrivateKey;
use crate::shortint::parameters::noise_squashing::NoiseSquashingParameters;
use crate::shortint::parameters::ModulusSwitchType;
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
        self.as_view().decrypt_squashed_noise_ciphertext(ciphertext)
    }

    pub fn post_noise_squashing_secret_key(&self) -> &GlweSecretKeyOwned<u128> {
        &self.post_noise_squashing_secret_key
    }

    pub fn noise_squashing_parameters(&self) -> NoiseSquashingParameters {
        self.params
    }

    pub(crate) fn as_view(&self) -> NoiseSquashingPrivateKeyView<'_> {
        self.into()
    }

    pub fn from_raw_parts(
        post_noise_squashing_secret_key: GlweSecretKeyOwned<u128>,
        params: NoiseSquashingParameters,
    ) -> Self {
        assert_eq!(
            post_noise_squashing_secret_key.polynomial_size(),
            params.polynomial_size
        );
        assert_eq!(
            post_noise_squashing_secret_key.glwe_dimension(),
            params.glwe_dimension
        );
        Self {
            post_noise_squashing_secret_key,
            params,
        }
    }

    pub fn into_raw_parts(self) -> (GlweSecretKeyOwned<u128>, NoiseSquashingParameters) {
        (self.post_noise_squashing_secret_key, self.params)
    }

    pub fn post_noise_squashing_lwe_secret_key(&self) -> LweSecretKeyView<'_, u128> {
        self.post_noise_squashing_secret_key.as_lwe_secret_key()
    }
}

pub(crate) struct NoiseSquashingPrivateKeyView<'a> {
    post_noise_squashing_secret_key: &'a GlweSecretKeyOwned<u128>,
    params: NoiseSquashingParameters,
}

impl NoiseSquashingPrivateKeyView<'_> {
    #[allow(unused, reason = "It's only used in integer module")]
    pub fn noise_squashing_parameters(&self) -> NoiseSquashingParameters {
        self.params
    }
}

impl<'a> From<&'a NoiseSquashingPrivateKey> for NoiseSquashingPrivateKeyView<'a> {
    fn from(value: &'a NoiseSquashingPrivateKey) -> Self {
        Self {
            post_noise_squashing_secret_key: &value.post_noise_squashing_secret_key,
            params: value.params,
        }
    }
}

impl<'a> From<&'a NoiseSquashingCompressionPrivateKey> for NoiseSquashingPrivateKeyView<'a> {
    fn from(value: &'a NoiseSquashingCompressionPrivateKey) -> Self {
        Self {
            post_noise_squashing_secret_key: &value.post_packing_ks_key,
            params: NoiseSquashingParameters {
                glwe_dimension: value.params.packing_ks_glwe_dimension,
                polynomial_size: value.params.packing_ks_polynomial_size,
                glwe_noise_distribution: value.params.packing_ks_key_noise_distribution,
                decomp_base_log: value.params.packing_ks_base_log,
                decomp_level_count: value.params.packing_ks_level,
                // Dummy value
                modulus_switch_noise_reduction_params: ModulusSwitchType::Standard,
                message_modulus: value.params.message_modulus,
                carry_modulus: value.params.carry_modulus,
                ciphertext_modulus: value.params.ciphertext_modulus,
            },
        }
    }
}

impl NoiseSquashingPrivateKeyView<'_> {
    pub(crate) fn decrypt_squashed_noise_ciphertext(
        &self,
        ciphertext: &SquashedNoiseCiphertext,
    ) -> u128 {
        let plaintext = decrypt_lwe_ciphertext(
            &self.post_noise_squashing_secret_key.as_lwe_secret_key(),
            ciphertext.lwe_ciphertext(),
        );

        let encoding = ShortintEncoding {
            ciphertext_modulus: self.params.ciphertext_modulus,
            message_modulus: ciphertext.message_modulus(),
            carry_modulus: ciphertext.carry_modulus(),
            padding_bit: PaddingBit::Yes,
        };

        encoding.decode(plaintext).0
    }
}
