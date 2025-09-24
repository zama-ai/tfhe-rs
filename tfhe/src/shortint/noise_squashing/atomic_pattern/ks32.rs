use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

use crate::core_crypto::prelude::{
    generate_programmable_bootstrap_glwe_lut, keyswitch_lwe_ciphertext_with_scalar_change,
    CiphertextModulus as CoreCiphertextModulus, LweCiphertext,
};
use crate::shortint::atomic_pattern::AtomicPattern;
use crate::shortint::backward_compatibility::noise_squashing::KS32AtomicPatternNoiseSquashingKeyVersions;
use crate::shortint::ciphertext::SquashedNoiseCiphertext;
use crate::shortint::client_key::atomic_pattern::KS32AtomicPatternClientKey;
use crate::shortint::encoding::compute_delta;
use crate::shortint::engine::ShortintEngine;
use crate::shortint::noise_squashing::{NoiseSquashingPrivateKey, Shortint128BootstrappingKey};
use crate::shortint::server_key::{
    apply_programmable_bootstrap_128, KS32ServerKeyView, ServerKeyView,
};
use crate::shortint::{CarryModulus, Ciphertext, MessageModulus, PaddingBit};

use super::NoiseSquashingAtomicPattern;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(KS32AtomicPatternNoiseSquashingKeyVersions)]
pub struct KS32AtomicPatternNoiseSquashingKey {
    bootstrapping_key: Shortint128BootstrappingKey<u32>,
}

impl KS32AtomicPatternNoiseSquashingKey {
    pub fn new(
        cks: &KS32AtomicPatternClientKey,
        noise_squashing_private_key: &NoiseSquashingPrivateKey,
    ) -> Self {
        let parameters = cks.parameters;

        let bootstrapping_key = Shortint128BootstrappingKey::new(
            &cks.lwe_secret_key,
            parameters.post_keyswitch_ciphertext_modulus(),
            parameters.lwe_noise_distribution(),
            noise_squashing_private_key,
        );

        Self { bootstrapping_key }
    }

    pub fn from_raw_parts(bootstrapping_key: Shortint128BootstrappingKey<u32>) -> Self {
        Self { bootstrapping_key }
    }

    pub fn into_raw_parts(self) -> Shortint128BootstrappingKey<u32> {
        self.bootstrapping_key
    }

    pub fn bootstrapping_key(&self) -> &Shortint128BootstrappingKey<u32> {
        &self.bootstrapping_key
    }
}

impl NoiseSquashingAtomicPattern for KS32AtomicPatternNoiseSquashingKey {
    fn squash_ciphertext_noise(
        &self,
        ciphertext: &Ciphertext,
        src_server_key: ServerKeyView,
        output_message_modulus: MessageModulus,
        output_carry_modulus: CarryModulus,
        output_ciphertext_modulus: CoreCiphertextModulus<u128>,
    ) -> crate::Result<SquashedNoiseCiphertext> {
        let sks_ap = src_server_key.atomic_pattern.kind();
        let src_server_key: KS32ServerKeyView = src_server_key.try_into().map_err(|_| {
            crate::error!(
                "Incompatible atomic pattern between noise squashing key and server key (noise \
squashing ap: KS32, server key ap: {:?})",
                sks_ap
            )
        })?;

        let mut lwe_before_ms = LweCiphertext::new(
            0u32,
            src_server_key
                .atomic_pattern
                .key_switching_key
                .output_lwe_size(),
            src_server_key
                .atomic_pattern
                .key_switching_key
                .ciphertext_modulus(),
        );

        keyswitch_lwe_ciphertext_with_scalar_change(
            &src_server_key.atomic_pattern.key_switching_key,
            &ciphertext.ct,
            &mut lwe_before_ms,
        );

        let output_lwe_size = self.bootstrapping_key.output_lwe_dimension().to_lwe_size();

        let mut res = SquashedNoiseCiphertext::new_zero(
            output_lwe_size,
            output_ciphertext_modulus,
            output_message_modulus,
            output_carry_modulus,
        );

        let bsk_glwe_size = self.bootstrapping_key.glwe_size();
        let bsk_polynomial_size = self.bootstrapping_key.polynomial_size();

        let delta = compute_delta(
            output_ciphertext_modulus,
            output_message_modulus,
            output_carry_modulus,
            PaddingBit::Yes,
        );

        let output_cleartext_space = output_message_modulus.0 * output_carry_modulus.0;

        let id_lut = generate_programmable_bootstrap_glwe_lut(
            bsk_polynomial_size,
            bsk_glwe_size,
            output_cleartext_space.try_into().unwrap(),
            output_ciphertext_modulus,
            delta,
            |x| x,
        );

        ShortintEngine::with_thread_local_mut(|engine| {
            let buffers = engine.get_computation_buffers();

            apply_programmable_bootstrap_128(
                &self.bootstrapping_key,
                &lwe_before_ms,
                res.lwe_ciphertext_mut(),
                &id_lut,
                buffers,
            );
        });

        res.set_degree(ciphertext.degree);

        Ok(res)
    }
}
