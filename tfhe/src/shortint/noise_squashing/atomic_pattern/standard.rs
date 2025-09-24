use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

use crate::core_crypto::prelude::{
    generate_programmable_bootstrap_glwe_lut, keyswitch_lwe_ciphertext, CiphertextModulus,
    LweCiphertext,
};
use crate::shortint::atomic_pattern::AtomicPattern;
use crate::shortint::backward_compatibility::noise_squashing::StandardAtomicPatternNoiseSquashingKeyVersions;
use crate::shortint::ciphertext::SquashedNoiseCiphertext;
use crate::shortint::client_key::atomic_pattern::{
    EncryptionAtomicPattern, StandardAtomicPatternClientKey,
};
use crate::shortint::encoding::compute_delta;
use crate::shortint::engine::ShortintEngine;
use crate::shortint::noise_squashing::{NoiseSquashingPrivateKey, Shortint128BootstrappingKey};
use crate::shortint::server_key::{
    apply_programmable_bootstrap_128, ServerKeyView, StandardServerKeyView,
};
use crate::shortint::{CarryModulus, Ciphertext, MessageModulus, PBSOrder, PaddingBit};

use super::NoiseSquashingAtomicPattern;

/// The definition of the noise squashing key elements used in the
/// [`Standard`](crate::shortint::atomic_pattern::AtomicPatternKind::Standard) atomic pattern
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(StandardAtomicPatternNoiseSquashingKeyVersions)]
pub struct StandardAtomicPatternNoiseSquashingKey {
    bootstrapping_key: Shortint128BootstrappingKey<u64>,
}

impl StandardAtomicPatternNoiseSquashingKey {
    pub fn new(
        cks: &StandardAtomicPatternClientKey,
        noise_squashing_private_key: &NoiseSquashingPrivateKey,
    ) -> Self {
        let parameters = cks.parameters();

        let bootstrapping_key = Shortint128BootstrappingKey::new(
            &cks.lwe_secret_key,
            parameters.ciphertext_modulus(),
            parameters.lwe_noise_distribution(),
            noise_squashing_private_key,
        );

        Self { bootstrapping_key }
    }

    pub fn from_raw_parts(bootstrapping_key: Shortint128BootstrappingKey<u64>) -> Self {
        Self { bootstrapping_key }
    }

    pub fn into_raw_parts(self) -> Shortint128BootstrappingKey<u64> {
        self.bootstrapping_key
    }

    pub fn bootstrapping_key(&self) -> &Shortint128BootstrappingKey<u64> {
        &self.bootstrapping_key
    }
}

impl NoiseSquashingAtomicPattern for StandardAtomicPatternNoiseSquashingKey {
    fn squash_ciphertext_noise(
        &self,
        ciphertext: &Ciphertext,
        src_server_key: ServerKeyView,
        output_message_modulus: MessageModulus,
        output_carry_modulus: CarryModulus,
        output_ciphertext_modulus: CiphertextModulus<u128>,
    ) -> crate::Result<SquashedNoiseCiphertext> {
        let sks_ap = src_server_key.atomic_pattern.kind();
        let src_server_key: StandardServerKeyView = src_server_key.try_into().map_err(|_| {
            crate::error!(
                "Incompatible atomic pattern between noise squashing key and server key (noise \
squashing ap: Standard, server key ap: {:?})",
                sks_ap
            )
        })?;

        let lwe_before_ms = match src_server_key.atomic_pattern.pbs_order {
            // Under the big key, first need to keyswitch
            PBSOrder::KeyswitchBootstrap => {
                let mut after_ks_ct = LweCiphertext::new(
                    0u64,
                    src_server_key
                        .atomic_pattern
                        .key_switching_key
                        .output_lwe_size(),
                    src_server_key
                        .atomic_pattern
                        .key_switching_key
                        .ciphertext_modulus(),
                );

                keyswitch_lwe_ciphertext(
                    &src_server_key.atomic_pattern.key_switching_key,
                    &ciphertext.ct,
                    &mut after_ks_ct,
                );
                after_ks_ct
            }
            // Under the small key, no need to keyswitch
            PBSOrder::BootstrapKeyswitch => ciphertext.ct.clone(),
        };

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
