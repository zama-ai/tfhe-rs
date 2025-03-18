use super::{NoiseSquashingKey, NoiseSquashingPrivateKey};
use crate::core_crypto::algorithms::lwe_bootstrap_key_conversion::par_convert_standard_lwe_bootstrap_key_to_fourier_128;
use crate::core_crypto::algorithms::lwe_bootstrap_key_generation::par_allocate_and_generate_new_seeded_lwe_bootstrap_key;
use crate::core_crypto::commons::math::random::Seeder;
use crate::core_crypto::entities::{Fourier128LweBootstrapKeyOwned, SeededLweBootstrapKeyOwned};
use crate::shortint::backward_compatibility::noise_squashing::CompressedNoiseSquashingKeyVersions;
use crate::shortint::client_key::ClientKey;
use crate::shortint::engine::ShortintEngine;
use crate::shortint::parameters::CoreCiphertextModulus;
use crate::shortint::server_key::CompressedModulusSwitchNoiseReductionKey;
use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(CompressedNoiseSquashingKeyVersions)]
pub struct CompressedNoiseSquashingKey {
    bootstrapping_key: SeededLweBootstrapKeyOwned<u128>,
    modulus_switch_noise_reduction_key: Option<CompressedModulusSwitchNoiseReductionKey>,
    output_ciphertext_modulus: CoreCiphertextModulus<u128>,
}

impl ClientKey {
    pub fn new_compressed_noise_squashing_key(
        &self,
        noise_squashing_private_key: &NoiseSquashingPrivateKey,
    ) -> CompressedNoiseSquashingKey {
        let pbs_parameters = self
            .parameters
            .pbs_parameters()
            .expect("NoiseSquashingKey generation requires PBSParameters");

        let noise_squashing_parameters = noise_squashing_private_key.noise_squashing_parameters();

        let (bootstrapping_key, modulus_switch_noise_reduction_key) =
            ShortintEngine::with_thread_local_mut(|engine| {
                let seeded_bsk = par_allocate_and_generate_new_seeded_lwe_bootstrap_key(
                    &self.lwe_secret_key,
                    noise_squashing_private_key.post_noise_squashing_secret_key(),
                    noise_squashing_parameters.decomp_base_log,
                    noise_squashing_parameters.decomp_level_count,
                    noise_squashing_parameters.glwe_noise_distribution,
                    noise_squashing_parameters.ciphertext_modulus,
                    &mut engine.seeder,
                );

                let modulus_switch_noise_reduction_key = noise_squashing_parameters
                    .modulus_switch_noise_reduction_params
                    .map(|p| {
                        let seed = engine.seeder.seed();
                        CompressedModulusSwitchNoiseReductionKey::new(
                            p,
                            &self.lwe_secret_key,
                            engine,
                            pbs_parameters.ciphertext_modulus(),
                            pbs_parameters.lwe_noise_distribution(),
                            seed.into(),
                        )
                    });

                (seeded_bsk, modulus_switch_noise_reduction_key)
            });

        CompressedNoiseSquashingKey {
            bootstrapping_key,
            modulus_switch_noise_reduction_key,
            output_ciphertext_modulus: noise_squashing_private_key
                .noise_squashing_parameters()
                .ciphertext_modulus,
        }
    }
}

impl CompressedNoiseSquashingKey {
    pub fn new(
        client_key: &ClientKey,
        noise_squashing_private_key: &NoiseSquashingPrivateKey,
    ) -> Self {
        client_key.new_compressed_noise_squashing_key(noise_squashing_private_key)
    }

    pub fn decompress(&self) -> NoiseSquashingKey {
        let (bootstrapping_key, modulus_switch_noise_reduction_key) = {
            let std_bsk = self
                .bootstrapping_key
                .as_view()
                .par_decompress_into_lwe_bootstrap_key();

            let mut fbsk = Fourier128LweBootstrapKeyOwned::new(
                std_bsk.input_lwe_dimension(),
                std_bsk.glwe_size(),
                std_bsk.polynomial_size(),
                std_bsk.decomposition_base_log(),
                std_bsk.decomposition_level_count(),
            );

            par_convert_standard_lwe_bootstrap_key_to_fourier_128(&std_bsk, &mut fbsk);

            (
                fbsk,
                self.modulus_switch_noise_reduction_key
                    .as_ref()
                    .map(|key| key.decompress()),
            )
        };

        NoiseSquashingKey {
            bootstrapping_key,
            modulus_switch_noise_reduction_key,
            output_ciphertext_modulus: self.output_ciphertext_modulus,
        }
    }
}
