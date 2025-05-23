use crate::conformance::ParameterSetConformant;
use crate::core_crypto::algorithms::lwe_keyswitch_key_generation::allocate_and_generate_new_seeded_lwe_keyswitch_key;
use crate::core_crypto::entities::seeded_lwe_keyswitch_key::SeededLweKeyswitchKeyOwned;
use crate::shortint::atomic_pattern::ks32::KS32AtomicPatternServerKey;
use crate::shortint::backward_compatibility::atomic_pattern::CompressedKS32AtomicPatternServerKeyVersions;
use crate::shortint::client_key::atomic_pattern::KS32AtomicPatternClientKey;
use crate::shortint::engine::ShortintEngine;
use crate::shortint::parameters::{KeySwitch32PBSParameters, LweDimension};
use crate::shortint::server_key::ShortintCompressedBootstrappingKey;

use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

/// The definition of the compressed server key elements used in the
/// [`KeySwitch32`](crate::shortint::atomic_pattern::AtomicPatternKind::KeySwitch32) atomic pattern
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(CompressedKS32AtomicPatternServerKeyVersions)]
pub struct CompressedKS32AtomicPatternServerKey {
    key_switching_key: SeededLweKeyswitchKeyOwned<u32>,
    bootstrapping_key: ShortintCompressedBootstrappingKey<u32>,
}

impl CompressedKS32AtomicPatternServerKey {
    pub fn new(cks: &KS32AtomicPatternClientKey, engine: &mut ShortintEngine) -> Self {
        let params = &cks.parameters;

        let in_key = cks.small_lwe_secret_key();

        let out_key = &cks.glwe_secret_key;

        let bootstrapping_key_base =
            engine.new_compressed_bootstrapping_key_ks32(*params, &in_key, out_key);

        // Creation of the key switching key
        let key_switching_key = allocate_and_generate_new_seeded_lwe_keyswitch_key(
            &cks.large_lwe_secret_key(),
            &in_key,
            params.ks_base_log(),
            params.ks_level(),
            params.lwe_noise_distribution(),
            params.post_keyswitch_ciphertext_modulus(),
            &mut engine.seeder,
        );

        Self::from_raw_parts(key_switching_key, bootstrapping_key_base)
    }

    pub fn from_raw_parts(
        key_switching_key: SeededLweKeyswitchKeyOwned<u32>,
        bootstrapping_key: ShortintCompressedBootstrappingKey<u32>,
    ) -> Self {
        assert_eq!(
            key_switching_key.input_key_lwe_dimension(),
            bootstrapping_key.output_lwe_dimension(),
            "Mismatch between the input SeededLweKeyswitchKey LweDimension ({:?}) \
            and the ShortintCompressedBootstrappingKey output LweDimension ({:?})",
            key_switching_key.input_key_lwe_dimension(),
            bootstrapping_key.output_lwe_dimension()
        );

        assert_eq!(
            key_switching_key.output_key_lwe_dimension(),
            bootstrapping_key.input_lwe_dimension(),
            "Mismatch between the output SeededLweKeyswitchKey LweDimension ({:?}) \
            and the ShortintCompressedBootstrappingKey input LweDimension ({:?})",
            key_switching_key.output_key_lwe_dimension(),
            bootstrapping_key.input_lwe_dimension()
        );

        Self {
            key_switching_key,
            bootstrapping_key,
        }
    }

    pub fn ciphertext_lwe_dimension(&self) -> LweDimension {
        // KS32 is always KeyswitchBootstrap, meaning Ciphertext is under the big LWE secret key
        self.key_switching_key.input_key_lwe_dimension()
    }

    pub fn key_switching_key(&self) -> &SeededLweKeyswitchKeyOwned<u32> {
        &self.key_switching_key
    }

    pub fn bootstrapping_key(&self) -> &ShortintCompressedBootstrappingKey<u32> {
        &self.bootstrapping_key
    }

    pub fn decompress(&self) -> KS32AtomicPatternServerKey {
        let Self {
            key_switching_key,
            bootstrapping_key,
        } = self;

        let ciphertext_modulus = bootstrapping_key.ciphertext_modulus();

        let (key_switching_key, bootstrapping_key) = rayon::join(
            || {
                key_switching_key
                    .as_view()
                    .par_decompress_into_lwe_keyswitch_key()
            },
            || bootstrapping_key.decompress(),
        );

        KS32AtomicPatternServerKey::from_raw_parts(
            key_switching_key,
            bootstrapping_key,
            ciphertext_modulus,
        )
    }
}

impl ParameterSetConformant for CompressedKS32AtomicPatternServerKey {
    type ParameterSet = KeySwitch32PBSParameters;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        let Self {
            key_switching_key,
            bootstrapping_key,
        } = self;

        let ksk_ok = key_switching_key.is_conformant(&parameter_set.into());
        let bsk_ok = bootstrapping_key.is_conformant(&parameter_set.into());

        ksk_ok && bsk_ok
    }
}
