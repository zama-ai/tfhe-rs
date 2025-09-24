use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

use crate::shortint::backward_compatibility::noise_squashing::CompressedKS32AtomicPatternNoiseSquashingKeyVersions;
use crate::shortint::client_key::atomic_pattern::KS32AtomicPatternClientKey;
use crate::shortint::noise_squashing::atomic_pattern::ks32::KS32AtomicPatternNoiseSquashingKey;
use crate::shortint::noise_squashing::{
    CompressedShortint128BootstrappingKey, NoiseSquashingPrivateKey,
};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(CompressedKS32AtomicPatternNoiseSquashingKeyVersions)]
pub struct CompressedKS32AtomicPatternNoiseSquashingKey {
    bootstrapping_key: CompressedShortint128BootstrappingKey<u32>,
}

impl CompressedKS32AtomicPatternNoiseSquashingKey {
    pub fn new(
        cks: &KS32AtomicPatternClientKey,
        noise_squashing_private_key: &NoiseSquashingPrivateKey,
    ) -> Self {
        let parameters = cks.parameters;

        let bootstrapping_key = CompressedShortint128BootstrappingKey::new(
            &cks.lwe_secret_key,
            parameters.post_keyswitch_ciphertext_modulus(),
            parameters.lwe_noise_distribution(),
            noise_squashing_private_key,
        );

        Self { bootstrapping_key }
    }

    pub fn decompress(&self) -> KS32AtomicPatternNoiseSquashingKey {
        let bootstrapping_key = self.bootstrapping_key.decompress();

        KS32AtomicPatternNoiseSquashingKey::from_raw_parts(bootstrapping_key)
    }

    pub fn from_raw_parts(bootstrapping_key: CompressedShortint128BootstrappingKey<u32>) -> Self {
        Self { bootstrapping_key }
    }

    pub fn into_raw_parts(self) -> CompressedShortint128BootstrappingKey<u32> {
        self.bootstrapping_key
    }

    pub fn bootstrapping_key(&self) -> &CompressedShortint128BootstrappingKey<u32> {
        &self.bootstrapping_key
    }
}
