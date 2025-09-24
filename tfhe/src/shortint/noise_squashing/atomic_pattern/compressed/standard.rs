use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

use crate::shortint::backward_compatibility::noise_squashing::CompressedStandardAtomicPatternNoiseSquashingKeyVersions;
use crate::shortint::client_key::atomic_pattern::StandardAtomicPatternClientKey;
use crate::shortint::noise_squashing::atomic_pattern::standard::StandardAtomicPatternNoiseSquashingKey;
use crate::shortint::noise_squashing::{
    CompressedShortint128BootstrappingKey, NoiseSquashingPrivateKey,
};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(CompressedStandardAtomicPatternNoiseSquashingKeyVersions)]
pub struct CompressedStandardAtomicPatternNoiseSquashingKey {
    bootstrapping_key: CompressedShortint128BootstrappingKey<u64>,
}

impl CompressedStandardAtomicPatternNoiseSquashingKey {
    pub fn new(
        cks: &StandardAtomicPatternClientKey,
        noise_squashing_private_key: &NoiseSquashingPrivateKey,
    ) -> Self {
        let parameters = cks.parameters;

        let bootstrapping_key = CompressedShortint128BootstrappingKey::new(
            &cks.lwe_secret_key,
            parameters.ciphertext_modulus(),
            parameters.lwe_noise_distribution(),
            noise_squashing_private_key,
        );

        Self { bootstrapping_key }
    }

    pub fn decompress(&self) -> StandardAtomicPatternNoiseSquashingKey {
        let bootstrapping_key = self.bootstrapping_key.decompress();

        StandardAtomicPatternNoiseSquashingKey::from_raw_parts(bootstrapping_key)
    }

    pub fn from_raw_parts(bootstrapping_key: CompressedShortint128BootstrappingKey<u64>) -> Self {
        Self { bootstrapping_key }
    }

    pub fn into_raw_parts(self) -> CompressedShortint128BootstrappingKey<u64> {
        self.bootstrapping_key
    }

    pub fn bootstrapping_key(&self) -> &CompressedShortint128BootstrappingKey<u64> {
        &self.bootstrapping_key
    }
}
