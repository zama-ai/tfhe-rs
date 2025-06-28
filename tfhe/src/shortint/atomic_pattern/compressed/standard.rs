use crate::conformance::ParameterSetConformant;
use crate::core_crypto::algorithms::lwe_keyswitch_key_generation::allocate_and_generate_new_seeded_lwe_keyswitch_key;
use crate::core_crypto::entities::seeded_lwe_keyswitch_key::SeededLweKeyswitchKeyOwned;
use crate::shortint::atomic_pattern::standard::StandardAtomicPatternServerKey;
use crate::shortint::backward_compatibility::atomic_pattern::CompressedStandardAtomicPatternServerKeyVersions;
use crate::shortint::client_key::atomic_pattern::StandardAtomicPatternClientKey;
use crate::shortint::engine::ShortintEngine;
use crate::shortint::parameters::{CiphertextModulus, LweDimension, PBSOrder, PBSParameters};
use crate::shortint::server_key::ShortintCompressedBootstrappingKey;

use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

/// The definition of the compressed server key elements used in the
/// [`Standard`](crate::shortint::atomic_pattern::AtomicPatternKind::Standard) atomic pattern
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(CompressedStandardAtomicPatternServerKeyVersions)]
pub struct CompressedStandardAtomicPatternServerKey {
    key_switching_key: SeededLweKeyswitchKeyOwned<u64>,
    bootstrapping_key: ShortintCompressedBootstrappingKey<u64>,
    pbs_order: PBSOrder,
}

impl CompressedStandardAtomicPatternServerKey {
    pub fn new(cks: &StandardAtomicPatternClientKey, engine: &mut ShortintEngine) -> Self {
        let params = &cks.parameters;

        let in_key = &cks.small_lwe_secret_key();

        let out_key = &cks.glwe_secret_key;

        let bootstrapping_key_base =
            engine.new_compressed_bootstrapping_key(*params, in_key, out_key);

        // Creation of the key switching key
        let key_switching_key = allocate_and_generate_new_seeded_lwe_keyswitch_key(
            &cks.large_lwe_secret_key(),
            &cks.small_lwe_secret_key(),
            params.ks_base_log(),
            params.ks_level(),
            params.lwe_noise_distribution(),
            params.ciphertext_modulus(),
            &mut engine.seeder,
        );

        Self::from_raw_parts(
            key_switching_key,
            bootstrapping_key_base,
            params.encryption_key_choice().into(),
        )
    }

    pub fn from_raw_parts(
        key_switching_key: SeededLweKeyswitchKeyOwned<u64>,
        bootstrapping_key: ShortintCompressedBootstrappingKey<u64>,
        pbs_order: PBSOrder,
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

        assert_eq!(
            key_switching_key.ciphertext_modulus(),
            bootstrapping_key.ciphertext_modulus(),
            "Mismatch between the output SeededLweKeyswitchKey CiphertextModulus ({:?}) \
            and the ShortintCompressedBootstrappingKey input CiphertextModulus ({:?})",
            key_switching_key.ciphertext_modulus(),
            bootstrapping_key.ciphertext_modulus(),
        );

        Self {
            key_switching_key,
            bootstrapping_key,
            pbs_order,
        }
    }

    pub fn into_raw_parts(
        self,
    ) -> (
        SeededLweKeyswitchKeyOwned<u64>,
        ShortintCompressedBootstrappingKey<u64>,
        PBSOrder,
    ) {
        let Self {
            key_switching_key,
            bootstrapping_key,
            pbs_order,
        } = self;

        (key_switching_key, bootstrapping_key, pbs_order)
    }

    pub fn ciphertext_lwe_dimension(&self) -> LweDimension {
        match self.pbs_order() {
            PBSOrder::KeyswitchBootstrap => self.key_switching_key.input_key_lwe_dimension(),
            PBSOrder::BootstrapKeyswitch => self.key_switching_key.output_key_lwe_dimension(),
        }
    }

    pub fn key_switching_key(&self) -> &SeededLweKeyswitchKeyOwned<u64> {
        &self.key_switching_key
    }

    pub fn bootstrapping_key(&self) -> &ShortintCompressedBootstrappingKey<u64> {
        &self.bootstrapping_key
    }

    pub fn bootstrapping_key_mut(&mut self) -> &mut ShortintCompressedBootstrappingKey<u64> {
        &mut self.bootstrapping_key
    }

    pub fn pbs_order(&self) -> PBSOrder {
        self.pbs_order
    }

    pub fn ciphertext_modulus(&self) -> CiphertextModulus {
        self.bootstrapping_key.ciphertext_modulus()
    }

    pub fn decompress(&self) -> StandardAtomicPatternServerKey {
        let Self {
            key_switching_key,
            bootstrapping_key,
            pbs_order,
        } = self;

        let (key_switching_key, bootstrapping_key) = rayon::join(
            || {
                key_switching_key
                    .as_view()
                    .par_decompress_into_lwe_keyswitch_key()
            },
            || bootstrapping_key.decompress(),
        );

        StandardAtomicPatternServerKey::from_raw_parts(
            key_switching_key,
            bootstrapping_key,
            *pbs_order,
        )
    }
}

impl ParameterSetConformant for CompressedStandardAtomicPatternServerKey {
    type ParameterSet = PBSParameters;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        let Self {
            key_switching_key,
            bootstrapping_key,
            pbs_order,
        } = self;

        let ksk_ok = key_switching_key.is_conformant(&parameter_set.into());
        let bsk_ok = bootstrapping_key.is_conformant(&parameter_set.into());

        let params_pbs_order: PBSOrder = parameter_set.encryption_key_choice().into();
        let pbs_order_ok = *pbs_order == params_pbs_order;

        ksk_ok && bsk_ok && pbs_order_ok
    }
}
