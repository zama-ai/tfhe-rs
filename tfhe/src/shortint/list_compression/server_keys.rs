use super::CompressionPrivateKeys;
use crate::conformance::ParameterSetConformant;
use crate::core_crypto::prelude::*;
use crate::shortint::atomic_pattern::AtomicPatternParameters;
use crate::shortint::backward_compatibility::list_compression::{
    CompressionKeyVersions, DecompressionKeyVersions,
};
use crate::shortint::client_key::ClientKey;
use crate::shortint::engine::ShortintEngine;
use crate::shortint::parameters::{CompressionParameters, PolynomialSize};
use crate::shortint::server_key::{
    PBSConformanceParams, PbsTypeConformanceParams, ShortintBootstrappingKey,
};
use crate::shortint::EncryptionKeyChoice;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use tfhe_versionable::Versionize;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Versionize)]
#[versionize(CompressionKeyVersions)]
pub struct CompressionKey {
    pub packing_key_switching_key: LwePackingKeyswitchKey<Vec<u64>>,
    pub lwe_per_glwe: LweCiphertextCount,
    pub storage_log_modulus: CiphertextModulusLog,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(DecompressionKeyVersions)]
pub struct DecompressionKey {
    pub blind_rotate_key: ShortintBootstrappingKey<u64>,
    pub lwe_per_glwe: LweCiphertextCount,
}

impl DecompressionKey {
    pub fn out_glwe_size(&self) -> GlweSize {
        self.blind_rotate_key.glwe_size()
    }

    pub fn out_polynomial_size(&self) -> PolynomialSize {
        self.blind_rotate_key.polynomial_size()
    }
}

impl ClientKey {
    pub fn new_compression_decompression_keys(
        &self,
        private_compression_key: &CompressionPrivateKeys,
    ) -> (CompressionKey, DecompressionKey) {
        let pbs_parameters = self.parameters.pbs_parameters().unwrap();

        assert_eq!(
            pbs_parameters.encryption_key_choice(),
            EncryptionKeyChoice::Big,
            "Compression is only compatible with ciphertext in post PBS dimension"
        );

        let params = private_compression_key.params;

        let mut engine = ShortintEngine::new();

        let packing_key_switching_key = allocate_and_generate_new_lwe_packing_keyswitch_key(
            &self.large_lwe_secret_key(),
            &private_compression_key.post_packing_ks_key,
            params.packing_ks_base_log,
            params.packing_ks_level,
            params.packing_ks_key_noise_distribution,
            self.parameters.ciphertext_modulus(),
            &mut engine.encryption_generator,
        );

        assert!(
            private_compression_key.params.storage_log_modulus.0
                <= pbs_parameters
                    .polynomial_size()
                    .to_blind_rotation_input_modulus_log()
                    .0,
            "Compression parameters say to store more bits than useful"
        );

        let glwe_compression_key = CompressionKey {
            packing_key_switching_key,
            lwe_per_glwe: params.lwe_per_glwe,
            storage_log_modulus: private_compression_key.params.storage_log_modulus,
        };

        let blind_rotate_key = ShortintBootstrappingKey::Classic {
            bsk: engine.new_classic_bootstrapping_key(
                &private_compression_key
                    .post_packing_ks_key
                    .as_lwe_secret_key(),
                &self.glwe_secret_key,
                self.parameters.glwe_noise_distribution(),
                private_compression_key.params.br_base_log,
                private_compression_key.params.br_level,
                self.parameters.ciphertext_modulus(),
            ),
            modulus_switch_noise_reduction_key: None,
        };

        let glwe_decompression_key = DecompressionKey {
            blind_rotate_key,
            lwe_per_glwe: params.lwe_per_glwe,
        };

        (glwe_compression_key, glwe_decompression_key)
    }
}

pub struct CompressionKeyConformanceParams {
    pub br_level: DecompositionLevelCount,
    pub br_base_log: DecompositionBaseLog,
    pub packing_ks_level: DecompositionLevelCount,
    pub packing_ks_base_log: DecompositionBaseLog,
    pub packing_ks_polynomial_size: PolynomialSize,
    pub packing_ks_glwe_dimension: GlweDimension,
    pub lwe_per_glwe: LweCiphertextCount,
    pub storage_log_modulus: CiphertextModulusLog,
    pub uncompressed_polynomial_size: PolynomialSize,
    pub uncompressed_glwe_dimension: GlweDimension,
    pub cipherext_modulus: CiphertextModulus<u64>,
}

impl From<(AtomicPatternParameters, CompressionParameters)> for CompressionKeyConformanceParams {
    fn from(
        (ap_params, compression_params): (AtomicPatternParameters, CompressionParameters),
    ) -> Self {
        Self {
            br_level: compression_params.br_level,
            br_base_log: compression_params.br_base_log,
            packing_ks_level: compression_params.packing_ks_level,
            packing_ks_base_log: compression_params.packing_ks_base_log,
            packing_ks_polynomial_size: compression_params.packing_ks_polynomial_size,
            packing_ks_glwe_dimension: compression_params.packing_ks_glwe_dimension,
            lwe_per_glwe: compression_params.lwe_per_glwe,
            storage_log_modulus: compression_params.storage_log_modulus,
            uncompressed_polynomial_size: ap_params.polynomial_size(),
            uncompressed_glwe_dimension: ap_params.glwe_dimension(),
            cipherext_modulus: ap_params.ciphertext_modulus(),
        }
    }
}

impl ParameterSetConformant for CompressionKey {
    type ParameterSet = CompressionKeyConformanceParams;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        let Self {
            packing_key_switching_key,
            lwe_per_glwe,
            storage_log_modulus,
        } = self;

        let params = LwePackingKeyswitchKeyConformanceParams {
            decomp_base_log: parameter_set.packing_ks_base_log,
            decomp_level_count: parameter_set.packing_ks_level,
            input_lwe_dimension: parameter_set
                .uncompressed_glwe_dimension
                .to_equivalent_lwe_dimension(parameter_set.uncompressed_polynomial_size),
            output_glwe_size: parameter_set.packing_ks_glwe_dimension.to_glwe_size(),
            output_polynomial_size: parameter_set.packing_ks_polynomial_size,
            ciphertext_modulus: parameter_set.cipherext_modulus,
        };

        packing_key_switching_key.is_conformant(&params)
            && *lwe_per_glwe == parameter_set.lwe_per_glwe
            && *storage_log_modulus == parameter_set.storage_log_modulus
    }
}

impl ParameterSetConformant for DecompressionKey {
    type ParameterSet = CompressionKeyConformanceParams;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        let Self {
            blind_rotate_key,
            lwe_per_glwe,
        } = self;

        let params: PBSConformanceParams = parameter_set.into();

        blind_rotate_key.is_conformant(&params) && *lwe_per_glwe == parameter_set.lwe_per_glwe
    }
}

impl From<&CompressionKeyConformanceParams> for PBSConformanceParams {
    fn from(value: &CompressionKeyConformanceParams) -> Self {
        Self {
            in_lwe_dimension: value
                .packing_ks_glwe_dimension
                .to_equivalent_lwe_dimension(value.packing_ks_polynomial_size),
            out_glwe_dimension: value.uncompressed_glwe_dimension,
            out_polynomial_size: value.uncompressed_polynomial_size,
            base_log: value.br_base_log,
            level: value.br_level,
            ciphertext_modulus: value.cipherext_modulus,
            pbs_type: PbsTypeConformanceParams::Classic {
                modulus_switch_noise_reduction: None,
            },
        }
    }
}
