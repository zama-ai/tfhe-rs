use super::server_keys::NoiseSquashingCompressionKeyConformanceParams;
use super::{
    CompressionKey, CompressionKeyConformanceParams, CompressionPrivateKeys, DecompressionKey,
    NoiseSquashingCompressionKey,
};
use crate::conformance::ParameterSetConformant;
use crate::core_crypto::prelude::{
    CiphertextModulus, CiphertextModulusLog, GlweSize, LweCiphertextCount,
    LwePackingKeyswitchKeyConformanceParams, PolynomialSize, SeededLwePackingKeyswitchKey,
};
use crate::shortint::backward_compatibility::list_compression::{
    CompressedCompressionKeyVersions, CompressedDecompressionKeyVersions,
    CompressedNoiseSquashingCompressionKeyVersions,
};
use crate::shortint::client_key::ClientKey;
use crate::shortint::server_key::ShortintCompressedBootstrappingKey;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use tfhe_versionable::Versionize;

#[derive(Clone, Debug, Serialize, Deserialize, Versionize)]
#[versionize(CompressedCompressionKeyVersions)]
pub struct CompressedCompressionKey {
    pub packing_key_switching_key: SeededLwePackingKeyswitchKey<Vec<u64>>,
    pub lwe_per_glwe: LweCiphertextCount,
    pub storage_log_modulus: CiphertextModulusLog,
}

impl CompressedCompressionKey {
    pub fn decompress(&self) -> CompressionKey {
        let packing_key_switching_key = self
            .packing_key_switching_key
            .as_view()
            .decompress_into_lwe_packing_keyswitch_key();

        CompressionKey {
            packing_key_switching_key,
            lwe_per_glwe: self.lwe_per_glwe,
            storage_log_modulus: self.storage_log_modulus,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Versionize)]
#[versionize(CompressedDecompressionKeyVersions)]
pub struct CompressedDecompressionKey {
    pub(crate) bsk: ShortintCompressedBootstrappingKey<u64>,
    pub(crate) lwe_per_glwe: LweCiphertextCount,
}

impl CompressedDecompressionKey {
    pub fn glwe_size(&self) -> GlweSize {
        self.bsk.glwe_size()
    }
    pub fn polynomial_size(&self) -> PolynomialSize {
        self.bsk.polynomial_size()
    }
    pub fn ciphertext_modulus(&self) -> CiphertextModulus<u64> {
        self.bsk.ciphertext_modulus()
    }

    pub fn decompress(&self) -> DecompressionKey {
        let bsk = self.bsk.decompress();

        DecompressionKey {
            bsk,
            lwe_per_glwe: self.lwe_per_glwe,
        }
    }
}

impl ClientKey {
    pub fn new_compressed_compression_decompression_keys(
        &self,
        private_compression_key: &CompressionPrivateKeys,
    ) -> (CompressedCompressionKey, CompressedDecompressionKey) {
        (
            self.atomic_pattern
                .new_compressed_compression_key(private_compression_key),
            self.atomic_pattern
                .new_compressed_decompression_key(private_compression_key),
        )
    }
}

impl ParameterSetConformant for CompressedCompressionKey {
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

impl ParameterSetConformant for CompressedDecompressionKey {
    type ParameterSet = CompressionKeyConformanceParams;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        let Self { bsk, lwe_per_glwe } = self;

        let params = parameter_set.into();

        bsk.is_conformant(&params) && *lwe_per_glwe == parameter_set.lwe_per_glwe
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Versionize)]
#[versionize(CompressedNoiseSquashingCompressionKeyVersions)]
pub struct CompressedNoiseSquashingCompressionKey {
    pub packing_key_switching_key: SeededLwePackingKeyswitchKey<Vec<u128>>,
    pub lwe_per_glwe: LweCiphertextCount,
}

impl CompressedNoiseSquashingCompressionKey {
    pub fn decompress(&self) -> NoiseSquashingCompressionKey {
        let packing_key_switching_key = self
            .packing_key_switching_key
            .as_view()
            .decompress_into_lwe_packing_keyswitch_key();

        NoiseSquashingCompressionKey {
            packing_key_switching_key,
            lwe_per_glwe: self.lwe_per_glwe,
        }
    }

    /// Construct from raw parts
    ///
    /// # Panics
    ///
    /// Panics if lwe_per_glwe is greater than the output polynomial size of the packing key
    /// switching key
    pub fn from_raw_parts(
        packing_key_switching_key: SeededLwePackingKeyswitchKey<Vec<u128>>,
        lwe_per_glwe: LweCiphertextCount,
    ) -> Self {
        assert!(
            lwe_per_glwe.0 <= packing_key_switching_key.output_polynomial_size().0,
            "Cannot pack more than polynomial_size(={}) elements per glwe, {} requested",
            packing_key_switching_key.output_polynomial_size().0,
            lwe_per_glwe.0,
        );
        Self {
            packing_key_switching_key,
            lwe_per_glwe,
        }
    }

    pub fn into_raw_parts(self) -> (SeededLwePackingKeyswitchKey<Vec<u128>>, LweCiphertextCount) {
        let Self {
            packing_key_switching_key,
            lwe_per_glwe,
        } = self;

        (packing_key_switching_key, lwe_per_glwe)
    }
}

impl ParameterSetConformant for CompressedNoiseSquashingCompressionKey {
    type ParameterSet = NoiseSquashingCompressionKeyConformanceParams;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        let Self {
            packing_key_switching_key,
            lwe_per_glwe,
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
    }
}
