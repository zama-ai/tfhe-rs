use super::record::CryptoParametersRecord;
use tfhe::shortint::parameters::compact_public_key_only::CompactPublicKeyEncryptionParameters;
use tfhe::shortint::parameters::list_compression::CompressionParameters;
use tfhe::shortint::parameters::{
    NoiseSquashingCompressionParameters, NoiseSquashingParameters, ShortintKeySwitchingParameters,
};
use tfhe::shortint::{AtomicPatternParameters, PBSParameters};

impl From<PBSParameters> for CryptoParametersRecord<u64> {
    fn from(params: PBSParameters) -> Self {
        AtomicPatternParameters::from(params).into()
    }
}

impl From<AtomicPatternParameters> for CryptoParametersRecord<u64> {
    fn from(params: AtomicPatternParameters) -> Self {
        CryptoParametersRecord {
            lwe_dimension: Some(params.lwe_dimension()),
            glwe_dimension: Some(params.glwe_dimension()),
            polynomial_size: Some(params.polynomial_size()),
            lwe_noise_distribution: Some(params.lwe_noise_distribution()),
            glwe_noise_distribution: Some(params.glwe_noise_distribution()),
            pbs_base_log: Some(params.pbs_base_log()),
            pbs_level: Some(params.pbs_level()),
            ks_base_log: Some(params.ks_base_log()),
            ks_level: Some(params.ks_level()),
            message_modulus: Some(params.message_modulus().0),
            carry_modulus: Some(params.carry_modulus().0),
            ciphertext_modulus: Some(
                params
                    .ciphertext_modulus()
                    .try_to()
                    .expect("failed to convert ciphertext modulus"),
            ),
            error_probability: Some(2f64.powf(params.log2_p_fail())),
            ..Default::default()
        }
    }
}

impl From<ShortintKeySwitchingParameters> for CryptoParametersRecord<u64> {
    fn from(params: ShortintKeySwitchingParameters) -> Self {
        CryptoParametersRecord {
            ks_base_log: Some(params.ks_base_log),
            ks_level: Some(params.ks_level),
            ..Default::default()
        }
    }
}

impl From<CompactPublicKeyEncryptionParameters> for CryptoParametersRecord<u64> {
    fn from(params: CompactPublicKeyEncryptionParameters) -> Self {
        CryptoParametersRecord {
            message_modulus: Some(params.message_modulus.0),
            carry_modulus: Some(params.carry_modulus.0),
            ciphertext_modulus: Some(params.ciphertext_modulus),
            ..Default::default()
        }
    }
}

impl From<(CompressionParameters, AtomicPatternParameters)> for CryptoParametersRecord<u64> {
    fn from((comp_params, pbs_params): (CompressionParameters, AtomicPatternParameters)) -> Self {
        CryptoParametersRecord {
            lwe_dimension: Some(pbs_params.lwe_dimension()),
            br_level: Some(comp_params.br_level()),
            br_base_log: Some(comp_params.br_base_log()),
            packing_ks_level: Some(comp_params.packing_ks_level()),
            packing_ks_base_log: Some(comp_params.packing_ks_base_log()),
            packing_ks_polynomial_size: Some(comp_params.packing_ks_polynomial_size()),
            packing_ks_glwe_dimension: Some(comp_params.packing_ks_glwe_dimension()),
            lwe_per_glwe: Some(comp_params.lwe_per_glwe()),
            storage_log_modulus: Some(comp_params.storage_log_modulus()),
            lwe_noise_distribution: Some(pbs_params.encryption_noise_distribution()),
            packing_ks_key_noise_distribution: Some(
                comp_params.packing_ks_key_noise_distribution(),
            ),
            ciphertext_modulus: Some(pbs_params.ciphertext_modulus()),
            error_probability: Some(2f64.powf(pbs_params.log2_p_fail())),
            ..Default::default()
        }
    }
}

impl From<(NoiseSquashingParameters, AtomicPatternParameters)> for CryptoParametersRecord<u64> {
    fn from(
        (noise_squash_params, pbs_params): (NoiseSquashingParameters, AtomicPatternParameters),
    ) -> Self {
        CryptoParametersRecord {
            lwe_dimension: Some(pbs_params.lwe_dimension()),
            glwe_dimension: Some(noise_squash_params.glwe_dimension()),
            polynomial_size: Some(noise_squash_params.polynomial_size()),
            pbs_level: Some(noise_squash_params.decomp_level_count()),
            pbs_base_log: Some(noise_squash_params.decomp_base_log()),
            lwe_noise_distribution: Some(pbs_params.encryption_noise_distribution()),
            message_modulus: Some(noise_squash_params.message_modulus().0),
            carry_modulus: Some(noise_squash_params.carry_modulus().0),
            error_probability: Some(2f64.powf(pbs_params.log2_p_fail())),
            ..Default::default()
        }
    }
}

impl From<(NoiseSquashingCompressionParameters, AtomicPatternParameters)>
    for CryptoParametersRecord<u64>
{
    fn from(
        (comp_params, pbs_params): (NoiseSquashingCompressionParameters, AtomicPatternParameters),
    ) -> Self {
        CryptoParametersRecord {
            lwe_dimension: Some(pbs_params.lwe_dimension()),
            br_level: None,
            br_base_log: None,
            packing_ks_level: Some(comp_params.packing_ks_level),
            packing_ks_base_log: Some(comp_params.packing_ks_base_log),
            packing_ks_polynomial_size: Some(comp_params.packing_ks_polynomial_size),
            packing_ks_glwe_dimension: Some(comp_params.packing_ks_glwe_dimension),
            lwe_per_glwe: Some(comp_params.lwe_per_glwe),
            storage_log_modulus: Some(comp_params.ciphertext_modulus.into_modulus_log()),
            lwe_noise_distribution: Some(pbs_params.encryption_noise_distribution()),
            packing_ks_key_noise_distribution: None,
            ciphertext_modulus: Some(pbs_params.ciphertext_modulus()),
            error_probability: Some(2f64.powf(pbs_params.log2_p_fail())),
            ..Default::default()
        }
    }
}
