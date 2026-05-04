use super::record::CryptoParametersRecord;
use tfhe::boolean::parameters::BooleanParameters;
use tfhe::core_crypto::prelude::CiphertextModulus;

impl From<BooleanParameters> for CryptoParametersRecord<u32> {
    fn from(params: BooleanParameters) -> Self {
        CryptoParametersRecord {
            lwe_dimension: Some(params.lwe_dimension),
            glwe_dimension: Some(params.glwe_dimension),
            polynomial_size: Some(params.polynomial_size),
            lwe_noise_distribution: Some(params.lwe_noise_distribution),
            glwe_noise_distribution: Some(params.glwe_noise_distribution),
            pbs_base_log: Some(params.pbs_base_log),
            pbs_level: Some(params.pbs_level),
            ks_base_log: Some(params.ks_base_log),
            ks_level: Some(params.ks_level),
            ciphertext_modulus: Some(CiphertextModulus::<u32>::new_native()),
            ..Default::default()
        }
    }
}
