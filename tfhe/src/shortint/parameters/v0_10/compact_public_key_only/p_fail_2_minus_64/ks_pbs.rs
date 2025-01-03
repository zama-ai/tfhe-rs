use crate::core_crypto::commons::parameters::{
    CiphertextModulus, DynamicDistribution, LweDimension,
};
use crate::shortint::parameters::{
    CarryModulus, CompactCiphertextListExpansionKind, CompactPublicKeyEncryptionParameters,
    MessageModulus, SupportedCompactPkeZkScheme,
};

/// This legacy parameter set were used with the v1 pke zk scheme on TFHE-rs v0.10 and lower
pub const V0_10_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64_ZKV1:
    CompactPublicKeyEncryptionParameters = CompactPublicKeyEncryptionParameters {
    encryption_lwe_dimension: LweDimension(1024),
    encryption_noise_distribution: DynamicDistribution::new_t_uniform(42),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    expansion_kind: CompactCiphertextListExpansionKind::RequiresCasting,
    zk_scheme: SupportedCompactPkeZkScheme::V1,
}
.validate();
