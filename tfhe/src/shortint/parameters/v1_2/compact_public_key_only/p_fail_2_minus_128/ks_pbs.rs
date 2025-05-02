use crate::shortint::parameters::{
    CarryModulus, CiphertextModulus, CompactCiphertextListExpansionKind,
    CompactPublicKeyEncryptionParameters, DynamicDistribution, LweDimension, MessageModulus,
    SupportedCompactPkeZkScheme,
};

/// This parameter set should be used when doing zk proof of public key encryption
pub const V1_2_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128:
    CompactPublicKeyEncryptionParameters =
    V1_2_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV2;

pub const V1_2_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV2:
    CompactPublicKeyEncryptionParameters =
    V1_2_PARAM_PKE_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV2;

pub const V1_2_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV1:
    CompactPublicKeyEncryptionParameters =
    V1_2_PARAM_PKE_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV1;

pub const V1_2_PARAM_PKE_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV2:
    CompactPublicKeyEncryptionParameters = CompactPublicKeyEncryptionParameters {
    encryption_lwe_dimension: LweDimension(2048),
    encryption_noise_distribution: DynamicDistribution::new_t_uniform(17),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    expansion_kind: CompactCiphertextListExpansionKind::RequiresCasting,
    zk_scheme: SupportedCompactPkeZkScheme::V2,
}
.validate();

pub const V1_2_PARAM_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV2:
    CompactPublicKeyEncryptionParameters = CompactPublicKeyEncryptionParameters {
    encryption_lwe_dimension: LweDimension(2048),
    encryption_noise_distribution: DynamicDistribution::new_t_uniform(17),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    expansion_kind: CompactCiphertextListExpansionKind::RequiresCasting,
    zk_scheme: SupportedCompactPkeZkScheme::V2,
}
.validate();

pub const V1_2_PARAM_PKE_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV1:
    CompactPublicKeyEncryptionParameters = CompactPublicKeyEncryptionParameters {
    encryption_lwe_dimension: LweDimension(1024),
    encryption_noise_distribution: DynamicDistribution::new_t_uniform(43),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    expansion_kind: CompactCiphertextListExpansionKind::RequiresCasting,
    zk_scheme: SupportedCompactPkeZkScheme::V1,
}
.validate();

pub const V1_2_PARAM_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV1:
    CompactPublicKeyEncryptionParameters = CompactPublicKeyEncryptionParameters {
    encryption_lwe_dimension: LweDimension(2048),
    encryption_noise_distribution: DynamicDistribution::new_t_uniform(17),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    expansion_kind: CompactCiphertextListExpansionKind::RequiresCasting,
    zk_scheme: SupportedCompactPkeZkScheme::V1,
}
.validate();
