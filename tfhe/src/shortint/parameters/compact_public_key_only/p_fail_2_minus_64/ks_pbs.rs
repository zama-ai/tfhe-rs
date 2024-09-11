use crate::core_crypto::commons::parameters::{
    CiphertextModulus, DynamicDistribution, LweDimension,
};
use crate::shortint::parameters::{
    CarryModulus, CompactCiphertextListExpansionKind, CompactPublicKeyEncryptionParameters,
    MessageModulus,
};

pub const PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64: CompactPublicKeyEncryptionParameters =
    CompactPublicKeyEncryptionParameters {
        encryption_lwe_dimension: LweDimension(1024),
        encryption_noise_distribution: DynamicDistribution::new_t_uniform(42),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(4),
        ciphertext_modulus: CiphertextModulus::new_native(),
        expansion_kind: CompactCiphertextListExpansionKind::RequiresCasting,
    }
    .validate();
