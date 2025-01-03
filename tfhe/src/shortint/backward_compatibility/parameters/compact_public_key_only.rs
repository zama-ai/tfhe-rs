use std::convert::Infallible;

use tfhe_versionable::{Upgrade, Version, VersionsDispatch};

use super::parameters::compact_public_key_only::CompactPublicKeyEncryptionParameters;
use super::parameters::{
    CompactCiphertextListExpansionKind, DynamicDistribution, SupportedCompactPkeZkScheme,
};
use super::prelude::*;

#[derive(VersionsDispatch)]
pub enum CompactCiphertextListExpansionKindVersions {
    V0(CompactCiphertextListExpansionKind),
}

#[derive(Version)]
pub struct CompactPublicKeyEncryptionParametersV0 {
    pub encryption_lwe_dimension: LweDimension,
    pub encryption_noise_distribution: DynamicDistribution<u64>,
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
    pub ciphertext_modulus: CiphertextModulus,
    pub expansion_kind: CompactCiphertextListExpansionKind,
}

impl Upgrade<CompactPublicKeyEncryptionParameters> for CompactPublicKeyEncryptionParametersV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<CompactPublicKeyEncryptionParameters, Self::Error> {
        Ok(CompactPublicKeyEncryptionParameters {
            encryption_lwe_dimension: self.encryption_lwe_dimension,
            encryption_noise_distribution: self.encryption_noise_distribution,
            message_modulus: self.message_modulus,
            carry_modulus: self.carry_modulus,
            ciphertext_modulus: self.ciphertext_modulus,
            expansion_kind: self.expansion_kind,
            // TFHE-rs v0.10 and before used only the v1 zk scheme
            zk_scheme: SupportedCompactPkeZkScheme::V1,
        })
    }
}

#[derive(VersionsDispatch)]
pub enum CompactPublicKeyEncryptionParametersVersions {
    V0(CompactPublicKeyEncryptionParametersV0),
    V1(CompactPublicKeyEncryptionParameters),
}
