use tfhe_versionable::VersionsDispatch;

use super::parameters::compact_public_key_only::CompactPublicKeyEncryptionParameters;
use super::parameters::CompactCiphertextListExpansionKind;

#[derive(VersionsDispatch)]
pub enum CompactCiphertextListExpansionKindVersions {
    V0(CompactCiphertextListExpansionKind),
}

#[derive(VersionsDispatch)]
pub enum CompactPublicKeyEncryptionParametersVersions {
    V0(CompactPublicKeyEncryptionParameters),
}
