use crate::{
    core_crypto::prelude::LweCompactCiphertextListOwned,
    shortint::{
        ciphertext::*, parameters::CompactCiphertextListExpansionKind, CarryModulus, MessageModulus,
    },
};
use tfhe_versionable::{Upgrade, Version, VersionsDispatch};

#[derive(VersionsDispatch)]
pub enum MaxNoiseLevelVersions {
    V0(MaxNoiseLevel),
}

#[derive(VersionsDispatch)]
pub enum NoiseLevelVersions {
    V0(NoiseLevel),
}

#[derive(VersionsDispatch)]
pub enum MaxDegreeVersions {
    V0(MaxDegree),
}

#[derive(VersionsDispatch)]
pub enum DegreeVersions {
    V0(Degree),
}

#[derive(VersionsDispatch)]
pub enum CiphertextVersions {
    V0(Ciphertext),
}

#[derive(Version)]
pub struct CompactCiphertextListV0 {
    pub ct_list: LweCompactCiphertextListOwned<u64>,
    pub degree: Degree,
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
    pub pbs_order: PBSOrder,
    pub noise_level: NoiseLevel,
}

impl Upgrade<CompactCiphertextList> for CompactCiphertextListV0 {
    fn upgrade(self) -> Result<CompactCiphertextList, String> {
        Ok(CompactCiphertextList {
            ct_list: self.ct_list,
            degree: self.degree,
            message_modulus: self.message_modulus,
            carry_modulus: self.carry_modulus,
            expansion_kind: CompactCiphertextListExpansionKind::NoCasting(self.pbs_order),
            noise_level: self.noise_level,
        })
    }
}

#[derive(VersionsDispatch)]
pub enum CompactCiphertextListVersions {
    V0(CompactCiphertextList),
}

#[derive(VersionsDispatch)]
pub enum CompressedCiphertextVersions {
    V0(CompressedCiphertext),
}

#[derive(VersionsDispatch)]
pub enum CompressedModulusSwitchedCiphertextVersions {
    V0(CompressedModulusSwitchedCiphertext),
}

#[derive(VersionsDispatch)]
#[allow(dead_code)]
pub(crate) enum InternalCompressedModulusSwitchedCiphertextVersions {
    V0(InternalCompressedModulusSwitchedCiphertext),
}
