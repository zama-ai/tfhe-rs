use std::convert::Infallible;

use crate::core_crypto::prelude::{
    CompressedModulusSwitchedLweCiphertext, LweCompactCiphertextListOwned,
};
use crate::shortint::ciphertext::*;
use crate::shortint::parameters::CompactCiphertextListExpansionKind;
use crate::shortint::{CarryModulus, MessageModulus};
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

impl Upgrade<CompactCiphertextListV1> for CompactCiphertextListV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<CompactCiphertextListV1, Self::Error> {
        Ok(CompactCiphertextListV1 {
            ct_list: self.ct_list,
            degree: self.degree,
            message_modulus: self.message_modulus,
            carry_modulus: self.carry_modulus,
            expansion_kind: CompactCiphertextListExpansionKind::NoCasting(self.pbs_order),
            noise_level: self.noise_level,
        })
    }
}

#[derive(Version)]
pub struct CompactCiphertextListV1 {
    pub ct_list: LweCompactCiphertextListOwned<u64>,
    pub degree: Degree,
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
    pub expansion_kind: CompactCiphertextListExpansionKind,
    pub noise_level: NoiseLevel,
}

impl Upgrade<CompactCiphertextList> for CompactCiphertextListV1 {
    type Error = Infallible;

    fn upgrade(self) -> Result<CompactCiphertextList, Self::Error> {
        Ok(CompactCiphertextList {
            ct_list: self.ct_list,
            degree: self.degree,
            message_modulus: self.message_modulus,
            carry_modulus: self.carry_modulus,
            expansion_kind: self.expansion_kind,
        })
    }
}

#[derive(VersionsDispatch)]
pub enum CompactCiphertextListVersions {
    V0(CompactCiphertextListV0),
    V1(CompactCiphertextListV1),
    V2(CompactCiphertextList),
}

#[cfg(feature = "zk-pok")]
#[derive(VersionsDispatch)]
pub enum ProvenCompactCiphertextListVersions {
    V0(ProvenCompactCiphertextList),
}

#[derive(VersionsDispatch)]
pub enum CompressedCiphertextVersions {
    V0(CompressedCiphertext),
}

#[derive(Version)]
pub struct CompressedModulusSwitchedCiphertextV0 {
    pub(crate) compressed_modulus_switched_lwe_ciphertext:
        CompressedModulusSwitchedLweCiphertext<u64>,
    pub(crate) degree: Degree,
    pub(crate) message_modulus: MessageModulus,
    pub(crate) carry_modulus: CarryModulus,
    pub(crate) pbs_order: PBSOrder,
}

impl Upgrade<CompressedModulusSwitchedCiphertext> for CompressedModulusSwitchedCiphertextV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<CompressedModulusSwitchedCiphertext, Self::Error> {
        Ok(CompressedModulusSwitchedCiphertext {
            compressed_modulus_switched_lwe_ciphertext:
                InternalCompressedModulusSwitchedCiphertext::Classic(
                    self.compressed_modulus_switched_lwe_ciphertext,
                ),
            degree: self.degree,
            message_modulus: self.message_modulus,
            carry_modulus: self.carry_modulus,
            pbs_order: self.pbs_order,
        })
    }
}

#[derive(VersionsDispatch)]
pub enum CompressedModulusSwitchedCiphertextVersions {
    V0(CompressedModulusSwitchedCiphertextV0),
    V1(CompressedModulusSwitchedCiphertext),
}

#[derive(VersionsDispatch)]
pub(crate) enum InternalCompressedModulusSwitchedCiphertextVersions {
    #[allow(dead_code)]
    V0(InternalCompressedModulusSwitchedCiphertext),
}

#[derive(VersionsDispatch)]
pub enum CompressedCiphertextListVersions {
    V0(CompressedCiphertextList),
}
