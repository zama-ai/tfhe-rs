use std::convert::Infallible;

use crate::core_crypto::prelude::compressed_modulus_switched_glwe_ciphertext::CompressedModulusSwitchedGlweCiphertext;
use crate::core_crypto::prelude::{
    CiphertextCount, CiphertextModulus, CompressedModulusSwitchedLweCiphertext, LweCiphertextOwned,
    LweCompactCiphertextListOwned, SeededLweCiphertext,
};
use crate::shortint::ciphertext::*;
use crate::shortint::parameters::{
    AtomicPatternKind, CompactCiphertextListExpansionKind, LweCiphertextCount,
};
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

#[derive(Version)]
pub struct CiphertextV0 {
    pub ct: LweCiphertextOwned<u64>,
    pub degree: Degree,
    noise_level: NoiseLevel,
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
    pub pbs_order: PBSOrder,
}

impl Upgrade<Ciphertext> for CiphertextV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<Ciphertext, Self::Error> {
        Ok(Ciphertext::new(
            self.ct,
            self.degree,
            self.noise_level,
            self.message_modulus,
            self.carry_modulus,
            AtomicPatternKind::Classical(self.pbs_order),
        ))
    }
}

#[derive(VersionsDispatch)]
pub enum CiphertextVersions {
    V0(CiphertextV0),
    V1(Ciphertext),
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

#[derive(Version)]
pub struct CompressedCiphertextV0 {
    pub ct: SeededLweCiphertext<u64>,
    pub degree: Degree,
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
    pub pbs_order: PBSOrder,
    pub noise_level: NoiseLevel,
}

impl Upgrade<CompressedCiphertext> for CompressedCiphertextV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<CompressedCiphertext, Self::Error> {
        Ok(CompressedCiphertext::from_raw_parts(
            self.ct,
            self.degree,
            self.message_modulus,
            self.carry_modulus,
            AtomicPatternKind::Classical(self.pbs_order),
            self.noise_level,
        ))
    }
}

#[derive(VersionsDispatch)]
pub enum CompressedCiphertextVersions {
    V0(CompressedCiphertextV0),
    V1(CompressedCiphertext),
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

impl Upgrade<CompressedModulusSwitchedCiphertextV1> for CompressedModulusSwitchedCiphertextV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<CompressedModulusSwitchedCiphertextV1, Self::Error> {
        Ok(CompressedModulusSwitchedCiphertextV1 {
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

#[derive(Version)]
pub struct CompressedModulusSwitchedCiphertextV1 {
    pub(crate) compressed_modulus_switched_lwe_ciphertext:
        InternalCompressedModulusSwitchedCiphertext,
    pub(crate) degree: Degree,
    pub(crate) message_modulus: MessageModulus,
    pub(crate) carry_modulus: CarryModulus,
    pub(crate) pbs_order: PBSOrder,
}

impl Upgrade<CompressedModulusSwitchedCiphertext> for CompressedModulusSwitchedCiphertextV1 {
    type Error = Infallible;

    fn upgrade(self) -> Result<CompressedModulusSwitchedCiphertext, Self::Error> {
        Ok(CompressedModulusSwitchedCiphertext {
            compressed_modulus_switched_lwe_ciphertext: self
                .compressed_modulus_switched_lwe_ciphertext,

            degree: self.degree,
            message_modulus: self.message_modulus,
            carry_modulus: self.carry_modulus,
            atomic_pattern: AtomicPatternKind::Classical(self.pbs_order),
        })
    }
}

#[derive(VersionsDispatch)]
pub enum CompressedModulusSwitchedCiphertextVersions {
    V0(CompressedModulusSwitchedCiphertextV0),
    V1(CompressedModulusSwitchedCiphertextV1),
    V2(CompressedModulusSwitchedCiphertext),
}

#[derive(VersionsDispatch)]
pub(crate) enum InternalCompressedModulusSwitchedCiphertextVersions {
    #[allow(dead_code)]
    V0(InternalCompressedModulusSwitchedCiphertext),
}

#[derive(Version)]
pub struct CompressedCiphertextListV0 {
    pub modulus_switched_glwe_ciphertext_list: Vec<CompressedModulusSwitchedGlweCiphertext<u64>>,
    pub ciphertext_modulus: CiphertextModulus<u64>,
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
    pub pbs_order: PBSOrder,
    pub lwe_per_glwe: LweCiphertextCount,
    pub count: CiphertextCount,
}

impl Upgrade<CompressedCiphertextList> for CompressedCiphertextListV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<CompressedCiphertextList, Self::Error> {
        Ok(CompressedCiphertextList {
            modulus_switched_glwe_ciphertext_list: self.modulus_switched_glwe_ciphertext_list,
            ciphertext_modulus: self.ciphertext_modulus,
            message_modulus: self.message_modulus,
            carry_modulus: self.carry_modulus,
            atomic_pattern: AtomicPatternKind::Classical(self.pbs_order),
            lwe_per_glwe: self.lwe_per_glwe,
            count: self.count,
        })
    }
}

#[derive(VersionsDispatch)]
pub enum CompressedCiphertextListVersions {
    V0(CompressedCiphertextListV0),
    V1(CompressedCiphertextList),
}

#[derive(VersionsDispatch)]
pub enum SquashedNoiseCiphertextVersions {
    V0(SquashedNoiseCiphertext),
}
