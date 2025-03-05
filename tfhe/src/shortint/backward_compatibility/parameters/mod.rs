pub mod compact_public_key_only;
pub mod key_switching;
pub mod list_compression;
pub mod modulus_switch_noise_reduction;
pub mod noise_squashing;

use crate::core_crypto::commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, DynamicDistribution, GlweDimension,
    LweDimension, PolynomialSize,
};
use crate::shortint::parameters::{ShortintParameterSetInner, SupportedCompactPkeZkScheme};
use crate::shortint::*;
use std::convert::Infallible;
use tfhe_versionable::{Upgrade, Version, VersionsDispatch};

#[derive(VersionsDispatch)]
pub enum MessageModulusVersions {
    V0(MessageModulus),
}

#[derive(VersionsDispatch)]
pub enum CarryModulusVersions {
    V0(CarryModulus),
}

#[derive(Version)]
pub struct ClassicPBSParametersV0 {
    pub lwe_dimension: LweDimension,
    pub glwe_dimension: GlweDimension,
    pub polynomial_size: PolynomialSize,
    pub lwe_noise_distribution: DynamicDistribution<u64>,
    pub glwe_noise_distribution: DynamicDistribution<u64>,
    pub pbs_base_log: DecompositionBaseLog,
    pub pbs_level: DecompositionLevelCount,
    pub ks_base_log: DecompositionBaseLog,
    pub ks_level: DecompositionLevelCount,
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
    pub max_noise_level: MaxNoiseLevel,
    pub log2_p_fail: f64,
    pub ciphertext_modulus: CiphertextModulus,
    pub encryption_key_choice: EncryptionKeyChoice,
}

impl Upgrade<ClassicPBSParameters> for ClassicPBSParametersV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<ClassicPBSParameters, Self::Error> {
        Ok(ClassicPBSParameters {
            lwe_dimension: self.lwe_dimension,
            glwe_dimension: self.glwe_dimension,
            polynomial_size: self.polynomial_size,
            lwe_noise_distribution: self.lwe_noise_distribution,
            glwe_noise_distribution: self.glwe_noise_distribution,
            pbs_base_log: self.pbs_base_log,
            pbs_level: self.pbs_level,
            ks_base_log: self.ks_base_log,
            ks_level: self.ks_level,
            message_modulus: self.message_modulus,
            carry_modulus: self.carry_modulus,
            max_noise_level: self.max_noise_level,
            log2_p_fail: self.log2_p_fail,
            ciphertext_modulus: self.ciphertext_modulus,
            encryption_key_choice: self.encryption_key_choice,
            modulus_switch_noise_reduction_params: None,
        })
    }
}

#[derive(VersionsDispatch)]
pub enum ClassicPBSParametersVersions {
    V0(ClassicPBSParametersV0),
    V1(ClassicPBSParameters),
}

#[derive(VersionsDispatch)]
pub enum PBSParametersVersions {
    V0(PBSParameters),
}

#[derive(VersionsDispatch)]
#[allow(unused)]
pub(crate) enum ShortintParameterSetInnerVersions {
    V0(ShortintParameterSetInner),
}

#[derive(VersionsDispatch)]
pub enum ShortintParameterSetVersions {
    V0(ShortintParameterSet),
}

#[derive(VersionsDispatch)]
pub enum MultiBitPBSParametersVersions {
    V0(MultiBitPBSParameters),
}

#[derive(VersionsDispatch)]
pub enum WopbsParametersVersions {
    V0(WopbsParameters),
}

#[derive(VersionsDispatch)]
pub enum SupportedCompactPkeZkSchemeVersions {
    V0(SupportedCompactPkeZkScheme),
}
