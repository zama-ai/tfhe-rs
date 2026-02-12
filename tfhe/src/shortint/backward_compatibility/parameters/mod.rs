pub mod compact_public_key_only;
pub mod key_switching;
pub mod list_compression;
pub mod modulus_switch_noise_reduction;
pub mod noise_squashing;

use crate::core_crypto::commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, DynamicDistribution, GlweDimension,
    LweDimension, PolynomialSize,
};
use crate::shortint::parameters::meta::{DedicatedCompactPublicKeyParameters, MetaParameters};
use crate::shortint::parameters::{
    Backend, CiphertextModulus32, MetaNoiseSquashingParameters, ModulusSwitchNoiseReductionParams,
    ModulusSwitchType, ShortintParameterSetInner, SupportedCompactPkeZkScheme,
};
use crate::shortint::*;
use parameters::KeySwitch32PBSParameters;
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use tfhe_versionable::{Upgrade, Version, Versionize, VersionsDispatch};

#[derive(VersionsDispatch)]
pub enum MessageModulusVersions {
    V0(MessageModulus),
}

#[derive(VersionsDispatch)]
pub enum CarryModulusVersions {
    V0(CarryModulus),
}

#[derive(VersionsDispatch)]
pub enum BackendVersions {
    V0(Backend),
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

impl Upgrade<ClassicPBSParametersV1> for ClassicPBSParametersV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<ClassicPBSParametersV1, Self::Error> {
        Ok(ClassicPBSParametersV1 {
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

#[derive(Version)]
pub struct ClassicPBSParametersV1 {
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
    pub modulus_switch_noise_reduction_params: Option<ModulusSwitchNoiseReductionParams>,
}

impl Upgrade<ClassicPBSParameters> for ClassicPBSParametersV1 {
    type Error = Infallible;

    fn upgrade(self) -> Result<ClassicPBSParameters, Self::Error> {
        let Self {
            lwe_dimension,
            glwe_dimension,
            polynomial_size,
            lwe_noise_distribution,
            glwe_noise_distribution,
            pbs_base_log,
            pbs_level,
            ks_base_log,
            ks_level,
            message_modulus,
            carry_modulus,
            max_noise_level,
            log2_p_fail,
            ciphertext_modulus,
            encryption_key_choice,
            modulus_switch_noise_reduction_params,
        } = self;

        Ok(ClassicPBSParameters {
            lwe_dimension,
            glwe_dimension,
            polynomial_size,
            lwe_noise_distribution,
            glwe_noise_distribution,
            pbs_base_log,
            pbs_level,
            ks_base_log,
            ks_level,
            message_modulus,
            carry_modulus,
            max_noise_level,
            log2_p_fail,
            ciphertext_modulus,
            encryption_key_choice,
            modulus_switch_noise_reduction_params: modulus_switch_noise_reduction_params.map_or(
                ModulusSwitchType::Standard,
                |modulus_switch_noise_reduction_params| {
                    ModulusSwitchType::DriftTechniqueNoiseReduction(
                        modulus_switch_noise_reduction_params,
                    )
                },
            ),
        })
    }
}

#[derive(VersionsDispatch)]
pub enum ClassicPBSParametersVersions {
    V0(ClassicPBSParametersV0),
    V1(ClassicPBSParametersV1),
    V2(ClassicPBSParameters),
}

#[derive(VersionsDispatch)]
pub enum PBSParametersVersions {
    V0(PBSParameters),
}

#[derive(Version)]
pub(crate) enum ShortintParameterSetInnerV0 {
    PBSOnly(PBSParameters),
    WopbsOnly(WopbsParameters),
    PBSAndWopbs(PBSParameters, WopbsParameters),
    KS32PBS(KeySwitch32PBSParameters),
}

impl Upgrade<ShortintParameterSetInner> for ShortintParameterSetInnerV0 {
    type Error = crate::Error;

    fn upgrade(self) -> Result<ShortintParameterSetInner, Self::Error> {
        Ok(match self {
            Self::PBSOnly(pbsparameters) => ShortintParameterSetInner::PBSOnly(pbsparameters),
            Self::WopbsOnly(_) => {
                return Err(crate::error!("Invalid value for ShortintParameterSetInner"))
            }
            Self::PBSAndWopbs(pbsparameters, _) => {
                ShortintParameterSetInner::PBSOnly(pbsparameters)
            }
            Self::KS32PBS(key_switch32_pbsparameters) => {
                ShortintParameterSetInner::KS32PBS(key_switch32_pbsparameters)
            }
        })
    }
}

#[allow(unused)]
#[derive(VersionsDispatch)]
pub(crate) enum ShortintParameterSetInnerVersions {
    V0(ShortintParameterSetInnerV0),
    V1(ShortintParameterSetInner),
}

#[derive(VersionsDispatch)]
pub enum ShortintParameterSetVersions {
    V0(ShortintParameterSet),
}

#[derive(VersionsDispatch)]
pub enum MultiBitPBSParametersVersions {
    V0(MultiBitPBSParameters),
}

#[derive(Serialize, Copy, Clone, Deserialize, Debug, PartialEq, Versionize)]
#[versionize(WopbsParametersVersions)]
pub(crate) struct WopbsParameters {
    pub lwe_dimension: LweDimension,
    pub glwe_dimension: GlweDimension,
    pub polynomial_size: PolynomialSize,
    pub lwe_noise_distribution: DynamicDistribution<u64>,
    pub glwe_noise_distribution: DynamicDistribution<u64>,
    pub pbs_base_log: DecompositionBaseLog,
    pub pbs_level: DecompositionLevelCount,
    pub ks_level: DecompositionLevelCount,
    pub ks_base_log: DecompositionBaseLog,
    pub pfks_level: DecompositionLevelCount,
    pub pfks_base_log: DecompositionBaseLog,
    pub pfks_noise_distribution: DynamicDistribution<u64>,
    pub cbs_level: DecompositionLevelCount,
    pub cbs_base_log: DecompositionBaseLog,
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
    pub ciphertext_modulus: CiphertextModulus,
    pub encryption_key_choice: EncryptionKeyChoice,
}

#[derive(VersionsDispatch)]
#[allow(unused)]
pub(crate) enum WopbsParametersVersions {
    V0(WopbsParameters),
}

#[derive(VersionsDispatch)]
pub enum SupportedCompactPkeZkSchemeVersions {
    V0(SupportedCompactPkeZkScheme),
}

#[derive(Version)]
pub struct KeySwitch32PBSParametersV0 {
    pub lwe_dimension: LweDimension,
    pub glwe_dimension: GlweDimension,
    pub polynomial_size: PolynomialSize,
    pub lwe_noise_distribution: DynamicDistribution<u32>,
    pub glwe_noise_distribution: DynamicDistribution<u64>,
    pub pbs_base_log: DecompositionBaseLog,
    pub pbs_level: DecompositionLevelCount,
    pub ks_base_log: DecompositionBaseLog,
    pub ks_level: DecompositionLevelCount,
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
    pub max_noise_level: MaxNoiseLevel,
    pub log2_p_fail: f64,
    pub post_keyswitch_ciphertext_modulus: CiphertextModulus32,
    pub ciphertext_modulus: CiphertextModulus,
    pub modulus_switch_noise_reduction_params: Option<ModulusSwitchNoiseReductionParams>,
}

impl Upgrade<KeySwitch32PBSParameters> for KeySwitch32PBSParametersV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<KeySwitch32PBSParameters, Self::Error> {
        let Self {
            lwe_dimension,
            glwe_dimension,
            polynomial_size,
            lwe_noise_distribution,
            glwe_noise_distribution,
            pbs_base_log,
            pbs_level,
            ks_base_log,
            ks_level,
            message_modulus,
            carry_modulus,
            max_noise_level,
            log2_p_fail,
            post_keyswitch_ciphertext_modulus,
            ciphertext_modulus,
            modulus_switch_noise_reduction_params,
        } = self;

        Ok(KeySwitch32PBSParameters {
            lwe_dimension,
            glwe_dimension,
            polynomial_size,
            lwe_noise_distribution,
            glwe_noise_distribution,
            pbs_base_log,
            pbs_level,
            ks_base_log,
            ks_level,
            message_modulus,
            carry_modulus,
            max_noise_level,
            log2_p_fail,
            post_keyswitch_ciphertext_modulus,
            ciphertext_modulus,
            modulus_switch_noise_reduction_params: modulus_switch_noise_reduction_params.map_or(
                ModulusSwitchType::Standard,
                |modulus_switch_noise_reduction_params| {
                    ModulusSwitchType::DriftTechniqueNoiseReduction(
                        modulus_switch_noise_reduction_params,
                    )
                },
            ),
        })
    }
}

#[derive(VersionsDispatch)]
pub enum KeySwitch32PBSParametersVersions {
    V0(KeySwitch32PBSParametersV0),
    V1(KeySwitch32PBSParameters),
}

#[derive(VersionsDispatch)]
pub enum ModulusSwitchTypeVersions {
    V0(ModulusSwitchType),
}

#[derive(VersionsDispatch)]
pub enum MetaNoiseSquashingParametersVersions {
    V0(MetaNoiseSquashingParameters),
}

#[derive(VersionsDispatch)]
pub enum DedicatedCompactPublicKeyParametersVersions {
    V0(DedicatedCompactPublicKeyParameters),
}

#[derive(VersionsDispatch)]
pub enum MetaParametersVersions {
    V0(MetaParameters),
}
