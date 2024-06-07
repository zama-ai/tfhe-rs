use tfhe_versionable::VersionsDispatch;

use crate::shortint::parameters::ShortintParameterSetInner;
use crate::shortint::*;

#[derive(VersionsDispatch)]
pub enum MessageModulusVersions {
    V0(MessageModulus),
}

#[derive(VersionsDispatch)]
pub enum CarryModulusVersions {
    V0(CarryModulus),
}

#[derive(VersionsDispatch)]
pub enum ClassicPBSParametersVersions {
    V0(ClassicPBSParameters),
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
