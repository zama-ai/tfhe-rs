use tfhe_versionable::VersionsDispatch;

use crate::core_crypto::commons::parameters::PBSOrder;

#[derive(VersionsDispatch)]
pub enum PBSOrderVersions {
    V0(PBSOrder),
}
