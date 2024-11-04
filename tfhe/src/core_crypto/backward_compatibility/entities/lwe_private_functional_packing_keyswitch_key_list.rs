use tfhe_versionable::deprecation::{Deprecable, Deprecated};
use tfhe_versionable::VersionsDispatch;

use crate::core_crypto::prelude::{
    Container, LwePrivateFunctionalPackingKeyswitchKeyList, UnsignedInteger,
};

impl<C: Container> Deprecable for LwePrivateFunctionalPackingKeyswitchKeyList<C>
where
    C::Element: UnsignedInteger,
{
    const TYPE_NAME: &'static str = "LwePrivateFunctionalPackingKeyswitchKeyList";
    const MIN_SUPPORTED_APP_VERSION: &'static str = "TFHE-rs v0.10";
}

#[derive(VersionsDispatch)]
pub enum LwePrivateFunctionalPackingKeyswitchKeyListVersions<C: Container>
where
    C::Element: UnsignedInteger,
{
    V0(Deprecated<LwePrivateFunctionalPackingKeyswitchKeyList<C>>),
    V1(LwePrivateFunctionalPackingKeyswitchKeyList<C>),
}
