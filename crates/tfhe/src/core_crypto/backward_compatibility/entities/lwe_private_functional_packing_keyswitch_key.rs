use tfhe_versionable::deprecation::{Deprecable, Deprecated};
use tfhe_versionable::VersionsDispatch;

use crate::core_crypto::prelude::{
    Container, LwePrivateFunctionalPackingKeyswitchKey, UnsignedInteger,
};

impl<C: Container> Deprecable for LwePrivateFunctionalPackingKeyswitchKey<C>
where
    C::Element: UnsignedInteger,
{
    const TYPE_NAME: &'static str = "LwePrivateFunctionalPackingKeyswitchKey";
    const MIN_SUPPORTED_APP_VERSION: &'static str = "TFHE-rs v0.10";
}

#[derive(VersionsDispatch)]
pub enum LwePrivateFunctionalPackingKeyswitchKeyVersions<C: Container>
where
    C::Element: UnsignedInteger,
{
    V0(Deprecated<LwePrivateFunctionalPackingKeyswitchKey<C>>),
    V1(LwePrivateFunctionalPackingKeyswitchKey<C>),
}
