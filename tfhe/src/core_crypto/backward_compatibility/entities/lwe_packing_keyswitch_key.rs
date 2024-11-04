use tfhe_versionable::deprecation::{Deprecable, Deprecated};
use tfhe_versionable::VersionsDispatch;

use crate::core_crypto::prelude::{Container, LwePackingKeyswitchKey, UnsignedInteger};

impl<C: Container> Deprecable for LwePackingKeyswitchKey<C>
where
    C::Element: UnsignedInteger,
{
    const TYPE_NAME: &'static str = "LwePackingKeyswitchKey";
    const MIN_SUPPORTED_APP_VERSION: &'static str = "TFHE-rs v0.10";
}

#[derive(VersionsDispatch)]
pub enum LwePackingKeyswitchKeyVersions<C: Container>
where
    C::Element: UnsignedInteger,
{
    V0(Deprecated<LwePackingKeyswitchKey<C>>),
    V1(Deprecated<LwePackingKeyswitchKey<C>>),
    V2(LwePackingKeyswitchKey<C>),
}
