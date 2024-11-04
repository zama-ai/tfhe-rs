use tfhe_versionable::deprecation::{Deprecable, Deprecated};
use tfhe_versionable::VersionsDispatch;

use crate::core_crypto::prelude::{Container, SeededLwePackingKeyswitchKey, UnsignedInteger};

impl<C: Container> Deprecable for SeededLwePackingKeyswitchKey<C>
where
    C::Element: UnsignedInteger,
{
    const TYPE_NAME: &'static str = "SeededLwePackingKeyswitchKey";
    const MIN_SUPPORTED_APP_VERSION: &'static str = "TFHE-rs v0.10";
}

#[derive(VersionsDispatch)]
pub enum SeededLwePackingKeyswitchKeyVersions<C: Container>
where
    C::Element: UnsignedInteger,
{
    V0(Deprecated<SeededLwePackingKeyswitchKey<C>>),
    V1(Deprecated<SeededLwePackingKeyswitchKey<C>>),
    V2(SeededLwePackingKeyswitchKey<C>),
}
