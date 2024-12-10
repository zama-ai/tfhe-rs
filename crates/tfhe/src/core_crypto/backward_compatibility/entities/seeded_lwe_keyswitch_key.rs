use tfhe_versionable::deprecation::{Deprecable, Deprecated};
use tfhe_versionable::VersionsDispatch;

use crate::core_crypto::prelude::{Container, SeededLweKeyswitchKey, UnsignedInteger};

impl<C: Container> Deprecable for SeededLweKeyswitchKey<C>
where
    C::Element: UnsignedInteger,
{
    const TYPE_NAME: &'static str = "SeededLweKeyswitchKey";
    const MIN_SUPPORTED_APP_VERSION: &'static str = "TFHE-rs v0.10";
}

#[derive(VersionsDispatch)]
pub enum SeededLweKeyswitchKeyVersions<C: Container>
where
    C::Element: UnsignedInteger,
{
    V0(Deprecated<SeededLweKeyswitchKey<C>>),
    V1(Deprecated<SeededLweKeyswitchKey<C>>),
    V2(SeededLweKeyswitchKey<C>),
}
