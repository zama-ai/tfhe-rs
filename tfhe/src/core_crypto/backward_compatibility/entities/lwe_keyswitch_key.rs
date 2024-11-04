use tfhe_versionable::deprecation::{Deprecable, Deprecated};
use tfhe_versionable::VersionsDispatch;

use crate::core_crypto::prelude::{Container, LweKeyswitchKey, UnsignedInteger};

impl<C: Container> Deprecable for LweKeyswitchKey<C>
where
    C::Element: UnsignedInteger,
{
    const TYPE_NAME: &'static str = "LweKeyswitchKey";
    const MIN_SUPPORTED_APP_VERSION: &'static str = "TFHE-rs v0.10";
}

#[derive(VersionsDispatch)]
pub enum LweKeyswitchKeyVersions<C: Container>
where
    C::Element: UnsignedInteger,
{
    V0(Deprecated<LweKeyswitchKey<C>>),
    V1(Deprecated<LweKeyswitchKey<C>>),
    V2(LweKeyswitchKey<C>),
}
