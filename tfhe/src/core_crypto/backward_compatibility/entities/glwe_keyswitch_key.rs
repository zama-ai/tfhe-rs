use crate::core_crypto::prelude::{Container, GlweKeyswitchKey, UnsignedInteger};
use tfhe_versionable::VersionsDispatch;

#[derive(VersionsDispatch)]
pub enum GlweKeyswitchKeyVersions<C: Container>
where
    C::Element: UnsignedInteger,
{
    V0(GlweKeyswitchKey<C>),
}
