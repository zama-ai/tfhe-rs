use tfhe_versionable::VersionsDispatch;

use crate::core_crypto::prelude::{Container, LweKeyswitchKey, UnsignedInteger};

#[derive(VersionsDispatch)]
pub enum LweKeyswitchKeyVersions<C: Container>
where
    C::Element: UnsignedInteger,
{
    V0(LweKeyswitchKey<C>),
}
