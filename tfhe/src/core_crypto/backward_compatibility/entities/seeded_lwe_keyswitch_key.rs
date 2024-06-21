use tfhe_versionable::VersionsDispatch;

use crate::core_crypto::prelude::{Container, SeededLweKeyswitchKey, UnsignedInteger};

#[derive(VersionsDispatch)]
pub enum SeededLweKeyswitchKeyVersions<C: Container>
where
    C::Element: UnsignedInteger,
{
    V0(SeededLweKeyswitchKey<C>),
}
