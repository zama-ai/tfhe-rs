use tfhe_versionable::VersionsDispatch;

use crate::core_crypto::prelude::{Container, SeededLwePackingKeyswitchKey, UnsignedInteger};

#[derive(VersionsDispatch)]
pub enum SeededLwePackingKeyswitchKeyVersions<C: Container>
where
    C::Element: UnsignedInteger,
{
    V0(SeededLwePackingKeyswitchKey<C>),
}
