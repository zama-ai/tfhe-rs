use tfhe_versionable::VersionsDispatch;

use crate::core_crypto::prelude::{Container, LwePackingKeyswitchKey, UnsignedInteger};

#[derive(VersionsDispatch)]
pub enum LwePackingKeyswitchKeyVersions<C: Container>
where
    C::Element: UnsignedInteger,
{
    V0(LwePackingKeyswitchKey<C>),
}
