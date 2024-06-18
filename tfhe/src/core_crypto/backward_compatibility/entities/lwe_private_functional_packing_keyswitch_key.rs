use tfhe_versionable::VersionsDispatch;

use crate::core_crypto::prelude::{
    Container, LwePrivateFunctionalPackingKeyswitchKey, UnsignedInteger,
};

#[derive(VersionsDispatch)]
pub enum LwePrivateFunctionalPackingKeyswitchKeyVersions<C: Container>
where
    C::Element: UnsignedInteger,
{
    V0(LwePrivateFunctionalPackingKeyswitchKey<C>),
}
