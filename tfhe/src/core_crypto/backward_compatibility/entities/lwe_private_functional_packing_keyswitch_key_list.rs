use tfhe_versionable::VersionsDispatch;

use crate::core_crypto::prelude::{
    Container, LwePrivateFunctionalPackingKeyswitchKeyList, UnsignedInteger,
};

#[derive(VersionsDispatch)]
pub enum LwePrivateFunctionalPackingKeyswitchKeyListVersions<C: Container>
where
    C::Element: UnsignedInteger,
{
    V0(LwePrivateFunctionalPackingKeyswitchKeyList<C>),
}
