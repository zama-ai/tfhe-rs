use tfhe_versionable::VersionsDispatch;

use crate::core_crypto::prelude::{Container, LweCiphertextList, UnsignedInteger};

#[derive(VersionsDispatch)]
pub enum LweCiphertextListVersions<C: Container>
where
    C::Element: UnsignedInteger,
{
    V0(LweCiphertextList<C>),
}
