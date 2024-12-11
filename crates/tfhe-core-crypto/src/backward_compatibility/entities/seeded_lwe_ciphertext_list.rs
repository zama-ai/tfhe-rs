use tfhe_versionable::VersionsDispatch;

use crate::prelude::{Container, SeededLweCiphertextList, UnsignedInteger};

#[derive(VersionsDispatch)]
pub enum SeededLweCiphertextListVersions<C: Container>
where
    C::Element: UnsignedInteger,
{
    V0(SeededLweCiphertextList<C>),
}
