use tfhe_versionable::VersionsDispatch;

use crate::prelude::{Container, SeededGlweCiphertextList, UnsignedInteger};

#[derive(VersionsDispatch)]
pub enum SeededGlweCiphertextListVersions<C: Container>
where
    C::Element: UnsignedInteger,
{
    V0(SeededGlweCiphertextList<C>),
}
