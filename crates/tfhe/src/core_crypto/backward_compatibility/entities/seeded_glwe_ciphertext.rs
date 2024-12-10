use tfhe_versionable::VersionsDispatch;

use crate::core_crypto::prelude::{Container, SeededGlweCiphertext, UnsignedInteger};

#[derive(VersionsDispatch)]
pub enum SeededGlweCiphertextVersions<C: Container>
where
    C::Element: UnsignedInteger,
{
    V0(SeededGlweCiphertext<C>),
}
