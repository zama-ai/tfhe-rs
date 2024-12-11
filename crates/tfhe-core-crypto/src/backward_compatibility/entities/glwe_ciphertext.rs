use tfhe_versionable::VersionsDispatch;

use crate::prelude::{Container, GlweCiphertext, UnsignedInteger};

#[derive(VersionsDispatch)]
pub enum GlweCiphertextVersions<C: Container>
where
    C::Element: UnsignedInteger,
{
    V0(GlweCiphertext<C>),
}
