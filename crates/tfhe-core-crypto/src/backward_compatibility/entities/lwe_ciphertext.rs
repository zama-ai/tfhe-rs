use tfhe_versionable::VersionsDispatch;

use crate::prelude::{Container, LweCiphertext, UnsignedInteger};

#[derive(VersionsDispatch)]
pub enum LweCiphertextVersions<C: Container>
where
    C::Element: UnsignedInteger,
{
    V0(LweCiphertext<C>),
}
