use tfhe_versionable::VersionsDispatch;

use crate::core_crypto::prelude::{Container, GlweCiphertextList, UnsignedInteger};

#[derive(VersionsDispatch)]
pub enum GlweCiphertextListVersions<C: Container>
where
    C::Element: UnsignedInteger,
{
    V0(GlweCiphertextList<C>),
}
