use tfhe_versionable::VersionsDispatch;

use crate::core_crypto::prelude::{Container, SeededLweBootstrapKey, UnsignedInteger};

#[derive(VersionsDispatch)]
pub enum SeededLweBootstrapKeyVersions<C: Container>
where
    C::Element: UnsignedInteger,
{
    V0(SeededLweBootstrapKey<C>),
}
