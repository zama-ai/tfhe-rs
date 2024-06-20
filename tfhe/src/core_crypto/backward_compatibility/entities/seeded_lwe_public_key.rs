use tfhe_versionable::VersionsDispatch;

use crate::core_crypto::prelude::{Container, SeededLwePublicKey, UnsignedInteger};

#[derive(VersionsDispatch)]
pub enum SeededLwePublicKeyVersions<C: Container>
where
    C::Element: UnsignedInteger,
{
    V0(SeededLwePublicKey<C>),
}
