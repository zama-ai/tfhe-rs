use tfhe_versionable::VersionsDispatch;

use crate::core_crypto::prelude::{Container, SeededLweCompactPublicKey, UnsignedInteger};

#[derive(VersionsDispatch)]
pub enum SeededLweCompactPublicKeyVersions<C: Container>
where
    C::Element: UnsignedInteger,
{
    V0(SeededLweCompactPublicKey<C>),
}
