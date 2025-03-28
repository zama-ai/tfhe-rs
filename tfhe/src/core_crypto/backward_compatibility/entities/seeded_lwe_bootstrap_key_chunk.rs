use tfhe_versionable::VersionsDispatch;

use crate::core_crypto::prelude::{Container, SeededLweBootstrapKeyChunk, UnsignedInteger};

#[derive(VersionsDispatch)]
pub enum SeededLweBootstrapKeyChunkVersions<C: Container>
where
    C::Element: UnsignedInteger,
{
    V0(SeededLweBootstrapKeyChunk<C>),
}
