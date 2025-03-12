use tfhe_versionable::VersionsDispatch;

use crate::core_crypto::prelude::{Container, LweBootstrapKeyChunk, UnsignedInteger};

#[derive(VersionsDispatch)]
pub enum LweBootstrapKeyChunkVersions<C: Container>
where
    C::Element: UnsignedInteger,
{
    V0(LweBootstrapKeyChunk<C>),
}
