use tfhe_versionable::VersionsDispatch;

use crate::core_crypto::prelude::{Container, SeededLweKeyswitchKeyChunk, UnsignedInteger};

#[derive(VersionsDispatch)]
pub enum SeededLweKeyswitchKeyChunkVersions<C: Container>
where
    C::Element: UnsignedInteger,
{
    V0(SeededLweKeyswitchKeyChunk<C>),
}
