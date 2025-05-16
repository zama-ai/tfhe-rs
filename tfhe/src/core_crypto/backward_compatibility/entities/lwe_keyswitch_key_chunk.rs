use tfhe_versionable::VersionsDispatch;

use crate::core_crypto::prelude::{Container, LweKeyswitchKeyChunk, UnsignedInteger};

#[derive(VersionsDispatch)]
pub enum LweKeyswitchKeyChunkVersions<C: Container>
where
    C::Element: UnsignedInteger,
{
    V0(LweKeyswitchKeyChunk<C>),
}
