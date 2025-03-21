use tfhe_versionable::deprecation::Deprecable;
use tfhe_versionable::VersionsDispatch;

use crate::core_crypto::prelude::{Container, LweBootstrapKeyChunk, UnsignedInteger};

impl<C: Container> Deprecable for LweBootstrapKeyChunk<C>
where
    C::Element: UnsignedInteger,
{
    const TYPE_NAME: &'static str = "LweBootstrapKeyChunk";
    // TODO
    const MIN_SUPPORTED_APP_VERSION: &'static str = "TFHE-rs v0.10";
}

#[derive(VersionsDispatch)]
pub enum LweBootstrapKeyChunkVersions<C: Container>
where
    C::Element: UnsignedInteger,
{
    V0(LweBootstrapKeyChunk<C>),
}
