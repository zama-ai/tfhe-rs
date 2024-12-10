use tfhe_versionable::deprecation::{Deprecable, Deprecated};
use tfhe_versionable::VersionsDispatch;

use crate::core_crypto::prelude::{Container, LweBootstrapKey, UnsignedInteger};

impl<C: Container> Deprecable for LweBootstrapKey<C>
where
    C::Element: UnsignedInteger,
{
    const TYPE_NAME: &'static str = "LweBootstrapKey";
    const MIN_SUPPORTED_APP_VERSION: &'static str = "TFHE-rs v0.10";
}

#[derive(VersionsDispatch)]
pub enum LweBootstrapKeyVersions<C: Container>
where
    C::Element: UnsignedInteger,
{
    V0(Deprecated<LweBootstrapKey<C>>),
    V1(LweBootstrapKey<C>),
}
