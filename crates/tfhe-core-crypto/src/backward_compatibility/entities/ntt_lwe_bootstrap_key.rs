use tfhe_versionable::deprecation::{Deprecable, Deprecated};
use tfhe_versionable::VersionsDispatch;

use crate::prelude::{Container, NttLweBootstrapKey, UnsignedInteger};

impl<C: Container> Deprecable for NttLweBootstrapKey<C>
where
    C::Element: UnsignedInteger,
{
    const TYPE_NAME: &'static str = "NttLweBootstrapKey";
    const MIN_SUPPORTED_APP_VERSION: &'static str = "TFHE-rs v0.10";
}

#[derive(VersionsDispatch)]
pub enum NttLweBootstrapKeyVersions<C: Container>
where
    C::Element: UnsignedInteger,
{
    V0(Deprecated<NttLweBootstrapKey<C>>),
    V1(NttLweBootstrapKey<C>),
}
