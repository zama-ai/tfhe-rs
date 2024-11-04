use tfhe_versionable::deprecation::{Deprecable, Deprecated};
use tfhe_versionable::VersionsDispatch;

use crate::core_crypto::prelude::{Container, SeededLweMultiBitBootstrapKey, UnsignedInteger};

impl<C: Container> Deprecable for SeededLweMultiBitBootstrapKey<C>
where
    C::Element: UnsignedInteger,
{
    const TYPE_NAME: &'static str = "SeededLweMultiBitBootstrapKey";
    const MIN_SUPPORTED_APP_VERSION: &'static str = "TFHE-rs v0.10";
}

#[derive(VersionsDispatch)]
pub enum SeededLweMultiBitBootstrapKeyVersions<C: Container>
where
    C::Element: UnsignedInteger,
{
    V0(Deprecated<SeededLweMultiBitBootstrapKey<C>>),
    V1(SeededLweMultiBitBootstrapKey<C>),
}
