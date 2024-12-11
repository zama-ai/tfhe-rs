use tfhe_versionable::deprecation::{Deprecable, Deprecated};
use tfhe_versionable::VersionsDispatch;

use crate::core_crypto::prelude::{Container, GgswCiphertextList, UnsignedInteger};

impl<C: Container> Deprecable for GgswCiphertextList<C>
where
    C::Element: UnsignedInteger,
{
    const TYPE_NAME: &'static str = "GgswCiphertextList";
    const MIN_SUPPORTED_APP_VERSION: &'static str = "TFHE-rs v0.10";
}

#[derive(VersionsDispatch)]
pub enum GgswCiphertextListVersions<C: Container>
where
    C::Element: UnsignedInteger,
{
    V0(Deprecated<GgswCiphertextList<C>>),
    V1(GgswCiphertextList<C>),
}
