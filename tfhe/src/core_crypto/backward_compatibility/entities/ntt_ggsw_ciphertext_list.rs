use tfhe_versionable::deprecation::{Deprecable, Deprecated};
use tfhe_versionable::VersionsDispatch;

use crate::core_crypto::prelude::{Container, NttGgswCiphertextList, UnsignedInteger};

impl<C: Container> Deprecable for NttGgswCiphertextList<C>
where
    C::Element: UnsignedInteger,
{
    const TYPE_NAME: &'static str = "NttGgswCiphertextList";
    const MIN_SUPPORTED_APP_VERSION: &'static str = "TFHE-rs v0.10";
}

#[derive(VersionsDispatch)]
pub enum NttGgswCiphertextListVersions<C: Container>
where
    C::Element: UnsignedInteger,
{
    V0(Deprecated<NttGgswCiphertextList<C>>),
    V1(NttGgswCiphertextList<C>),
}
