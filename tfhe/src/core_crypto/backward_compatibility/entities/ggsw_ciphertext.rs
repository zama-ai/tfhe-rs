use tfhe_versionable::deprecation::{Deprecable, Deprecated};
use tfhe_versionable::VersionsDispatch;

use crate::core_crypto::prelude::{Container, GgswCiphertext, UnsignedInteger};

impl<C: Container> Deprecable for GgswCiphertext<C>
where
    C::Element: UnsignedInteger,
{
    const TYPE_NAME: &'static str = "GgswCiphertext";
    const MIN_SUPPORTED_APP_VERSION: &'static str = "TFHE-rs v0.10";
}

#[derive(VersionsDispatch)]
pub enum GgswCiphertextVersions<C: Container>
where
    C::Element: UnsignedInteger,
{
    V0(Deprecated<GgswCiphertext<C>>),
    V1(GgswCiphertext<C>),
}
