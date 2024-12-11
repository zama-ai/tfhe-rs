use tfhe_versionable::deprecation::{Deprecable, Deprecated};
use tfhe_versionable::VersionsDispatch;

use crate::core_crypto::prelude::{Container, SeededGgswCiphertext, UnsignedInteger};

impl<C: Container> Deprecable for SeededGgswCiphertext<C>
where
    C::Element: UnsignedInteger,
{
    const TYPE_NAME: &'static str = "SeededGgswCiphertext";
    const MIN_SUPPORTED_APP_VERSION: &'static str = "TFHE-rs v0.10";
}

#[derive(VersionsDispatch)]
pub enum SeededGgswCiphertextVersions<C: Container>
where
    C::Element: UnsignedInteger,
{
    V0(Deprecated<SeededGgswCiphertext<C>>),
    V1(SeededGgswCiphertext<C>),
}
