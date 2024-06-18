use tfhe_versionable::VersionsDispatch;

use crate::core_crypto::prelude::{Container, SeededGgswCiphertext, UnsignedInteger};

#[derive(VersionsDispatch)]
pub enum SeededGgswCiphertextVersions<C: Container>
where
    C::Element: UnsignedInteger,
{
    V0(SeededGgswCiphertext<C>),
}
