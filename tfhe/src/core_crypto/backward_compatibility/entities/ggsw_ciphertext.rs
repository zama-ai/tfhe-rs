use tfhe_versionable::VersionsDispatch;

use crate::core_crypto::prelude::{Container, GgswCiphertext, UnsignedInteger};

#[derive(VersionsDispatch)]
pub enum GgswCiphertextVersions<C: Container>
where
    C::Element: UnsignedInteger,
{
    V0(GgswCiphertext<C>),
}
