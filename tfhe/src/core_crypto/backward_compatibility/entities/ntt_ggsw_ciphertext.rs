use tfhe_versionable::VersionsDispatch;

use crate::core_crypto::prelude::{Container, NttGgswCiphertext, UnsignedInteger};

#[derive(VersionsDispatch)]
pub enum NttGgswCiphertextVersions<C: Container>
where
    C::Element: UnsignedInteger,
{
    V0(NttGgswCiphertext<C>),
}
