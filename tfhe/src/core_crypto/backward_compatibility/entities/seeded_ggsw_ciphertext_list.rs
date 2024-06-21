use tfhe_versionable::VersionsDispatch;

use crate::core_crypto::prelude::{Container, SeededGgswCiphertextList, UnsignedInteger};

#[derive(VersionsDispatch)]
pub enum SeededGgswCiphertextListVersions<C: Container>
where
    C::Element: UnsignedInteger,
{
    V0(SeededGgswCiphertextList<C>),
}
