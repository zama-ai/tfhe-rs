use tfhe_versionable::VersionsDispatch;

use crate::core_crypto::prelude::{Container, NttGgswCiphertextList, UnsignedInteger};

#[derive(VersionsDispatch)]
pub enum NttGgswCiphertextListVersions<C: Container>
where
    C::Element: UnsignedInteger,
{
    V0(NttGgswCiphertextList<C>),
}
