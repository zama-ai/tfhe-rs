use tfhe_versionable::VersionsDispatch;

use crate::core_crypto::prelude::{Container, GgswCiphertextList, UnsignedInteger};

#[derive(VersionsDispatch)]
pub enum GgswCiphertextListVersions<C: Container>
where
    C::Element: UnsignedInteger,
{
    V0(GgswCiphertextList<C>),
}
