use tfhe_versionable::VersionsDispatch;

use crate::core_crypto::prelude::{Container, LweCompactCiphertextList, UnsignedInteger};

#[derive(VersionsDispatch)]
pub enum LweCompactCiphertextListVersions<C: Container>
where
    C::Element: UnsignedInteger,
{
    V0(LweCompactCiphertextList<C>),
}
