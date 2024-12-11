use tfhe_versionable::VersionsDispatch;

use crate::prelude::{Container, LweCompactPublicKey, UnsignedInteger};

#[derive(VersionsDispatch)]
pub enum LweCompactPublicKeyVersions<C: Container>
where
    C::Element: UnsignedInteger,
{
    V0(LweCompactPublicKey<C>),
}
