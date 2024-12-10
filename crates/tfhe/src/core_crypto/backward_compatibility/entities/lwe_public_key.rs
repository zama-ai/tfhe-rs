use tfhe_versionable::VersionsDispatch;

use crate::core_crypto::prelude::{Container, LwePublicKey, UnsignedInteger};

#[derive(VersionsDispatch)]
pub enum LwePublicKeyVersions<C: Container>
where
    C::Element: UnsignedInteger,
{
    V0(LwePublicKey<C>),
}
