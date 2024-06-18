use tfhe_versionable::VersionsDispatch;

use crate::core_crypto::prelude::{Container, LweBootstrapKey, UnsignedInteger};

#[derive(VersionsDispatch)]
pub enum LweBootstrapKeyVersions<C: Container>
where
    C::Element: UnsignedInteger,
{
    V0(LweBootstrapKey<C>),
}
