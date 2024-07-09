use tfhe_versionable::VersionsDispatch;

use crate::core_crypto::prelude::{Container, NttLweBootstrapKey, UnsignedInteger};

#[derive(VersionsDispatch)]
pub enum NttLweBootstrapKeyVersions<C: Container>
where
    C::Element: UnsignedInteger,
{
    V0(NttLweBootstrapKey<C>),
}
