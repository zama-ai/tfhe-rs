use tfhe_versionable::VersionsDispatch;

use crate::core_crypto::prelude::{Container, SeededLweMultiBitBootstrapKey, UnsignedInteger};

#[derive(VersionsDispatch)]
pub enum SeededLweMultiBitBootstrapKeyVersions<C: Container>
where
    C::Element: UnsignedInteger,
{
    V0(SeededLweMultiBitBootstrapKey<C>),
}
