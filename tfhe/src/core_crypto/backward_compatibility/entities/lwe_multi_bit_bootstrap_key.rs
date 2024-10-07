use concrete_fft::c64;
use tfhe_versionable::VersionsDispatch;

use crate::core_crypto::prelude::{
    Container, FourierLweMultiBitBootstrapKey, LweMultiBitBootstrapKey, UnsignedInteger,
};

#[derive(VersionsDispatch)]
pub enum LweMultiBitBootstrapKeyVersions<C: Container>
where
    C::Element: UnsignedInteger,
{
    V0(LweMultiBitBootstrapKey<C>),
}

#[derive(VersionsDispatch)]
pub enum FourierLweMultiBitBootstrapKeyVersions<C: Container<Element = c64>> {
    V0(FourierLweMultiBitBootstrapKey<C>),
}
