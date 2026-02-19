use tfhe_fft::c64;
use tfhe_versionable::deprecation::{Deprecable, Deprecated};
use tfhe_versionable::VersionsDispatch;

use crate::core_crypto::entities::lwe_multi_bit_bootstrap_key::Fourier128LweMultiBitBootstrapKey;
use crate::core_crypto::prelude::{
    Container, FourierLweMultiBitBootstrapKey, LweMultiBitBootstrapKey, UnsignedInteger,
};

impl<C: Container> Deprecable for LweMultiBitBootstrapKey<C>
where
    C::Element: UnsignedInteger,
{
    const TYPE_NAME: &'static str = "LweMultiBitBootstrapKey";
    const MIN_SUPPORTED_APP_VERSION: &'static str = "TFHE-rs v0.10";
}

#[derive(VersionsDispatch)]
pub enum LweMultiBitBootstrapKeyVersions<C: Container>
where
    C::Element: UnsignedInteger,
{
    V0(Deprecated<LweMultiBitBootstrapKey<C>>),
    V1(LweMultiBitBootstrapKey<C>),
}

impl<C: Container<Element = c64>> Deprecable for FourierLweMultiBitBootstrapKey<C> {
    const TYPE_NAME: &'static str = "FourierLweMultiBitBootstrapKey";
    const MIN_SUPPORTED_APP_VERSION: &'static str = "TFHE-rs v0.10";
}

#[derive(VersionsDispatch)]
pub enum FourierLweMultiBitBootstrapKeyVersions<C: Container<Element = c64>> {
    V0(Deprecated<FourierLweMultiBitBootstrapKey<C>>),
    V1(FourierLweMultiBitBootstrapKey<C>),
}

#[derive(VersionsDispatch)]
#[cfg_attr(dylint_lib = "tfhe_lints", allow(versionize_dispatch_enum))]
pub enum Fourier128MultiBitLweBootstrapKeyVersions<C: Container<Element = f64>> {
    V0(Fourier128LweMultiBitBootstrapKey<C>),
}
