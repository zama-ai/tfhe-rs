use tfhe_versionable::deprecation::{Deprecable, Deprecated};
use tfhe_versionable::VersionsDispatch;

use aligned_vec::ABox;
use serde::{Deserialize, Serialize};
use tfhe_fft::c64;

use crate::core_crypto::fft_impl::fft64::math::fft::FourierPolynomialList;
use crate::core_crypto::prelude::{
    Container, Fourier128GgswCiphertext, Fourier128LweBootstrapKey, FourierGgswCiphertext,
    FourierLweBootstrapKey, IntoContainerOwned,
};

#[derive(Serialize)]
pub enum FourierPolynomialListVersioned<'vers> {
    V0(FourierPolynomialList<&'vers [c64]>),
}

impl<'vers, C: Container<Element = c64>> From<&'vers FourierPolynomialList<C>>
    for FourierPolynomialListVersioned<'vers>
{
    fn from(value: &'vers FourierPolynomialList<C>) -> Self {
        let ref_poly = FourierPolynomialList {
            data: value.data.as_ref(),
            polynomial_size: value.polynomial_size,
        };
        Self::V0(ref_poly)
    }
}

// Here we do not derive "VersionsDispatch" so that we can implement a non recursive Versionize
#[derive(Serialize, Deserialize)]
pub enum FourierPolynomialListVersionedOwned {
    V0(FourierPolynomialList<ABox<[c64]>>),
}

impl<C: Container<Element = c64>> From<FourierPolynomialList<C>>
    for FourierPolynomialListVersionedOwned
{
    fn from(value: FourierPolynomialList<C>) -> Self {
        let owned_poly = FourierPolynomialList {
            data: ABox::collect(value.data.as_ref().iter().copied()),
            polynomial_size: value.polynomial_size,
        };
        Self::V0(owned_poly)
    }
}

impl<C: IntoContainerOwned<Element = c64>> From<FourierPolynomialListVersionedOwned>
    for FourierPolynomialList<C>
{
    fn from(value: FourierPolynomialListVersionedOwned) -> Self {
        match value {
            FourierPolynomialListVersionedOwned::V0(v0) => Self {
                data: C::collect(v0.data.iter().copied()),
                polynomial_size: v0.polynomial_size,
            },
        }
    }
}

impl<C: Container<Element = c64>> Deprecable for FourierLweBootstrapKey<C> {
    const TYPE_NAME: &'static str = "FourierLweBootstrapKey";
    const MIN_SUPPORTED_APP_VERSION: &'static str = "TFHE-rs v0.10";
}

#[derive(VersionsDispatch)]
pub enum FourierLweBootstrapKeyVersions<C: Container<Element = c64>> {
    V0(Deprecated<FourierLweBootstrapKey<C>>),
    V1(FourierLweBootstrapKey<C>),
}

impl<C: Container<Element = c64>> Deprecable for FourierGgswCiphertext<C> {
    const TYPE_NAME: &'static str = "FourierGgswCiphertext";
    const MIN_SUPPORTED_APP_VERSION: &'static str = "TFHE-rs v0.10";
}

#[derive(VersionsDispatch)]
pub enum FourierGgswCiphertextVersions<C: Container<Element = c64>> {
    V0(Deprecated<FourierGgswCiphertext<C>>),
    V1(FourierGgswCiphertext<C>),
}

impl<C: Container<Element = f64>> Deprecable for Fourier128LweBootstrapKey<C> {
    const TYPE_NAME: &'static str = "Fourier128LweBootstrapKey";
    const MIN_SUPPORTED_APP_VERSION: &'static str = "TFHE-rs v0.10";
}

#[derive(VersionsDispatch)]
pub enum Fourier128LweBootstrapKeyVersions<C: Container<Element = f64>> {
    V0(Deprecated<Fourier128LweBootstrapKey<C>>),
    V1(Fourier128LweBootstrapKey<C>),
}

impl<C: Container<Element = f64>> Deprecable for Fourier128GgswCiphertext<C> {
    const TYPE_NAME: &'static str = "Fourier128GgswCiphertext";
    const MIN_SUPPORTED_APP_VERSION: &'static str = "TFHE-rs v0.10";
}

#[derive(VersionsDispatch)]
pub enum Fourier128GgswCiphertextVersions<C: Container<Element = f64>> {
    V0(Deprecated<Fourier128GgswCiphertext<C>>),
    V1(Fourier128GgswCiphertext<C>),
}
