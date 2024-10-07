use tfhe_versionable::VersionsDispatch;

use aligned_vec::ABox;
use concrete_fft::c64;
use serde::{Deserialize, Serialize};

use crate::core_crypto::fft_impl::fft64::math::fft::FourierPolynomialList;
use crate::core_crypto::prelude::{
    Container, Fourier128GgswCiphertext, Fourier128LweBootstrapKey, FourierGgswCiphertext,
    FourierLweBootstrapKey, IntoContainerOwned,
};

#[derive(Serialize)]
#[cfg_attr(tfhe_lints, allow(tfhe_lints::serialize_without_versionize))]
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
#[cfg_attr(tfhe_lints, allow(tfhe_lints::serialize_without_versionize))]
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

#[derive(VersionsDispatch)]
pub enum FourierLweBootstrapKeyVersions<C: Container<Element = c64>> {
    V0(FourierLweBootstrapKey<C>),
}

#[derive(VersionsDispatch)]
pub enum FourierGgswCiphertextVersions<C: Container<Element = c64>> {
    V0(FourierGgswCiphertext<C>),
}

#[derive(VersionsDispatch)]
pub enum Fourier128LweBootstrapKeyVersions<C: Container<Element = f64>> {
    V0(Fourier128LweBootstrapKey<C>),
}

#[derive(VersionsDispatch)]
pub enum Fourier128GgswCiphertextVersions<C: Container<Element = f64>> {
    V0(Fourier128GgswCiphertext<C>),
}
