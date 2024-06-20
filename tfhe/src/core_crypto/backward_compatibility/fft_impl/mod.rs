use tfhe_versionable::UnversionizeError;

use aligned_vec::ABox;
use concrete_fft::c64;
use serde::{Deserialize, Serialize};

use crate::core_crypto::fft_impl::fft64::crypto::bootstrap::{
    FourierLweBootstrapKeyVersion, FourierLweBootstrapKeyVersionOwned,
};
use crate::core_crypto::fft_impl::fft64::math::fft::FourierPolynomialList;
use crate::core_crypto::prelude::{Container, FourierLweBootstrapKey, IntoContainerOwned};

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

impl<C: Container<Element = c64>> From<&FourierPolynomialList<C>>
    for FourierPolynomialListVersionedOwned
{
    fn from(value: &FourierPolynomialList<C>) -> Self {
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

#[derive(Serialize)]
pub enum FourierLweBootstrapKeyVersioned<'vers> {
    V0(FourierLweBootstrapKeyVersion<'vers>),
}

impl<'vers, C: Container<Element = c64>> From<&'vers FourierLweBootstrapKey<C>>
    for FourierLweBootstrapKeyVersioned<'vers>
{
    fn from(value: &'vers FourierLweBootstrapKey<C>) -> Self {
        Self::V0(value.into())
    }
}

#[derive(Serialize, Deserialize)]
pub enum FourierLweBootstrapKeyVersionedOwned {
    V0(FourierLweBootstrapKeyVersionOwned),
}

impl<C: Container<Element = c64>> From<&FourierLweBootstrapKey<C>>
    for FourierLweBootstrapKeyVersionedOwned
{
    fn from(value: &FourierLweBootstrapKey<C>) -> Self {
        Self::V0(value.into())
    }
}

impl<C: IntoContainerOwned<Element = c64>> TryFrom<FourierLweBootstrapKeyVersionedOwned>
    for FourierLweBootstrapKey<C>
{
    type Error = UnversionizeError;

    fn try_from(value: FourierLweBootstrapKeyVersionedOwned) -> Result<Self, Self::Error> {
        match value {
            FourierLweBootstrapKeyVersionedOwned::V0(v0) => Self::try_from(v0),
        }
    }
}
