use concrete_fft::c64;
use serde::{Deserialize, Serialize};
use tfhe_versionable::{UnversionizeError, VersionsDispatch};

use crate::core_crypto::prelude::{
    Container, FourierLweMultiBitBootstrapKey, FourierLweMultiBitBootstrapKeyVersion,
    FourierLweMultiBitBootstrapKeyVersionOwned, IntoContainerOwned, LweMultiBitBootstrapKey,
    UnsignedInteger,
};

#[derive(VersionsDispatch)]
pub enum LweMultiBitBootstrapKeyVersions<C: Container>
where
    C::Element: UnsignedInteger,
{
    V0(LweMultiBitBootstrapKey<C>),
}

#[derive(Serialize)]
pub enum FourierLweMultiBitBootstrapKeyVersioned<'vers> {
    V0(FourierLweMultiBitBootstrapKeyVersion<'vers>),
}

impl<'vers, C: Container<Element = c64>> From<&'vers FourierLweMultiBitBootstrapKey<C>>
    for FourierLweMultiBitBootstrapKeyVersioned<'vers>
{
    fn from(value: &'vers FourierLweMultiBitBootstrapKey<C>) -> Self {
        Self::V0(value.into())
    }
}

#[derive(Serialize, Deserialize)]
pub enum FourierLweMultiBitBootstrapKeyVersionedOwned {
    V0(FourierLweMultiBitBootstrapKeyVersionOwned),
}

impl<C: Container<Element = c64>> From<&FourierLweMultiBitBootstrapKey<C>>
    for FourierLweMultiBitBootstrapKeyVersionedOwned
{
    fn from(value: &FourierLweMultiBitBootstrapKey<C>) -> Self {
        Self::V0(value.into())
    }
}

impl<C: IntoContainerOwned<Element = c64>> TryFrom<FourierLweMultiBitBootstrapKeyVersionedOwned>
    for FourierLweMultiBitBootstrapKey<C>
{
    type Error = UnversionizeError;

    fn try_from(value: FourierLweMultiBitBootstrapKeyVersionedOwned) -> Result<Self, Self::Error> {
        match value {
            FourierLweMultiBitBootstrapKeyVersionedOwned::V0(v0) => Self::try_from(v0),
        }
    }
}
