use super::super::as_mut_uninit;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::PolynomialBase;
use concrete_fft::c64;

//--------------------------------------------------------------------------------
// Structure definitions
//--------------------------------------------------------------------------------

/// Polynomial in the Fourier domain.
///
/// # Note
///
/// Polynomials in the Fourier domain have half the size of the corresponding polynomials in
/// the standard domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FourierPolynomial<C: Container> {
    pub data: C,
}

pub type FourierPolynomialView<'a> = FourierPolynomial<&'a [c64]>;
pub type FourierPolynomialMutView<'a> = FourierPolynomial<&'a mut [c64]>;

/// Polynomial in the standard domain, with possibly uninitialized coefficients.
///
/// This is used for the Fourier transforms to avoid the cost of initializing the output buffer,
/// which can be non negligible.
pub type PolynomialUninitMutView<'a, Scalar> =
    PolynomialBase<&'a mut [core::mem::MaybeUninit<Scalar>]>;

/// Polynomial in the Fourier domain, with possibly uninitialized coefficients.
///
/// This is used for the Fourier transforms to avoid the cost of initializing the output buffer,
/// which can be non negligible.
///
/// # Note
///
/// Polynomials in the Fourier domain have half the size of the corresponding polynomials in
/// the standard domain.
pub type FourierPolynomialUninitMutView<'a> =
    FourierPolynomial<&'a mut [core::mem::MaybeUninit<c64>]>;

impl<C: Container<Element = c64>> FourierPolynomial<C> {
    pub fn as_view(&self) -> FourierPolynomialView<'_> {
        FourierPolynomial {
            data: self.data.as_ref(),
        }
    }

    pub fn as_mut_view(&mut self) -> FourierPolynomialMutView<'_>
    where
        C: AsMut<[c64]>,
    {
        FourierPolynomial {
            data: self.data.as_mut(),
        }
    }
}

impl<'a, Scalar> PolynomialBase<&'a mut [Scalar]> {
    /// # Safety
    ///
    /// No uninitialized values must be written into the output buffer when the borrow ends
    pub unsafe fn into_uninit(self) -> PolynomialUninitMutView<'a, Scalar> {
        PolynomialUninitMutView::from_container(as_mut_uninit(self.into_container()))
    }
}

impl<'a> FourierPolynomialMutView<'a> {
    /// # Safety
    ///
    /// No uninitialized values must be written into the output buffer when the borrow ends
    pub unsafe fn into_uninit(self) -> FourierPolynomialUninitMutView<'a> {
        FourierPolynomialUninitMutView {
            data: as_mut_uninit(self.data),
        }
    }
}
