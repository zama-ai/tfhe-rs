use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use aligned_vec::{avec, ABox};
use tfhe_fft::c64;

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

pub type FourierPolynomialOwned = FourierPolynomial<ABox<[c64]>>;

impl FourierPolynomial<ABox<[c64]>> {
    pub fn new(polynomial_size: PolynomialSize) -> Self {
        let boxed = avec![
            c64::default();
            polynomial_size.to_fourier_polynomial_size().0
        ]
        .into_boxed_slice();

        FourierPolynomial { data: boxed }
    }
}

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

    pub fn polynomial_size(&self) -> PolynomialSize {
        PolynomialSize(self.data.container_len() * 2)
    }
}
