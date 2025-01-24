use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use aligned_vec::{avec, ABox};

//--------------------------------------------------------------------------------
// Structure definitions
//--------------------------------------------------------------------------------

/// Polynomial in the Fourier128 domain.
///
/// # Note
///
/// Polynomials in the Fourier128 domain have half the size of the corresponding polynomials in
/// the standard domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fourier128Polynomial<C: Container> {
    pub data_re0: C,
    pub data_re1: C,
    pub data_im0: C,
    pub data_im1: C,
}

pub type Fourier128PolynomialView<'a> = Fourier128Polynomial<&'a [f64]>;
pub type Fourier128PolynomialMutView<'a> = Fourier128Polynomial<&'a mut [f64]>;

pub type Fourier128PolynomialOwned = Fourier128Polynomial<ABox<[f64]>>;

impl Fourier128Polynomial<ABox<[f64]>> {
    pub fn new(polynomial_size: PolynomialSize) -> Self {
        let fourier_polynomial_size = polynomial_size.to_fourier_polynomial_size();

        let boxed_re0 = avec![
            f64::default();
            fourier_polynomial_size.0
        ]
        .into_boxed_slice();
        let boxed_re1 = avec![
            f64::default();
            fourier_polynomial_size.0
        ]
        .into_boxed_slice();
        let boxed_im0 = avec![
            f64::default();
            fourier_polynomial_size.0
        ]
        .into_boxed_slice();
        let boxed_im1 = avec![
            f64::default();
            fourier_polynomial_size.0
        ]
        .into_boxed_slice();

        Fourier128Polynomial {
            data_re0: boxed_re0,
            data_re1: boxed_re1,
            data_im0: boxed_im0,
            data_im1: boxed_im1,
        }
    }
}

impl<C: Container<Element = f64>> Fourier128Polynomial<C> {
    pub fn as_view(&self) -> Fourier128PolynomialView<'_> {
        Fourier128Polynomial {
            data_re0: self.data_re0.as_ref(),
            data_re1: self.data_re1.as_ref(),
            data_im0: self.data_im0.as_ref(),
            data_im1: self.data_im1.as_ref(),
        }
    }

    pub fn as_mut_view(&mut self) -> Fourier128PolynomialMutView<'_>
    where
        C: AsMut<[f64]>,
    {
        let Self {
            data_re0,
            data_re1,
            data_im0,
            data_im1,
        } = self;

        Fourier128Polynomial {
            data_re0: data_re0.as_mut(),
            data_re1: data_re1.as_mut(),
            data_im0: data_im0.as_mut(),
            data_im1: data_im1.as_mut(),
        }
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        PolynomialSize(self.data_re0.container_len() * 2)
    }
}
