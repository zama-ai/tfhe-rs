use crate::core_crypto::commons::parameters::{PolynomialCount, PolynomialSize};
use crate::core_crypto::commons::traits::Container;
use crate::core_crypto::entities::*;
use crate::core_crypto::prelude::Split;
use concrete_fft::c64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FourierPolynomialList<C: Container> {
    pub data: C,
    pub polynomial_size: PolynomialSize,
}

impl<C: Container> FourierPolynomialList<C> {
    pub fn polynomial_count(&self) -> PolynomialCount {
        PolynomialCount(
            self.data.container_len() / self.polynomial_size.to_fourier_polynomial_size().0,
        )
    }
}

impl<C: Container<Element = c64> + Split> FourierPolynomialList<C> {
    pub fn into_polynomial_iter(self) -> impl DoubleEndedIterator<Item = FourierPolynomial<C>> {
        self.data
            .into_chunks(self.polynomial_size.to_fourier_polynomial_size().0)
            .map(FourierPolynomial::from_container)
    }
}
