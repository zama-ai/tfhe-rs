use super::super::math::polynomial::*;
use crate::core_crypto::commons::math::tensor::{Container, IntoChunks};
use crate::core_crypto::commons::math::torus::UnsignedTorus;
use crate::core_crypto::prelude::{GlweSize, PolynomialSize};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "backend_fft_serialization",
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct GlweCiphertext<C: Container> {
    data: C,
    polynomial_size: PolynomialSize,
    glwe_size: GlweSize,
}

pub type GlweCiphertextView<'a, Scalar> = GlweCiphertext<&'a [Scalar]>;
pub type GlweCiphertextMutView<'a, Scalar> = GlweCiphertext<&'a mut [Scalar]>;

impl<C: Container> GlweCiphertext<C> {
    pub fn new(data: C, polynomial_size: PolynomialSize, glwe_size: GlweSize) -> Self
    where
        C: Container,
    {
        assert_eq!(data.container_len(), polynomial_size.0 * glwe_size.0);

        Self {
            data,
            polynomial_size,
            glwe_size,
        }
    }

    /// Returns an iterator over the polynomials in `self`.
    pub fn into_polynomials(self) -> impl DoubleEndedIterator<Item = Polynomial<C>>
    where
        C: IntoChunks,
    {
        self.data
            .split_into(self.glwe_size.0)
            .map(|chunk| Polynomial { data: chunk })
    }

    pub fn data(self) -> C {
        self.data
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    pub fn glwe_size(&self) -> GlweSize {
        self.glwe_size
    }

    pub fn as_view(&self) -> GlweCiphertextView<'_, C::Element> {
        GlweCiphertext {
            data: self.data.as_ref(),
            polynomial_size: self.polynomial_size,
            glwe_size: self.glwe_size,
        }
    }

    pub fn as_mut_view(&mut self) -> GlweCiphertextMutView<'_, C::Element>
    where
        C: AsMut<[C::Element]>,
    {
        GlweCiphertext {
            data: self.data.as_mut(),
            polynomial_size: self.polynomial_size,
            glwe_size: self.glwe_size,
        }
    }
}

impl<'a, Scalar> GlweCiphertextView<'a, Scalar> {
    /// Fills an LWE ciphertext with the extraction of one coefficient of the current GLWE
    /// ciphertext.
    pub fn fill_lwe_with_sample_extraction(self, lwe: &mut [Scalar], nth: usize)
    where
        Scalar: UnsignedTorus,
    {
        let this = crate::core_crypto::commons::crypto::glwe::GlweCiphertext::from_container(
            self.data,
            self.polynomial_size,
        );
        let mut lwe = crate::core_crypto::commons::crypto::lwe::LweCiphertext::from_container(lwe);
        #[allow(deprecated)]
        let n_th = crate::core_crypto::prelude::MonomialDegree(nth);

        this.fill_lwe_with_sample_extraction(&mut lwe, n_th);
    }
}
