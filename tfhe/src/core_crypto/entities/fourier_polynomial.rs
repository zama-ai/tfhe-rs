use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use aligned_vec::{avec, ABox};
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
    data: C,
}

pub type FourierPolynomialView<'a> = FourierPolynomial<&'a [c64]>;
pub type FourierPolynomialMutView<'a> = FourierPolynomial<&'a mut [c64]>;
pub type FourierPolynomialOwned = FourierPolynomial<ABox<[c64]>>;

impl FourierPolynomialOwned {
    pub fn new(polynomial_size: PolynomialSize) -> FourierPolynomial<ABox<[c64]>> {
        let boxed = avec![
            c64::default();
            polynomial_size.to_fourier_polynomial_size().0
        ]
        .into_boxed_slice();

        FourierPolynomial { data: boxed }
    }
}

impl<T, C: Container<Element = T>> AsRef<[T]> for FourierPolynomial<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T, C: ContainerMut<Element = T>> AsMut<[T]> for FourierPolynomial<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

impl<C: Container<Element = c64>> FourierPolynomial<C> {
    /// Create a [`FourierPolynomial`] from an existing container.
    ///
    /// # Note
    ///
    /// This function only wraps a container in the appropriate type.
    pub fn from_container(container: C) -> FourierPolynomial<C> {
        assert!(
            container.container_len() > 0,
            "Got an empty container to create a Polynomial"
        );
        FourierPolynomial { data: container }
    }

    /// Return the [`PolynomialSize`] of the [`FourierPolynomial`].
    pub fn polynomial_size(&self) -> PolynomialSize {
        FourierPolynomialSize(self.data.container_len()).to_standard_polynomial_size()
    }

    /// Consume the entity and return its underlying container.
    pub fn into_container(self) -> C {
        self.data
    }

    /// Return a view of the [`FourierPolynomial`]. This is useful if an algorithm takes a view by
    /// value.
    pub fn as_view(&self) -> FourierPolynomialView<'_> {
        FourierPolynomialView::from_container(self.as_ref())
    }
}

impl<C: ContainerMut<Element = c64>> FourierPolynomial<C> {
    /// Return a view of the [`FourierPolynomial`]. This is useful if an algorithm takes a view by
    /// value.
    pub fn as_mut_view(&mut self) -> FourierPolynomialMutView<'_> {
        FourierPolynomialMutView::from_container(self.as_mut())
    }
}

/// Metadata used in the [`CreateFrom`] implementation to create [`FourierPolynomial`] entities.
#[derive(Clone, Copy)]
pub struct FourierPolynomialCreationMetadata();

impl<C: Container<Element = c64>> CreateFrom<C> for FourierPolynomial<C> {
    type Metadata = FourierPolynomialCreationMetadata;

    #[inline]
    fn create_from(from: C, _: Self::Metadata) -> FourierPolynomial<C> {
        FourierPolynomial::from_container(from)
    }
}
