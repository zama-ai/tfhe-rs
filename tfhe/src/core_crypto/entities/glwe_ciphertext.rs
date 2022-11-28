use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::specification::parameters::*;

pub struct GlweBody<C: Container> {
    data: C,
}

impl<C: Container> GlweBody<C> {
    pub fn from_container(container: C) -> GlweBody<C> {
        assert!(
            container.container_len() > 0,
            "Got an empty container to create a GlweBody"
        );
        GlweBody { data: container }
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        PolynomialSize(self.data.container_len())
    }

    pub fn as_polynomial(&self) -> PolynomialView<'_, C::Element> {
        PolynomialView::from_container(self.as_ref())
    }
}

impl<C: ContainerMut> GlweBody<C> {
    pub fn as_mut_polynomial(&mut self) -> PolynomialMutView<'_, C::Element> {
        PolynomialMutView::from_container(self.as_mut())
    }
}

pub struct GlweMask<C: Container> {
    data: C,
    polynomial_size: PolynomialSize,
}

impl<C: Container> GlweMask<C> {
    pub fn from_container(container: C, polynomial_size: PolynomialSize) -> Self {
        assert!(
            container.container_len() % polynomial_size.0 == 0,
            "The provided container length is not valid. \
        It needs to be dividable by polynomial_size. \
        Got container length: {} and polynomial_size: {polynomial_size:?}.",
            container.container_len()
        );
        GlweMask {
            data: container,
            polynomial_size,
        }
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    pub fn glwe_dimension(&self) -> GlweDimension {
        GlweDimension(self.data.container_len() / self.polynomial_size.0)
    }

    pub fn as_polynomial_list(&self) -> PolynomialListView<'_, C::Element> {
        PolynomialListView::from_container(self.as_ref(), self.polynomial_size)
    }
}

impl<C: ContainerMut> GlweMask<C> {
    pub fn as_mut_polynomial_list(&mut self) -> PolynomialListMutView<'_, C::Element> {
        let polynomial_size = self.polynomial_size;
        PolynomialListMutView::from_container(self.as_mut(), polynomial_size)
    }
}

impl<T, C: Container<Element = T>> AsRef<[T]> for GlweMask<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T, C: ContainerMut<Element = T>> AsMut<[T]> for GlweMask<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

impl<T, C: Container<Element = T>> AsRef<[T]> for GlweBody<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T, C: ContainerMut<Element = T>> AsMut<[T]> for GlweBody<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

pub fn glwe_ciphertext_size(polynomial_size: PolynomialSize, glwe_size: GlweSize) -> usize {
    polynomial_size.0 * glwe_size.0
}

pub fn glwe_ciphertext_mask_size(
    polynomial_size: PolynomialSize,
    glwe_dimension: GlweDimension,
) -> usize {
    polynomial_size.0 * glwe_dimension.0
}

#[derive(Clone, Debug, PartialEq)]
pub struct GlweCiphertextBase<C: Container> {
    data: C,
    polynomial_size: PolynomialSize,
}

impl<T, C: Container<Element = T>> AsRef<[T]> for GlweCiphertextBase<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T, C: ContainerMut<Element = T>> AsMut<[T]> for GlweCiphertextBase<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

impl<Scalar, C: Container<Element = Scalar>> GlweCiphertextBase<C> {
    pub fn from_container(container: C, polynomial_size: PolynomialSize) -> GlweCiphertextBase<C> {
        assert!(
            container.container_len() > 0,
            "Got an empty container to create a GlweCiphertext"
        );
        assert!(
            container.container_len() % polynomial_size.0 == 0,
            "The provided container length is not valid. \
        It needs to be dividable by polynomial_size. \
        Got container length: {} and polynomial_size: {polynomial_size:?}.",
            container.container_len()
        );
        GlweCiphertextBase {
            data: container,
            polynomial_size,
        }
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    pub fn glwe_size(&self) -> GlweSize {
        GlweSize(self.as_ref().container_len() / self.polynomial_size.0)
    }

    pub fn get_mask_and_body(&self) -> (GlweMask<&[Scalar]>, GlweBody<&[Scalar]>) {
        let (mask, body) = self.data.as_ref().split_at(glwe_ciphertext_mask_size(
            self.polynomial_size,
            self.glwe_size().to_glwe_dimension(),
        ));

        (
            GlweMask::from_container(mask, self.polynomial_size),
            GlweBody::from_container(body),
        )
    }

    pub fn get_body(&self) -> GlweBody<&[Scalar]> {
        let body = &self.data.as_ref()[glwe_ciphertext_mask_size(
            self.polynomial_size,
            self.glwe_size().to_glwe_dimension(),
        )..];

        GlweBody::from_container(body)
    }

    pub fn get_mask(&self) -> GlweMask<&[Scalar]> {
        GlweMask::from_container(
            &self.as_ref()[0..glwe_ciphertext_mask_size(
                self.polynomial_size,
                self.glwe_size().to_glwe_dimension(),
            )],
            self.polynomial_size,
        )
    }

    pub fn as_polynomial_list(&self) -> PolynomialListBase<&'_ [Scalar]> {
        PolynomialListBase::from_container(self.as_ref(), self.polynomial_size)
    }

    pub fn as_view(&self) -> GlweCiphertextBase<&'_ [Scalar]> {
        GlweCiphertextBase {
            data: self.data.as_ref(),
            polynomial_size: self.polynomial_size,
        }
    }
}

impl<Scalar, C: ContainerMut<Element = Scalar>> GlweCiphertextBase<C> {
    pub fn get_mut_mask_and_body(&mut self) -> (GlweMask<&mut [Scalar]>, GlweBody<&mut [Scalar]>) {
        let polynomial_size = self.polynomial_size();
        let glwe_dimension = self.glwe_size().to_glwe_dimension();

        let (mask, body) = self
            .data
            .as_mut()
            .split_at_mut(glwe_ciphertext_mask_size(polynomial_size, glwe_dimension));

        (
            GlweMask::from_container(mask, polynomial_size),
            GlweBody::from_container(body),
        )
    }

    pub fn get_mut_body(&mut self) -> GlweBody<&mut [Scalar]> {
        let polynomial_size = self.polynomial_size();
        let glwe_dimension = self.glwe_size().to_glwe_dimension();

        let body =
            &mut self.data.as_mut()[glwe_ciphertext_mask_size(polynomial_size, glwe_dimension)..];

        GlweBody::from_container(body)
    }

    pub fn get_mut_mask(&mut self) -> GlweMask<&mut [Scalar]> {
        let polynomial_size = self.polynomial_size();
        let glwe_dimension = self.glwe_size().to_glwe_dimension();

        GlweMask::from_container(
            &mut self.as_mut()[0..glwe_ciphertext_mask_size(polynomial_size, glwe_dimension)],
            polynomial_size,
        )
    }

    pub fn as_mut_polynomial_list(&mut self) -> PolynomialListBase<&'_ mut [Scalar]> {
        let polynomial_size = self.polynomial_size;
        PolynomialListBase::from_container(self.as_mut(), polynomial_size)
    }

    pub fn as_mut_view(&mut self) -> GlweCiphertextBase<&'_ mut [Scalar]> {
        GlweCiphertextBase {
            data: self.data.as_mut(),
            polynomial_size: self.polynomial_size,
        }
    }
}

pub type GlweCiphertext<Scalar> = GlweCiphertextBase<Vec<Scalar>>;
pub type GlweCiphertextView<'data, Scalar> = GlweCiphertextBase<&'data [Scalar]>;
pub type GlweCiphertextMutView<'data, Scalar> = GlweCiphertextBase<&'data mut [Scalar]>;

impl<Scalar: Copy> GlweCiphertext<Scalar> {
    pub fn new(
        fill_with: Scalar,
        polynomial_size: PolynomialSize,
        glwe_size: GlweSize,
    ) -> GlweCiphertext<Scalar> {
        GlweCiphertext::from_container(
            vec![fill_with; glwe_ciphertext_size(polynomial_size, glwe_size)],
            polynomial_size,
        )
    }
}

#[derive(Clone, Copy)]
pub struct GlweCiphertextCreationMetadata(pub PolynomialSize);

impl<C: Container> CreateFrom<C> for GlweCiphertextBase<C> {
    type Metadata = GlweCiphertextCreationMetadata;

    #[inline]
    fn create_from(from: C, meta: Self::Metadata) -> GlweCiphertextBase<C> {
        let GlweCiphertextCreationMetadata(polynomial_size) = meta;
        GlweCiphertextBase::from_container(from, polynomial_size)
    }
}
