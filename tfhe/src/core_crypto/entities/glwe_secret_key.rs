use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct GlweSecretKey<C: Container> {
    data: C,
    polynomial_size: PolynomialSize,
}

impl<T, C: Container<Element = T>> AsRef<[T]> for GlweSecretKey<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T, C: ContainerMut<Element = T>> AsMut<[T]> for GlweSecretKey<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

impl<Scalar, C: Container<Element = Scalar>> GlweSecretKey<C> {
    pub fn from_container(container: C, polynomial_size: PolynomialSize) -> Self {
        assert!(
            container.container_len() > 0,
            "Got an empty container to create a GlweSecretKey"
        );
        assert!(
            container.container_len() % polynomial_size.0 == 0,
            "The provided container length is not valid. \
        It needs to be dividable by polynomial_size. \
        Got container length: {} and polynomial_size: {polynomial_size:?}",
            container.container_len()
        );
        GlweSecretKey {
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

    pub fn into_lwe_secret_key(self) -> LweSecretKey<C> {
        LweSecretKey::from_container(self.data)
    }

    pub fn as_polynomial_list(&self) -> PolynomialListView<'_, C::Element> {
        PolynomialListView::from_container(self.as_ref(), self.polynomial_size)
    }

    pub fn into_container(self) -> C {
        self.data
    }
}

pub type GlweSecretKeyOwned<Scalar> = GlweSecretKey<Vec<Scalar>>;

impl<Scalar> GlweSecretKeyOwned<Scalar>
where
    Scalar: Copy,
{
    pub fn new(
        value: Scalar,
        glwe_dimension: GlweDimension,
        polynomial_size: PolynomialSize,
    ) -> GlweSecretKeyOwned<Scalar> {
        GlweSecretKeyOwned::from_container(
            vec![value; glwe_dimension.0 * polynomial_size.0],
            polynomial_size,
        )
    }
}
