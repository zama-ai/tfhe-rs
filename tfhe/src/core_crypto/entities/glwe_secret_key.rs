use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::specification::parameters::{GlweDimension, PolynomialSize};

#[derive(Clone, Debug, PartialEq)]
pub struct GlweSecretKeyBase<C: Container> {
    data: C,
    polynomial_size: PolynomialSize,
}

impl<T, C: Container<Element = T>> AsRef<[T]> for GlweSecretKeyBase<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T, C: ContainerMut<Element = T>> AsMut<[T]> for GlweSecretKeyBase<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

impl<Scalar, C: Container<Element = Scalar>> GlweSecretKeyBase<C> {
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
        GlweSecretKeyBase {
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

    pub fn into_lwe_secret_key(self) -> LweSecretKeyBase<C> {
        LweSecretKeyBase::from_container(self.data)
    }
}

pub type GlweSecretKey<Scalar> = GlweSecretKeyBase<Vec<Scalar>>;

impl<Scalar> GlweSecretKey<Scalar>
where
    Scalar: Copy,
{
    pub fn new(
        value: Scalar,
        glwe_dimension: GlweDimension,
        polynomial_size: PolynomialSize,
    ) -> GlweSecretKey<Scalar> {
        GlweSecretKey::from_container(
            vec![value; glwe_dimension.0 * polynomial_size.0],
            polynomial_size,
        )
    }
}

// TODO REFACTOR
// Remove the back and forth conversions
impl From<GlweSecretKey<u64>> for crate::core_crypto::prelude::GlweSecretKey64 {
    fn from(new_glwe_secret_key: GlweSecretKey<u64>) -> Self {
        use crate::core_crypto::commons::crypto::secret::GlweSecretKey as PrivateGlweSecretKey;
        use crate::core_crypto::prelude::GlweSecretKey64;
        GlweSecretKey64(PrivateGlweSecretKey::binary_from_container(
            new_glwe_secret_key.data,
            new_glwe_secret_key.polynomial_size,
        ))
    }
}

impl From<crate::core_crypto::prelude::GlweSecretKey64> for GlweSecretKey<u64> {
    fn from(old_glwe_secret_key: crate::core_crypto::prelude::GlweSecretKey64) -> Self {
        use crate::core_crypto::commons::math::tensor::IntoTensor;
        let polynomial_size = old_glwe_secret_key.0.polynomial_size();
        GlweSecretKey::<u64>::from_container(
            old_glwe_secret_key.0.into_tensor().into_container(),
            polynomial_size,
        )
    }
}
