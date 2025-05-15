//! Module containing the definition of the HpuGlweCiphertext.
//! Raw typed container without any logic
//! Conversion from/into tfhers entities should be implemented inside tfhers to prevent dependency
//! loop

use super::parameters::*;
use super::traits::container::*;

/// A [`Hpu GLWE ciphertext`](`HpuGlweCiphertext`).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HpuGlweCiphertext<C: Container> {
    data: C,
    params: HpuParameters,
}

impl<C: ContainerMut> AsMut<[C::Element]> for HpuGlweCiphertext<C> {
    fn as_mut(&mut self) -> &mut [C::Element] {
        self.data.as_mut()
    }
}

impl<C: ContainerMut> AsRef<[C::Element]> for HpuGlweCiphertext<C> {
    fn as_ref(&self) -> &[C::Element] {
        self.data.as_ref()
    }
}

pub fn hpu_glwe_ciphertext_size(params: &HpuParameters) -> usize {
    (params.pbs_params.glwe_dimension + 1) * params.pbs_params.polynomial_size
}

impl<C: Container> HpuGlweCiphertext<C> {
    /// Create a [`HpuGlweCiphertext`] from an existing container.
    pub fn from_container(container: C, params: HpuParameters) -> Self {
        assert!(
            container.container_len() > 0,
            "Got an empty container to create a HpuGlweCiphertext"
        );
        assert!(
            container.container_len() == hpu_glwe_ciphertext_size(&params),
            "The provided container length is not valid. \
        It needs to match with parameters. \
        Got container length: {} and based on parameters value expect: {}.",
            container.container_len(),
            hpu_glwe_ciphertext_size(&params),
        );
        Self {
            data: container,
            params,
        }
    }

    /// Consume the entity and return its underlying container.
    ///
    /// See [`HpuGlweCiphertext::from_container`] for usage.
    pub fn into_container(self) -> C {
        self.data
    }
}

impl<C: Container> HpuGlweCiphertext<C> {
    /// Return the [`Parameters`] of the [`HpuGlweCiphertext`].
    ///
    /// See [`HpuGlweCiphertext::from_container`] for usage.
    pub fn params(&self) -> &HpuParameters {
        &self.params
    }

    /// Return a view of the [`HpuGlweCiphertext`]. This is useful if an algorithm takes a view by
    /// value.
    pub fn as_view(&self) -> HpuGlweCiphertext<&'_ [C::Element]> {
        HpuGlweCiphertext {
            data: self.data.as_ref(),
            params: self.params.clone(),
        }
    }
}

impl<C: ContainerMut> HpuGlweCiphertext<C> {
    /// Mutable variant of [`HpuGlweCiphertext::as_view`].
    pub fn as_mut_view(&mut self) -> HpuGlweCiphertext<&'_ mut [C::Element]> {
        HpuGlweCiphertext {
            data: self.data.as_mut(),
            params: self.params.clone(),
        }
    }
}

/// A [`HpuGlweCiphertext`] owning the memory for its own storage.
pub type HpuGlweCiphertextOwned<Scalar> = HpuGlweCiphertext<Vec<Scalar>>;
/// A [`HpuGlweCiphertext`] immutably borrowing memory for its own storage.
pub type HpuGlweCiphertextView<'data, Scalar> = HpuGlweCiphertext<&'data [Scalar]>;
/// A [`HpuGlweCiphertext`] mutably borrowing memory for its own storage.
pub type HpuGlweCiphertextMutView<'data, Scalar> = HpuGlweCiphertext<&'data mut [Scalar]>;

impl<Scalar: std::clone::Clone> HpuGlweCiphertextOwned<Scalar> {
    /// Allocate memory and create a new owned [`HpuGlweCiphertext`].
    ///
    /// # Note
    ///
    /// This function allocates a vector of the appropriate size and wraps it in the appropriate
    /// type.
    ///
    /// See [`HpuGlweCiphertext::from_container`] for usage.
    pub fn new(fill_with: Scalar, params: HpuParameters) -> Self {
        Self::from_container(vec![fill_with; hpu_glwe_ciphertext_size(&params)], params)
    }
}
