//! Module containing the definition of the HpuGlweLookuptable.
//! -> Mainly a Glwe body
//! Raw typed container without any logic
//! Conversion from/into tfhers entities should be implemented inside tfhers to prevent dependency
//! loop

use super::parameters::*;
use super::traits::container::*;

/// A [`Hpu GLWE lookuptable`](`HpuGlweLookuptable`).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HpuGlweLookuptable<C: Container> {
    data: C,
    params: HpuParameters,
}

impl<C: ContainerMut> AsMut<[C::Element]> for HpuGlweLookuptable<C> {
    fn as_mut(&mut self) -> &mut [C::Element] {
        self.data.as_mut()
    }
}

impl<C: Container> AsRef<[C::Element]> for HpuGlweLookuptable<C> {
    fn as_ref(&self) -> &[C::Element] {
        self.data.as_ref()
    }
}

pub fn hpu_glwe_lookuptable_size(params: &HpuParameters) -> usize {
    params.pbs_params.polynomial_size
}

impl<C: Container> HpuGlweLookuptable<C> {
    /// Create a [`HpuGlweLookuptable`] from an existing container.
    pub fn from_container(container: C, params: HpuParameters) -> Self {
        assert!(
            container.container_len() > 0,
            "Got an empty container to create a HpuGlweLookuptable"
        );
        assert!(
            container.container_len() == hpu_glwe_lookuptable_size(&params),
            "The provided container length is not valid. \
        It needs to match with parameters. \
        Got container length: {} and based on parameters value expect: {}.",
            container.container_len(),
            hpu_glwe_lookuptable_size(&params),
        );
        Self {
            data: container,
            params,
        }
    }

    /// Consume the entity and return its underlying container.
    ///
    /// See [`HpuGlweLookuptable::from_container`] for usage.
    pub fn into_container(self) -> C {
        self.data
    }
}

impl<C: Container> HpuGlweLookuptable<C> {
    /// Return the [`Parameters`] of the [`HpuGlweLookuptable`].
    ///
    /// See [`HpuGlweLookuptable::from_container`] for usage.
    pub fn params(&self) -> &HpuParameters {
        &self.params
    }

    /// Return a view of the [`HpuGlweLookuptable`]. This is useful if an algorithm takes a view by
    /// value.
    pub fn as_view(&self) -> HpuGlweLookuptable<&'_ [C::Element]> {
        HpuGlweLookuptable {
            data: self.data.as_ref(),
            params: self.params.clone(),
        }
    }
}

impl<C: ContainerMut> HpuGlweLookuptable<C> {
    /// Mutable variant of [`HpuGlweLookuptable::as_view`].
    pub fn as_mut_view(&mut self) -> HpuGlweLookuptable<&'_ mut [C::Element]> {
        HpuGlweLookuptable {
            data: self.data.as_mut(),
            params: self.params.clone(),
        }
    }
}

/// A [`HpuGlweLookuptable`] owning the memory for its own storage.
pub type HpuGlweLookuptableOwned<Scalar> = HpuGlweLookuptable<Vec<Scalar>>;
/// A [`HpuGlweLookuptable`] immutably borrowing memory for its own storage.
pub type HpuGlweLookuptableView<'data, Scalar> = HpuGlweLookuptable<&'data [Scalar]>;
/// A [`HpuGlweLookuptable`] mutably borrowing memory for its own storage.
pub type HpuGlweLookuptableMutView<'data, Scalar> = HpuGlweLookuptable<&'data mut [Scalar]>;

impl<Scalar: std::clone::Clone> HpuGlweLookuptableOwned<Scalar> {
    /// Allocate memory and create a new owned [`HpuGlweLookuptable`].
    ///
    /// See [`HpuGlweLookuptable::from_container`] for usage.
    pub fn new(fill_with: Scalar, params: HpuParameters) -> Self {
        Self::from_container(vec![fill_with; hpu_glwe_lookuptable_size(&params)], params)
    }
}
