//! Module containing the definition of the HpuLweKeyswitchKey.
//! Raw typed container without any logic
//! Conversion from/into tfhers entities should be implemented inside tfhers to prevent dependency
//! loop

use super::parameters::*;
use super::traits::container::*;

/// A [`Hpu Lwe Keyswitch key`](`HpuLweKeyswitchKey`).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HpuLweKeyswitchKey<C: Container> {
    data: C,
    params: HpuParameters,
}

impl<C: Container> AsRef<[C::Element]> for HpuLweKeyswitchKey<C> {
    fn as_ref(&self) -> &[C::Element] {
        self.data.as_ref()
    }
}

impl<C: ContainerMut> AsMut<[C::Element]> for HpuLweKeyswitchKey<C> {
    fn as_mut(&mut self) -> &mut [C::Element] {
        self.data.as_mut()
    }
}

pub fn hpu_lwe_keyswitch_key_size(params: &HpuParameters) -> usize {
    #[inline]
    fn divide_ceil(numerator: usize, denominator: usize) -> usize {
        let (div, rem) = (numerator / denominator, numerator % denominator);
        div + (rem != 0) as usize
    }

    // HwkeyswitchKey is a polyhedron padded with 0 to be multiple of lbx,lby,lbz
    let ks_p = &params.ks_params;
    let pbs_p = &params.pbs_params;
    let hw_ksk_x = ks_p.lbx * divide_ceil(pbs_p.lwe_dimension + 1, ks_p.lbx);
    let hw_ksk_y = ks_p.lby * divide_ceil(pbs_p.glwe_dimension * pbs_p.polynomial_size, ks_p.lby);
    // coefs over z are packed in u64
    let hw_ksk_z = divide_ceil(pbs_p.ks_level, ks_p.lbz);

    hw_ksk_x * hw_ksk_y * hw_ksk_z
}

impl<C: Container> HpuLweKeyswitchKey<C> {
    /// Create a [`HpuLweKeyswitchKey`] from an existing container.
    pub fn from_container(container: C, params: HpuParameters) -> Self {
        assert!(
            container.container_len() > 0,
            "Got an empty container to create a HpuLweKeyswitchKey"
        );
        assert!(
            container.container_len() == hpu_lwe_keyswitch_key_size(&params),
            "The provided container length is not valid. \
        It needs to match with parameters. \
        Got container length: {} and based on parameters value expect: {}.",
            container.container_len(),
            hpu_lwe_keyswitch_key_size(&params)
        );
        Self {
            data: container,
            params,
        }
    }

    /// Consume the entity and return its underlying container.
    ///
    /// See [`HpuLweKeyswitchKey::from_container`] for usage.
    pub fn into_container(self) -> C {
        self.data
    }
}

impl<C: Container> HpuLweKeyswitchKey<C> {
    /// Return the [`Parameters`] of the [`HpuLweKeyswitchKey`].
    ///
    /// See [`HpuLweKeyswitchKey::from_container`] for usage.
    pub fn params(&self) -> &HpuParameters {
        &self.params
    }

    /// Return a view of the [`HpuLweKeyswitchKey`]. This is useful if an algorithm takes a view by
    /// value.
    pub fn as_view(&self) -> HpuLweKeyswitchKey<&'_ [C::Element]> {
        HpuLweKeyswitchKey {
            data: self.data.as_ref(),
            params: self.params.clone(),
        }
    }
}

impl<C: ContainerMut> HpuLweKeyswitchKey<C> {
    /// Mutable variant of [`HpuLweKeyswitchKey::as_view`].
    pub fn as_mut_view(&mut self) -> HpuLweKeyswitchKey<&'_ mut [C::Element]> {
        HpuLweKeyswitchKey {
            data: self.data.as_mut(),
            params: self.params.clone(),
        }
    }
}

impl<T: std::clone::Clone, C: Container<Element = T>> HpuLweKeyswitchKey<C> {
    /// Slice key stream in interleaved chunks for each memory cut
    pub fn hw_slice(&self) -> Vec<Vec<C::Element>> {
        // Infer params from args
        let ks_p = &self.params.ks_params;
        let nb_pc = self.params.pc_params.ksk_pc;

        let mut ksk_slice = vec![Vec::new(); nb_pc];
        for (i, chunk) in self.data.as_ref().into_chunks(ks_p.lby / nb_pc).enumerate() {
            let cut_idx = i % nb_pc;

            // Copy in targeted stream_cut
            for c in chunk.iter() {
                ksk_slice[cut_idx].push(c.clone());
            }
        }
        ksk_slice
    }
}

impl<T: std::clone::Clone, C: ContainerMut<Element = T>> HpuLweKeyswitchKey<C> {
    /// Filled HpuLweBootstrapKey from hw_slice view
    pub fn copy_from_hw_slice(&mut self, hw_slice: &[&[T]]) {
        // TODO -> Implement the correct copy procedure
    }
}

/// A [`HpuLweKeyswitchKey`] owning the memory for its own storage.
pub type HpuLweKeyswitchKeyOwned<Scalar> = HpuLweKeyswitchKey<Vec<Scalar>>;
/// A [`HpuLweKeyswitchKey`] immutably borrowing memory for its own storage.
pub type HpuLweKeyswitchKeyView<'data, Scalar> = HpuLweKeyswitchKey<&'data [Scalar]>;
/// A [`HpuLweKeyswitchKey`] mutably borrowing memory for its own storage.
pub type HpuLweKeyswitchKeyMutView<'data, Scalar> = HpuLweKeyswitchKey<&'data mut [Scalar]>;

impl<Scalar: std::clone::Clone> HpuLweKeyswitchKeyOwned<Scalar> {
    /// Allocate memory and create a new owned [`HpuLweKeyswitchKey`].
    ///
    ///
    /// See [`HpuLweKeyswitchKey::from_container`] for usage.
    pub fn new(fill_with: Scalar, params: HpuParameters) -> Self {
        Self::from_container(vec![fill_with; hpu_lwe_keyswitch_key_size(&params)], params)
    }
}
