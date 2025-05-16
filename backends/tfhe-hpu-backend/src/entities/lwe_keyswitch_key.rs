//! Module containing the definition of the HpuLweKeyswitchKey.
//! Raw typed container without any logic
//! Conversion from/into tfhers entities should be implemented inside tfhers to prevent dependency
//! loop

use super::parameters::*;
use super::traits::container::*;

/// A [`Hpu Lwe Keyswitch key`](`HpuLweKeyswitchKey`).
/// Inner container is split in pc chunks to ease copy from/to hardware
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HpuLweKeyswitchKey<C: Container> {
    pc_data: Vec<C>,
    params: HpuParameters,
}

/// Index inside the container abstracting away the inner pc split
impl<C: Container> std::ops::Index<usize> for HpuLweKeyswitchKey<C> {
    type Output = C::Element;

    fn index(&self, index: usize) -> &Self::Output {
        let (pc, ofst) = self.get_pc_offset_from_index(index);
        &self.pc_data[pc].as_ref()[ofst]
    }
}

/// IndexMut inside the container abstracting away the inner pc split
impl<C: ContainerMut> std::ops::IndexMut<usize> for HpuLweKeyswitchKey<C> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        let (pc, ofst) = self.get_pc_offset_from_index(index);
        &mut self.pc_data[pc].as_mut()[ofst]
    }
}

pub fn hpu_lwe_keyswitch_key_size(params: &HpuParameters) -> usize {
    // HwkeyswitchKey is a polyhedron padded with 0 to be multiple of lbx,lby,lbz
    let ks_p = &params.ks_params;
    let pbs_p = &params.pbs_params;
    let hw_ksk_x = ks_p.lbx * (pbs_p.lwe_dimension + 1).div_ceil(ks_p.lbx);
    let hw_ksk_y = ks_p.lby * (pbs_p.glwe_dimension * pbs_p.polynomial_size).div_ceil(ks_p.lby);
    // coefs over z are packed in u64
    let hw_ksk_z = pbs_p.ks_level.div_ceil(ks_p.lbz);

    hw_ksk_x * hw_ksk_y * hw_ksk_z
}

impl<C: Container> HpuLweKeyswitchKey<C> {
    /// Create a [`HpuLweKeyswitchKey`] from an existing container.
    pub fn from_container(container: Vec<C>, params: HpuParameters) -> Self {
        assert_eq!(
            container.len(),
            params.pc_params.ksk_pc,
            "Container chunk mismatch with ksk_pc number"
        );
        assert_eq!(
            container.iter().map(|x| x.container_len()).sum::<usize>(),
            hpu_lwe_keyswitch_key_size(&params),
            "The provided container length is not valid. \
        It needs to match with parameters. \
        Got container length: {} and based on parameters value expect: {}.",
            container.iter().map(|x| x.container_len()).sum::<usize>(),
            hpu_lwe_keyswitch_key_size(&params)
        );
        Self {
            pc_data: container,
            params,
        }
    }

    /// Consume the entity and return its underlying container.
    ///
    /// See [`HpuLweKeyswitchKey::from_container`] for usage.
    pub fn into_container(self) -> Vec<C> {
        self.pc_data
    }
}

impl<C: Container> HpuLweKeyswitchKey<C> {
    /// Return the [`Parameters`] of the [`HpuLweKeyswitchKey`].
    ///
    /// See [`HpuLweKeyswitchKey::from_container`] for usage.
    pub fn params(&self) -> &HpuParameters {
        &self.params
    }

    /// Return the length of the [`HpuLweKeyswitchKey`] underlying containers.
    pub fn len(&self) -> usize {
        self.pc_data.iter().map(|c| c.container_len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        !self.pc_data.iter().any(|c| c.container_len() != 0)
    }

    /// Return a view of the [`HpuLweKeyswitchKey`]. This is useful if an algorithm takes a view by
    /// value.
    pub fn as_view(&self) -> HpuLweKeyswitchKey<&'_ [C::Element]> {
        HpuLweKeyswitchKey {
            pc_data: self.pc_data.iter().map(|x| x.as_ref()).collect::<Vec<_>>(),
            params: self.params.clone(),
        }
    }

    /// Utility function to retrieved pc/offset from a global index in the key
    /// Use by the Index/IndexMut trait implementation
    fn get_pc_offset_from_index(&self, index: usize) -> (usize, usize) {
        let ksk_pc = self.params.pc_params.ksk_pc;
        let chunk_size = self.params.ks_params.lby / ksk_pc;
        (
            (index / chunk_size) % ksk_pc,
            (((index / chunk_size) / ksk_pc) * chunk_size) + (index % chunk_size),
        )
    }
}

impl<C: ContainerMut> HpuLweKeyswitchKey<C> {
    /// Mutable variant of [`HpuLweKeyswitchKey::as_view`].
    pub fn as_mut_view(&mut self) -> HpuLweKeyswitchKey<&'_ mut [C::Element]> {
        HpuLweKeyswitchKey {
            pc_data: self
                .pc_data
                .iter_mut()
                .map(|x| x.as_mut())
                .collect::<Vec<_>>(),
            params: self.params.clone(),
        }
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
        let chunk_size = hpu_lwe_keyswitch_key_size(&params) / params.pc_params.ksk_pc;
        let pc_data = (0..params.pc_params.ksk_pc)
            .map(|_| vec![fill_with.clone(); chunk_size])
            .collect::<Vec<_>>();
        Self::from_container(pc_data, params)
    }
}
