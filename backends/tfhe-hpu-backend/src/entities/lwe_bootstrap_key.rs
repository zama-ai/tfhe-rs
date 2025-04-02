//! Module containing the definition of the HpuLweBootstrapKey.
//! Raw typed container without any logic
//! Conversion from/into tfhers entities should be implemented inside tfhers to prevent dependency
//! loop

use super::parameters::*;
use super::traits::container::*;

/// A [`Hpu lwe bootstrapping key`](`HpuLweBootstrapKey`).
/// Inner container is split in pc chunks to ease copy from/to hardware
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HpuLweBootstrapKey<C: Container> {
    pc_data: Vec<C>,
    params: HpuParameters,
}

/// Index inside the container abstracting away the inner pc split
impl<C: Container> std::ops::Index<usize> for HpuLweBootstrapKey<C> {
    type Output = C::Element;

    fn index(&self, index: usize) -> &Self::Output {
        let ntt_p = &self.params.ntt_params;
        let bsk_pc = self.params.pc_params.bsk_pc;
        let chunk_size = (ntt_p.radix * ntt_p.psi) / bsk_pc;
        let (pc, ofst) = (
            (index / chunk_size) % bsk_pc,
            (((index / chunk_size) / bsk_pc) * chunk_size) + (index % chunk_size),
        );
        &self.pc_data[pc].as_ref()[ofst]
    }
}

/// IndexMut inside the container abstracting away the inner pc split
impl<C: ContainerMut> std::ops::IndexMut<usize> for HpuLweBootstrapKey<C> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        let ntt_p = &self.params.ntt_params;
        let bsk_pc = self.params.pc_params.bsk_pc;
        let chunk_size = (ntt_p.radix * ntt_p.psi) / bsk_pc;
        let (pc, ofst) = (
            (index / chunk_size) % bsk_pc,
            (((index / chunk_size) / bsk_pc) * chunk_size) + (index % chunk_size),
        );
        &mut self.pc_data[pc].as_mut()[ofst]
    }
}

pub fn hpu_lwe_bootstrap_key_size(params: &HpuParameters) -> usize {
    let pbs_p = &params.pbs_params;
    pbs_p.lwe_dimension       // ciphertext_count
  * pbs_p.pbs_level           // ggsw_ciphertext_size
  * ((pbs_p.glwe_dimension +1)  // ggsw_level_matrix_size
  *  (pbs_p.glwe_dimension +1)
  *  pbs_p.polynomial_size)
}

impl<C: Container> HpuLweBootstrapKey<C> {
    /// Create a [`HpuLweBootstrapKey`] from an existing container.
    pub fn from_container(container: Vec<C>, params: HpuParameters) -> Self {
        debug_assert_eq!(
            (params.ntt_params.radix * params.ntt_params.psi) % params.pc_params.bsk_pc,
            0,
            "Error: Incompatible (R*PSI: {}, BSK_PC: {})",
            params.ntt_params.radix * params.ntt_params.psi,
            params.pc_params.bsk_pc
        );

        assert_eq!(
            container.len(),
            params.pc_params.bsk_pc,
            "Container chunk mismatch with bsk_pc number"
        );
        assert!(
            container.iter().map(|x| x.container_len()).sum::<usize>() > 0,
            "Got an empty container to create a HpuLweBootstrapKey"
        );
        assert_eq!(
            container.iter().map(|x| x.container_len()).sum::<usize>(),
            hpu_lwe_bootstrap_key_size(&params),
            "The provided container length is not valid. \
        It needs to match with parameters. \
        Got container length: {} and based on parameters value expect: {}.",
            container.iter().map(|x| x.container_len()).sum::<usize>(),
            hpu_lwe_bootstrap_key_size(&params)
        );

        Self {
            pc_data: container,
            params,
        }
    }

    /// Consume the entity and return its underlying container.
    ///
    /// See [`HpuLweBootstrapKey::from_container`] for usage.
    pub fn into_container(self) -> Vec<C> {
        self.pc_data
    }
}

impl<C: Container> HpuLweBootstrapKey<C> {
    /// Return the [`Parameters`] of the [`HpuLweBootstrapKey`].
    ///
    /// See [`HpuLweBootstrapKey::from_container`] for usage.
    pub fn params(&self) -> &HpuParameters {
        &self.params
    }

    /// Return the length of the [`HpuLweBootstrapKey`] underlying containers.
    pub fn len(&self) -> usize {
        self.pc_data.iter().map(|c| c.container_len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        !self.pc_data.iter().any(|c| c.container_len() != 0)
    }

    /// Return a view of the [`HpuLweBootstrapKey`]. This is useful if an algorithm takes a view by
    /// value.
    pub fn as_view(&self) -> HpuLweBootstrapKey<&'_ [C::Element]> {
        HpuLweBootstrapKey {
            pc_data: self.pc_data.iter().map(|x| x.as_ref()).collect::<Vec<_>>(),
            params: self.params.clone(),
        }
    }
}

impl<C: ContainerMut> HpuLweBootstrapKey<C> {
    /// Mutable variant of [`HpuLweBootstrapKey::as_view`].
    pub fn as_mut_view(&mut self) -> HpuLweBootstrapKey<&'_ mut [C::Element]> {
        HpuLweBootstrapKey {
            pc_data: self
                .pc_data
                .iter_mut()
                .map(|x| x.as_mut())
                .collect::<Vec<_>>(),
            params: self.params.clone(),
        }
    }
}

/// A [`HpuLweBootstrapKey`] owning the memory for its own storage.
pub type HpuLweBootstrapKeyOwned<Scalar> = HpuLweBootstrapKey<Vec<Scalar>>;
/// A [`HpuLweBootstrapKey`] immutably borrowing memory for its own storage.
pub type HpuLweBootstrapKeyView<'data, Scalar> = HpuLweBootstrapKey<&'data [Scalar]>;
/// A [`HpuLweBootstrapKey`] mutably borrowing memory for its own storage.
pub type HpuLweBootstrapKeyMutView<'data, Scalar> = HpuLweBootstrapKey<&'data mut [Scalar]>;

impl<Scalar: std::clone::Clone> HpuLweBootstrapKeyOwned<Scalar> {
    /// Allocate memory and create a new owned [`HpuLweBootstrapKey`].
    ///
    ///
    /// See [`HpuLweBootstrapKey::from_container`] for usage.
    pub fn new(fill_with: Scalar, params: HpuParameters) -> Self {
        let chunk_size = hpu_lwe_bootstrap_key_size(&params).div_euclid(params.pc_params.bsk_pc);
        let pc_data = (0..params.pc_params.bsk_pc)
            .map(|_| vec![fill_with.clone(); chunk_size])
            .collect::<Vec<_>>();

        Self::from_container(pc_data, params)
    }
}
