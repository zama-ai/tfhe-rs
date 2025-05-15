//! Module containing the definition of the HpuLweCiphertext.
//! Raw typed container without any logic
//! Conversion from/into tfhers entities should be implemented inside tfhers to prevent dependency
//! loop

use super::parameters::*;
use super::traits::container::*;

/// A [`Hpu LWE ciphertext`](`HpuLweCiphertext`).
/// Inner container is split in pc chunks to ease copy from/to hardware
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HpuLweCiphertext<C: Container> {
    pc_data: Vec<C>,
    params: HpuParameters,
}

/// Index inside the container abstracting away the inner pc split
impl<C: Container> std::ops::Index<usize> for HpuLweCiphertext<C> {
    type Output = C::Element;

    fn index(&self, index: usize) -> &Self::Output {
        let pem_pc = self.params.pc_params.pem_pc;
        let chunk_size = self.params.regf_params.coef_nb / pem_pc;
        let (pc, ofst) = (
            (index / chunk_size) % pem_pc,
            (((index / chunk_size) / pem_pc) * chunk_size) + (index % chunk_size),
        );
        &self.pc_data[pc].as_ref()[ofst]
    }
}

/// IndexMut inside the container abstracting away the inner pc split
impl<C: ContainerMut> std::ops::IndexMut<usize> for HpuLweCiphertext<C> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        let pem_pc = self.params.pc_params.pem_pc;
        let chunk_size = self.params.regf_params.coef_nb / pem_pc;
        let (pc, ofst) = (
            (index / chunk_size) % pem_pc,
            (((index / chunk_size) / pem_pc) * chunk_size) + (index % chunk_size),
        );
        &mut self.pc_data[pc].as_mut()[ofst]
    }
}

#[allow(unused)]
// NB: HPU only handle Big Lwe over it's boundaries
// Indeed only the Big encryption key-choice is supported and the small lwe stay inside the chip
// (never reach the host)
pub fn hpu_small_lwe_ciphertext_size(params: &HpuParameters) -> usize {
    params.pbs_params.lwe_dimension + 1
}

pub fn hpu_big_lwe_ciphertext_size(params: &HpuParameters) -> usize {
    (params.pbs_params.glwe_dimension * params.pbs_params.polynomial_size) + 1
}

impl<C: Container> HpuLweCiphertext<C> {
    /// Create a [`HpuLweCiphertext`] from an existing container.
    pub fn from_container(container: Vec<C>, params: HpuParameters) -> Self {
        assert_eq!(
            container.len(),
            params.pc_params.pem_pc,
            "Container chunk mismatch with pem_pc number"
        );
        assert!(
            container.iter().map(|x| x.container_len()).sum::<usize>() > 0,
            "Got an empty container to create a HpuLweCiphertext"
        );
        assert_eq!(
            container.iter().map(|x| x.container_len()).sum::<usize>(),
            hpu_big_lwe_ciphertext_size(&params),
            "The provided container length is not valid. \
        It needs to match with parameters. \
        Got container length: {} and based on parameters value expect: {}.",
            container.iter().map(|x| x.container_len()).sum::<usize>(),
            hpu_big_lwe_ciphertext_size(&params),
        );
        Self {
            pc_data: container,
            params,
        }
    }

    /// Consume the entity and return its underlying container.
    ///
    /// See [`HpuLweCiphertext::from_container`] for usage.
    pub fn into_container(self) -> Vec<C> {
        self.pc_data
    }
}

impl<C: Container> HpuLweCiphertext<C> {
    /// Return the [`Parameters`] of the [`HpuLweCiphertext`].
    ///
    /// See [`HpuLweCiphertext::from_container`] for usage.
    pub fn params(&self) -> &HpuParameters {
        &self.params
    }

    /// Return the length of the [`HpuLweCiphertext`] underlying containers.
    pub fn len(&self) -> usize {
        self.pc_data.iter().map(|c| c.container_len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        !self.pc_data.iter().any(|c| c.container_len() != 0)
    }

    /// Return a view of the [`HpuLweCiphertext`]. This is useful if an algorithm takes a view by
    /// value.
    pub fn as_view(&self) -> HpuLweCiphertext<&'_ [C::Element]> {
        HpuLweCiphertext {
            pc_data: self.pc_data.iter().map(|x| x.as_ref()).collect::<Vec<_>>(),
            params: self.params.clone(),
        }
    }
}

impl<C: ContainerMut> HpuLweCiphertext<C> {
    /// Mutable variant of [`HpuLweCiphertext::as_view`].
    pub fn as_mut_view(&mut self) -> HpuLweCiphertext<&'_ mut [C::Element]> {
        HpuLweCiphertext {
            pc_data: self
                .pc_data
                .iter_mut()
                .map(|x| x.as_mut())
                .collect::<Vec<_>>(),
            params: self.params.clone(),
        }
    }
}

/// A [`HpuLweCiphertext`] owning the memory for its own storage.
pub type HpuLweCiphertextOwned<Scalar> = HpuLweCiphertext<Vec<Scalar>>;
/// A [`HpuLweCiphertext`] immutably borrowing memory for its own storage.
pub type HpuLweCiphertextView<'data, Scalar> = HpuLweCiphertext<&'data [Scalar]>;
/// A [`HpuLweCiphertext`] mutably borrowing memory for its own storage.
pub type HpuLweCiphertextMutView<'data, Scalar> = HpuLweCiphertext<&'data mut [Scalar]>;

impl<Scalar: std::clone::Clone> HpuLweCiphertextOwned<Scalar> {
    /// Allocate memory and create a new owned [`HpuLweCiphertext`].
    ///
    /// # Note
    ///
    /// This function allocates a vector of the appropriate size and wraps it in the appropriate
    /// type.
    ///
    /// See [`HpuLweCiphertext::from_container`] for usage.
    pub fn new(fill_with: Scalar, params: HpuParameters) -> Self {
        // Mask is equally split in pc chunks.
        // Body is then added to first chunk
        let chunk_size = hpu_big_lwe_ciphertext_size(&params).div_euclid(params.pc_params.pem_pc);
        let pc_data = (0..params.pc_params.pem_pc)
            .map(|id| {
                if (id == 0) && (params.pc_params.pem_pc != 1) {
                    vec![fill_with.clone(); chunk_size + 1]
                } else {
                    vec![fill_with.clone(); chunk_size]
                }
            })
            .collect::<Vec<_>>();
        Self::from_container(pc_data, params)
    }
}
