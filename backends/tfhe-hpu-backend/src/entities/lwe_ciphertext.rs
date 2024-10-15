//! Module containing the definition of the HpuLweCiphertext.
//! Raw typed container without any logic
//! Conversion from/into tfhers entities should be implemented inside tfhers to prevent dependency
//! loop

use super::parameters::*;
use super::traits::container::*;

/// A [`Hpu LWE ciphertext`](`HpuLweCiphertext`).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HpuLweCiphertext<C: Container> {
    data: C,
    params: HpuParameters,
}

impl<C: Container> AsRef<[C::Element]> for HpuLweCiphertext<C> {
    fn as_ref(&self) -> &[C::Element] {
        self.data.as_ref()
    }
}

impl<C: ContainerMut> AsMut<[C::Element]> for HpuLweCiphertext<C> {
    fn as_mut(&mut self) -> &mut [C::Element] {
        self.data.as_mut()
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
    pub fn from_container(container: C, params: HpuParameters) -> Self {
        assert!(
            container.container_len() > 0,
            "Got an empty container to create a HpuLweCiphertext"
        );
        assert!(
            container.container_len() == hpu_big_lwe_ciphertext_size(&params),
            "The provided container length is not valid. \
        It needs to match with parameters. \
        Got container length: {} and based on parameters value expect: {}.",
            container.container_len(),
            hpu_big_lwe_ciphertext_size(&params),
        );
        Self {
            data: container,
            params,
        }
    }

    /// Consume the entity and return its underlying container.
    ///
    /// See [`HpuLweCiphertext::from_container`] for usage.
    pub fn into_container(self) -> C {
        self.data
    }
}

impl<C: Container> HpuLweCiphertext<C> {
    /// Return the [`Parameters`] of the [`HpuLweCiphertext`].
    ///
    /// See [`HpuLweCiphertext::from_container`] for usage.
    pub fn params(&self) -> &HpuParameters {
        &self.params
    }

    /// Return a view of the [`HpuLweCiphertext`]. This is useful if an algorithm takes a view by
    /// value.
    pub fn as_view(&self) -> HpuLweCiphertext<&'_ [C::Element]> {
        HpuLweCiphertext {
            data: self.data.as_ref(),
            params: self.params.clone(),
        }
    }
}

impl<C: ContainerMut> HpuLweCiphertext<C> {
    /// Mutable variant of [`HpuLweCiphertext::as_view`].
    pub fn as_mut_view(&mut self) -> HpuLweCiphertext<&'_ mut [C::Element]> {
        HpuLweCiphertext {
            data: self.data.as_mut(),
            params: self.params.clone(),
        }
    }
}

impl<T: std::clone::Clone, C: Container<Element = T>> HpuLweCiphertext<C> {
    /// Slice lwe stream in interleaved chunks for each memory cut
    pub fn hw_slice(&self) -> Vec<Vec<T>> {
        let regf_p = &self.params.regf_params;
        let nb_pc = self.params.pc_params.pem_pc;

        let mut lwe_slice = vec![Vec::new(); nb_pc];
        for (i, chunk) in self
            .data
            .as_ref()
            .chunks(regf_p.coef_nb / nb_pc)
            .enumerate()
        {
            let cut_idx = i % nb_pc;

            // Copy in targeted stream_cut
            for c in chunk.iter() {
                lwe_slice[cut_idx].push(c.clone());
            }
        }
        lwe_slice
    }
}

impl<T: std::clone::Clone, C: ContainerMut<Element = T>> HpuLweCiphertext<C> {
    /// Filled HpuLweCiphertext from hw_slice view
    pub fn copy_from_hw_slice(&mut self, hw_slice: &[&[T]]) {
        // Infer params from args
        let regf_p = &self.params.regf_params;
        let nb_pc = self.params.pc_params.pem_pc;

        match nb_pc {
            1 => {
                self.data.as_mut().clone_from_slice(hw_slice[0]);
            }
            2 => {
                let mut pos = 0;
                println!(
                    "s[0] -> {}, s[1] -> {}, d -> {}",
                    hw_slice[0].len(),
                    hw_slice[1].len(),
                    self.data.as_ref().len(),
                );
                std::iter::zip(
                    hw_slice[0].chunks_exact(regf_p.coef_nb / nb_pc),
                    hw_slice[1].chunks_exact(regf_p.coef_nb / nb_pc),
                )
                .for_each(|(chunk_a, chunk_b)| {
                    for a in chunk_a {
                        self.data.as_mut()[pos] = a.clone();
                        pos += 1;
                    }
                    for b in chunk_b {
                        self.data.as_mut()[pos] = b.clone();
                        pos += 1;
                    }
                });
                // copy body
                self.data.as_mut()[pos] = hw_slice[0].last().unwrap().clone();
            }
            _ => panic!("Current implementation only work with up to two slices"),
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
    /// type. If you want to encrypt data you need to use
    /// [`crate::core_crypto::algorithms::encrypt_lwe_ciphertext`] using this ciphertext as
    /// output.
    ///
    ///
    /// See [`HpuLweCiphertext::from_container`] for usage.
    pub fn new(fill_with: Scalar, params: HpuParameters) -> Self {
        Self::from_container(
            vec![fill_with; hpu_big_lwe_ciphertext_size(&params)],
            params,
        )
    }
}
