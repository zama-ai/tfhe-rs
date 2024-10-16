//! Module containing the definition of the HpuLweBootstrapKey.
//! Raw typed container without any logic
//! Conversion from/into tfhers entities should be implemented inside tfhers to prevent dependency
//! loop

use super::parameters::*;
use super::traits::container::*;

/// A [`Hpu lwe bootstraping key`](`HpuLweBootstrapKey`).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HpuLweBootstrapKey<C: Container> {
    data: C,
    params: HpuParameters,
}

impl<C: Container> AsRef<[C::Element]> for HpuLweBootstrapKey<C> {
    fn as_ref(&self) -> &[C::Element] {
        self.data.as_ref()
    }
}

impl<C: ContainerMut> AsMut<[C::Element]> for HpuLweBootstrapKey<C> {
    fn as_mut(&mut self) -> &mut [C::Element] {
        self.data.as_mut()
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
    pub fn from_container(container: C, params: HpuParameters) -> Self {
        assert!(
            container.container_len() > 0,
            "Got an empty container to create a HpuLweBootstrapKey"
        );
        assert!(
            container.container_len() == hpu_lwe_bootstrap_key_size(&params),
            "The provided container length is not valid. \
        It needs to match with parameters. \
        Got container length: {} and based on parameters value expect: {}.",
            container.container_len(),
            hpu_lwe_bootstrap_key_size(&params)
        );
        Self {
            data: container,
            params,
        }
    }

    /// Consume the entity and return its underlying container.
    ///
    /// See [`HpuLweBootstrapKey::from_container`] for usage.
    pub fn into_container(self) -> C {
        self.data
    }
}

impl<C: Container> HpuLweBootstrapKey<C> {
    /// Return the [`Parameters`] of the [`HpuLweBootstrapKey`].
    ///
    /// See [`HpuLweBootstrapKey::from_container`] for usage.
    pub fn params(&self) -> &HpuParameters {
        &self.params
    }

    /// Return a view of the [`HpuLweBootstrapKey`]. This is useful if an algorithm takes a view by
    /// value.
    pub fn as_view(&self) -> HpuLweBootstrapKey<&'_ [C::Element]> {
        HpuLweBootstrapKey {
            data: self.data.as_ref(),
            params: self.params.clone(),
        }
    }
}

impl<C: ContainerMut> HpuLweBootstrapKey<C> {
    /// Mutable variant of [`HpuLweBootstrapKey::as_view`].
    pub fn as_mut_view(&mut self) -> HpuLweBootstrapKey<&'_ mut [C::Element]> {
        HpuLweBootstrapKey {
            data: self.data.as_mut(),
            params: self.params.clone(),
        }
    }
}

impl<T: std::clone::Clone, C: Container<Element = T>> HpuLweBootstrapKey<C> {
    /// Slice key stream in interleaved chunks for each memory cut
    pub fn hw_slice(&self) -> Vec<Vec<C::Element>> {
        let ntt_p = &self.params.ntt_params;
        let nb_pc = self.params.pc_params.bsk_pc;

        debug_assert_eq!(
            (ntt_p.radix * ntt_p.psi) % nb_pc,
            0,
            "Error: Incompatible (R*PSI: {}, BSK_PC: {})",
            ntt_p.radix * ntt_p.psi,
            nb_pc
        );

        let mut bsk_slice = vec![Vec::new(); nb_pc];
        for (i, chunk) in self
            .as_ref()
            .into_chunks((ntt_p.radix * ntt_p.psi) / nb_pc)
            .enumerate()
        {
            let cut_idx = i % nb_pc;

            // Copy in targeted stream_cut
            for c in chunk.iter() {
                bsk_slice[cut_idx].push(c.clone());
            }
        }
        bsk_slice
    }
}

impl<T: std::clone::Clone, C: ContainerMut<Element = T>> HpuLweBootstrapKey<C> {
    /// Filled HpuLweBootstrapKey from hw_slice view
    pub fn copy_from_hw_slice(&mut self, hw_slice: &[&[T]]) {
        // TODO -> Implement the correct copy procedure

        //     // Infer params from args
        //     let regf_p = &self.params.regf_params;
        //     let nb_pc = self.params.pc_params.bsk_pc;

        //     // View hw_slice as a mutable array of iterator
        //     // That will be consumed by sequence of coef_nb/nb_pc
        //     let mut slice_it = hw_slice.iter().map(|x| x.iter()).collect::<Vec<_>>();

        //     // Stop on first chunk that mismatch the required size
        //     // TODO try to rewrite in a efficient manner ?!
        //     let mut stop = false;
        //     let mut pos = 0;
        //     while !stop {
        //         for it in slice_it.iter_mut() {
        //             let chunk = (0..(regf_p.coef_nb / nb_pc))
        //                 .map(|_| it.next())
        //                 .filter(|x| x.is_some())
        //                 .map(|x| x.unwrap())
        //                 .collect::<Vec<_>>();

        //             if chunk.len() == (regf_p.coef_nb / nb_pc) {
        //                 chunk.iter().for_each(|v| {
        //                     self.data.as_mut()[pos] = (*v).clone();
        //                     pos += 1;
        //                 });
        //             } else {
        //                 stop = true;
        //                 break;
        //             }
        //         }
        //     }

        //     // copy body
        //     self.data.as_mut()[pos] = hw_slice[0].last().unwrap().clone();
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
        Self::from_container(vec![fill_with; hpu_lwe_bootstrap_key_size(&params)], params)
    }
}
