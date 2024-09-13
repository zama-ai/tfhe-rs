//! Module containing the definition of the HpuGlweCiphertext.

use tfhe_hpu_backend::prelude::*;

use super::algorithms::{modswitch, order};
use super::FromWith;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

impl FromWith<LweBootstrapKey<&[u64]>, HpuParameters> for HpuLweBootstrapKeyOwned<u64> {
    fn from_with(cpu_bsk: LweBootstrapKey<&[u64]>, params: HpuParameters) -> Self {
        let mut hpu_bsk = Self::new(0_u64, params.clone());

        // Extract params inner values for ease of writting
        let ntt_p = &params.ntt_params;
        let pbs_p = &params.pbs_params;
        let glwe_n = pbs_p.polynomial_size;
        let glwe_kp1 = pbs_p.glwe_dimension + 1;
        let pbs_l = pbs_p.pbs_level;

        // Convert in Ntt domain
        let ntt_engine = concrete_ntt::prime64::Plan::try_new(glwe_n, ntt_p.prime_modulus)
            .expect("Check polynomial size and associated ntt prime");

        // NB: Plan output polynomial in bit reverse order in Ntt domain
        // Hw expect ntt in reverse order.
        // We currently use keep value as is but this must be modified when
        // arch radix != 2
        assert_eq!(
            2, ntt_p.radix,
            "Error: With radix !=2 bsk must be converted from bit-reverse in radix-reverse order"
        );

        let ntt_bsk = {
            let mut bsk = LweBootstrapKeyOwned::new(
                0_u64,
                cpu_bsk.glwe_size(),
                cpu_bsk.polynomial_size(),
                cpu_bsk.decomposition_base_log(),
                cpu_bsk.decomposition_level_count(),
                cpu_bsk.input_lwe_dimension(),
                cpu_bsk.ciphertext_modulus(),
            );

            std::iter::zip(
                bsk.as_mut_polynomial_list().iter_mut(),
                cpu_bsk.as_polynomial_list().iter(),
            )
            .for_each(|(mut ntt, cpu)| {
                ntt.as_mut().clone_from_slice(cpu.as_ref());
                modswitch::msb2lsb_align(&params, ntt.as_mut());
                modswitch::user2ntt_modswitch(&params, ntt.as_mut());
                ntt_engine.fwd(ntt.as_mut());
            });
            bsk
        };

        // Instanciate Ntt network
        let mut ntw = order::Network::new(order::NetworkKind::Pcg, ntt_p.radix, ntt_p.stg_nb);

        let mut wr_idx = 0;
        for ggsw in ntt_bsk.iter() {
            // Arch dependant iterations
            for glwe_idx in 0..glwe_kp1 {
                for stg_iter in 0..ntt_p.stg_iter(glwe_n) {
                    for g_idx in 0..glwe_kp1 {
                        for l_idx in (0..pbs_l).rev() {
                            let p_view = GgswIndex {
                                s_dim: g_idx,
                                lvl_dim: l_idx,
                                glwe_dim: glwe_idx,
                            }
                            .poly_view(&ggsw);

                            for p in 0..ntt_p.psi {
                                for r in 0..ntt_p.radix {
                                    let c_idx =
                                        stg_iter * ntt_p.psi * ntt_p.radix + ntt_p.radix * p + r;
                                    let c_id = ntw.get_pos_id(ntt_p.ls_delta(), c_idx);
                                    hpu_bsk.as_mut()[wr_idx] = p_view[c_id];
                                    wr_idx += 1;
                                }
                            }
                        }
                    }
                }
            }
        }
        hpu_bsk
    }
}

/// Uploading BSK on HW required custom polynomial interleaving.
/// The following structure enable OutOfOrder access of GGSW polynomial to ease
/// the interleaving description
pub struct GgswIndex {
    pub s_dim: usize,
    pub lvl_dim: usize,
    pub glwe_dim: usize,
}

impl GgswIndex {
    /// Ease out of order iteration over a Ggsw ciphertext.
    /// This is usefull for Bootstrapping key shuffling to match expected HW
    /// order
    pub fn poly_view<'a, Scalar: UnsignedInteger>(
        self,
        ggsw: &'a GgswCiphertextView<Scalar>,
    ) -> &'a [Scalar] {
        let decomp_level = ggsw.decomposition_level_count().0;
        let row_cnt = ggsw.glwe_size().0;
        let poly_cnt = ggsw.glwe_size().0;

        ggsw.as_ref()
            .split_into(decomp_level)
            .nth(self.lvl_dim)
            .unwrap()
            .split_into(row_cnt)
            .nth(self.s_dim)
            .unwrap()
            .split_into(poly_cnt)
            .nth(self.glwe_dim)
            .unwrap()
    }
}
