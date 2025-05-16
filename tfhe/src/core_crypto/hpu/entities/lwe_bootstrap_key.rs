//! Module containing the definition of the HpuGlweCiphertext.

use tfhe_hpu_backend::prelude::*;

use super::algorithms::order;
use crate::core_crypto::prelude::*;

impl CreateFrom<LweBootstrapKey<&[u64]>> for HpuLweBootstrapKeyOwned<u64> {
    type Metadata = HpuParameters;
    fn create_from(cpu_bsk: LweBootstrapKey<&[u64]>, meta: Self::Metadata) -> Self {
        // Convert the LweBootstrapKey in Ntt domain
        let mut ntt_bsk = NttLweBootstrapKeyOwned::<u64>::new(
            0_u64,
            cpu_bsk.input_lwe_dimension(),
            cpu_bsk.glwe_size(),
            cpu_bsk.polynomial_size(),
            cpu_bsk.decomposition_base_log(),
            cpu_bsk.decomposition_level_count(),
            CiphertextModulus::new(u64::from(&meta.ntt_params.prime_modulus) as u128),
        );

        // Conversion to ntt domain
        par_convert_standard_lwe_bootstrap_key_to_ntt64(
            &cpu_bsk,
            &mut ntt_bsk,
            NttLweBootstrapKeyOption::Raw,
        );

        Self::create_from(ntt_bsk.as_view(), meta)
    }
}

/// Shuffle BSK for GF64 Ntt architecture
/// This architectures don't use an internal network, however, inputs polynomial was in a custom
/// order and not bit-reversed one
fn shuffle_gf64(
    ntt_bsk: &NttLweBootstrapKeyView<u64>,
    params: &HpuParameters,
    cut_w: &[u8],
) -> HpuLweBootstrapKeyOwned<u64> {
    let mut hpu_bsk = HpuLweBootstrapKeyOwned::<u64>::new(0_u64, params.clone());

    // Extract params inner values for ease of writing
    let ntt_p = &params.ntt_params;
    let pbs_p = &params.pbs_params;
    let glwe_n = pbs_p.polynomial_size;
    let glwe_kp1 = pbs_p.glwe_dimension + 1;
    let pbs_l = pbs_p.pbs_level;

    // Recursive function used to define the expected polynomial order
    fn bsk_order(cut_w: &[u8]) -> Vec<usize> {
        if cut_w.len() == 1 {
            (0..2_usize.pow(cut_w[0] as u32)).collect::<Vec<usize>>()
        } else {
            let coefs_left = 2_usize.pow(cut_w[0] as u32);
            let sub_order = bsk_order(&cut_w[1..]);

            (0..coefs_left)
                .flat_map(|j| {
                    sub_order
                        .iter()
                        .map(|idx| coefs_left * idx + j)
                        .collect::<Vec<usize>>()
                })
                .collect::<Vec<usize>>()
        }
    }

    // Compute Gf64 polynomial order based on cut_w
    let mut gf64_order = bsk_order(cut_w);
    //  gf64_idx must be expressed in bitreverse (to compensate the fact that ntt output is in
    // bitreverse
    let rb_conv = order::RadixBasis::new(2, cut_w.iter().sum::<u8>() as usize);
    for x in gf64_order.iter_mut() {
        *x = rb_conv.idx_rev(*x);
    }

    let mut wr_idx = 0;
    for ggsw in ntt_bsk.as_view().into_ggsw_iter() {
        // Arch dependant iterations
        for glwe_idx in 0..glwe_kp1 {
            for stg_iter in 0..ntt_p.stg_iter(glwe_n) {
                for g_idx in 0..glwe_kp1 {
                    for l_idx in 0..pbs_l {
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
                                hpu_bsk[wr_idx] = p_view[gf64_order[c_idx]];
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

/// UnShuffle BSK for GF64 Ntt architecture
fn unshuffle_gf64(
    hpu_bsk: &HpuLweBootstrapKeyView<u64>,
    cut_w: &[u8],
) -> NttLweBootstrapKeyOwned<u64> {
    // Extract params inner values for ease of writing
    let params = hpu_bsk.params();
    let ntt_p = &params.ntt_params;
    let pbs_p = &params.pbs_params;
    let glwe_n = pbs_p.polynomial_size;
    let glwe_kp1 = pbs_p.glwe_dimension + 1;
    let pbs_l = pbs_p.pbs_level;

    let mut ntt_bsk = NttLweBootstrapKeyOwned::new(
        0,
        LweDimension(pbs_p.lwe_dimension),
        GlweDimension(pbs_p.glwe_dimension).to_glwe_size(),
        PolynomialSize(pbs_p.polynomial_size),
        DecompositionBaseLog(pbs_p.pbs_base_log),
        DecompositionLevelCount(pbs_p.pbs_level),
        CiphertextModulus::new(u64::from(&hpu_bsk.params().ntt_params.prime_modulus) as u128),
    );

    // Recursive function used to define the expected polynomial order
    fn bsk_order(cut_w: &[u8]) -> Vec<usize> {
        if cut_w.len() == 1 {
            (0..2_usize.pow(cut_w[0] as u32)).collect::<Vec<usize>>()
        } else {
            let coefs_left = 2_usize.pow(cut_w[0] as u32);
            let sub_order = bsk_order(&cut_w[1..]);

            (0..coefs_left)
                .flat_map(|j| {
                    sub_order
                        .iter()
                        .map(|idx| coefs_left * idx + j)
                        .collect::<Vec<usize>>()
                })
                .collect::<Vec<usize>>()
        }
    }

    // Compute Gf64 polynomial order based on cut_w
    let mut gf64_order = bsk_order(cut_w);
    //  gf64_idx must be expressed in bitreverse (to compensate the fact that ntt output is in
    // bitreverse
    let rb_conv = order::RadixBasis::new(2, cut_w.iter().sum::<u8>() as usize);
    for x in gf64_order.iter_mut() {
        *x = rb_conv.idx_rev(*x);
    }

    let mut rd_idx = 0;
    for mut ggsw in ntt_bsk.as_mut_view().into_ggsw_iter() {
        // Arch dependant iterations
        for glwe_idx in 0..glwe_kp1 {
            for stg_iter in 0..ntt_p.stg_iter(glwe_n) {
                for g_idx in 0..glwe_kp1 {
                    for l_idx in 0..pbs_l {
                        let p_view = GgswIndex {
                            s_dim: g_idx,
                            lvl_dim: l_idx,
                            glwe_dim: glwe_idx,
                        }
                        .poly_mut_view(&mut ggsw);

                        for p in 0..ntt_p.psi {
                            for r in 0..ntt_p.radix {
                                let c_idx =
                                    stg_iter * ntt_p.psi * ntt_p.radix + ntt_p.radix * p + r;
                                p_view[gf64_order[c_idx]] = hpu_bsk[rd_idx];
                                rd_idx += 1;
                            }
                        }
                    }
                }
            }
        }
    }

    ntt_bsk
}

/// Shuffle BSK for Wmm Ntt architecture
/// These architectures used a network internally
/// With those architecture, the structural order and the iteration order differe and required a
/// custom Bsk layout
fn shuffle_wmm(
    ntt_bsk: &NttLweBootstrapKeyView<u64>,
    params: &HpuParameters,
) -> HpuLweBootstrapKeyOwned<u64> {
    let mut hpu_bsk = HpuLweBootstrapKeyOwned::<u64>::new(0_u64, params.clone());

    // Extract params inner values for ease of writing
    let ntt_p = &params.ntt_params;
    let pbs_p = &params.pbs_params;
    let glwe_n = pbs_p.polynomial_size;
    let glwe_kp1 = pbs_p.glwe_dimension + 1;
    let pbs_l = pbs_p.pbs_level;

    // NB: Ntt output polynomial in bit reverse order in Ntt domain
    // Hw expect ntt in reverse order.
    // We currently use keep value as is but this must be modified when
    // arch radix != 2
    assert_eq!(
        2, ntt_p.radix,
        "Error: With radix !=2 bsk must be converted from bit-reverse in radix-reverse order"
    );

    // Instantiate Ntt network
    let mut ntw = order::PcgNetwork::new(ntt_p.radix, ntt_p.stg_nb);

    let mut wr_idx = 0;
    for ggsw in ntt_bsk.as_view().into_ggsw_iter() {
        // Arch dependant iterations
        for glwe_idx in 0..glwe_kp1 {
            for stg_iter in 0..ntt_p.stg_iter(glwe_n) {
                for g_idx in 0..glwe_kp1 {
                    for l_idx in 0..pbs_l {
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
                                hpu_bsk[wr_idx] = p_view[c_id];
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

/// UnShuffle BSK for Wmm Ntt architecture
fn unshuffle_wmm(hpu_bsk: &HpuLweBootstrapKeyView<u64>) -> NttLweBootstrapKeyOwned<u64> {
    // Extract params inner values for ease of writing
    let params = hpu_bsk.params();
    let ntt_p = &params.ntt_params;
    let pbs_p = &params.pbs_params;
    let glwe_n = pbs_p.polynomial_size;
    let glwe_kp1 = pbs_p.glwe_dimension + 1;
    let pbs_l = pbs_p.pbs_level;

    let mut ntt_bsk = NttLweBootstrapKeyOwned::new(
        0,
        LweDimension(pbs_p.lwe_dimension),
        GlweDimension(pbs_p.glwe_dimension).to_glwe_size(),
        PolynomialSize(pbs_p.polynomial_size),
        DecompositionBaseLog(pbs_p.pbs_base_log),
        DecompositionLevelCount(pbs_p.pbs_level),
        CiphertextModulus::new(u64::from(&hpu_bsk.params().ntt_params.prime_modulus) as u128),
    );

    // Instantiate Ntt network
    let mut ntw = order::PcgNetwork::new(ntt_p.radix, ntt_p.stg_nb);

    let mut rd_idx = 0;
    for mut ggsw in ntt_bsk.as_mut_view().into_ggsw_iter() {
        // Arch dependant iterations
        for glwe_idx in 0..glwe_kp1 {
            for stg_iter in 0..ntt_p.stg_iter(glwe_n) {
                for g_idx in 0..glwe_kp1 {
                    for l_idx in 0..pbs_l {
                        let p_view = GgswIndex {
                            s_dim: g_idx,
                            lvl_dim: l_idx,
                            glwe_dim: glwe_idx,
                        }
                        .poly_mut_view(&mut ggsw);

                        for p in 0..ntt_p.psi {
                            for r in 0..ntt_p.radix {
                                let c_idx =
                                    stg_iter * ntt_p.psi * ntt_p.radix + ntt_p.radix * p + r;
                                let c_id = ntw.get_pos_id(ntt_p.ls_delta(), c_idx);
                                p_view[c_id] = hpu_bsk[rd_idx];
                                rd_idx += 1;
                            }
                        }
                    }
                }
            }
        }
    }
    ntt_bsk
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
    /// This is useful for Bootstrapping key shuffling to match expected HW
    /// order
    pub fn poly_view<'a, Scalar: UnsignedInteger>(
        self,
        ggsw: &'a NttGgswCiphertextView<Scalar>,
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

    /// Ease out of order iteration over a mutable Ggsw ciphertext.
    /// This is useful for Bootstrapping key shuffling to match expected HW
    /// order
    pub fn poly_mut_view<'a, Scalar: UnsignedInteger>(
        self,
        ggsw: &'a mut NttGgswCiphertextMutView<Scalar>,
    ) -> &'a mut [Scalar] {
        let decomp_level = ggsw.decomposition_level_count().0;
        let row_cnt = ggsw.glwe_size().0;
        let poly_cnt = ggsw.glwe_size().0;

        ggsw.as_mut()
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

impl<'a> CreateFrom<NttLweBootstrapKeyView<'a, u64>> for HpuLweBootstrapKeyOwned<u64> {
    type Metadata = HpuParameters;
    fn create_from(cpu_bsk: NttLweBootstrapKeyView<'a, u64>, meta: Self::Metadata) -> Self {
        match meta.ntt_params.core_arch.clone() {
            // Shuffle required by GF64 Ntt without internal network
            HpuNttCoreArch::GF64(cut_w) => shuffle_gf64(&cpu_bsk, &meta, &cut_w),
            // Legacy shuffle required by WmmNtt with internal network
            HpuNttCoreArch::WmmCompactPcg | HpuNttCoreArch::WmmUnfoldPcg => {
                shuffle_wmm(&cpu_bsk, &meta)
            }
        }
    }
}

impl<'a> From<HpuLweBootstrapKeyView<'a, u64>> for NttLweBootstrapKeyOwned<u64> {
    fn from(hpu_bsk: HpuLweBootstrapKeyView<'a, u64>) -> Self {
        match hpu_bsk.params().ntt_params.core_arch.clone() {
            // Shuffle required by GF64 Ntt without internal network
            HpuNttCoreArch::GF64(cut_w) => unshuffle_gf64(&hpu_bsk, &cut_w),
            // Legacy shuffle required by WmmNtt with internal network
            HpuNttCoreArch::WmmCompactPcg | HpuNttCoreArch::WmmUnfoldPcg => unshuffle_wmm(&hpu_bsk),
        }
    }
}
