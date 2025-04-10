//! Module containing the definition of the HpuGlweCiphertext.

use tfhe_hpu_backend::prelude::*;

use super::algorithms::order;
use super::FromWith;
use crate::core_crypto::prelude::*;

impl<Scalar> FromWith<LweKeyswitchKeyView<'_, Scalar>, HpuParameters>
    for HpuLweKeyswitchKeyOwned<u64>
where
    Scalar: UnsignedInteger + CastInto<u64>,
{
    fn from_with(cpu_ksk: LweKeyswitchKeyView<'_, Scalar>, params: HpuParameters) -> Self {
        let mut hpu_ksk = Self::new(0, params.clone());

        // Allocate radix_basis converter
        let mut rb_conv = order::RadixBasis::new(params.ntt_params.radix, params.ntt_params.stg_nb);

        // Extract params inner values for ease of writing
        let pbs_p = &params.pbs_params;
        let lwe_k = pbs_p.lwe_dimension;
        let glwe_k = pbs_p.glwe_dimension;
        let glwe_n = pbs_p.polynomial_size;
        let ks_p = &params.ks_params;

        // View KsK as a polyhedral with rectangles faces.
        // Front face is a rectangle of size (N*Glwe_k)x(Lwe_k + 1)
        // Depth is ksk_level
        //         --------------
        //  ksk   / /           /
        //  lvl  / /           / |
        //       --------------  |   Y   Z
        //      |s|lwe_k +1   |  |   |  /
        //glwe_k|l|           |  |   | /
        // * N  |i|           | /    |/ |c|           |/     / ------> X -e------------
        //
        // Ksk is sliced in one slot face over x.
        // This slice is then decomposed in rectancles lby*lbz.
        // These rectangle are iterated in natural order.
        // Within this rectangle lbZ coefs are merged in one 64b coefs
        // and iterated over y dim.
        // Furthermore it's possible that ksk polyhedron isn't a multiple of lbx/lby/lbz.
        // Incomplete rectangle are then extend with xx and iterate as usual

        let mut hw_idx = 0;
        for outer_x in (0..lwe_k + 1).step_by(ks_p.lbx) {
            for inner_x in 0..ks_p.lbx {
                // -> Iterate over Slices
                let raw_x = outer_x + inner_x;
                let abs_x = if raw_x < (lwe_k + 1) {
                    Some(raw_x)
                } else {
                    None
                };

                for outer_y in (0..(glwe_k * glwe_n)).step_by(ks_p.lby) {
                    for outer_z in (0..pbs_p.ks_level).step_by(ks_p.lbz) {
                        // -> Iterate over rectangles lby*lbz
                        for inner_y in 0..ks_p.lby {
                            let raw_y = outer_y + inner_y;
                            let abs_y = if raw_y < (glwe_k * glwe_n) {
                                // Hw-order expect y-dim to be in bitreverse
                                // Compute it inflight
                                // NB: raw_y represent the index over Y in [0; glwe_k*glwe_n] and
                                // the bitreverse must be only
                                // applied over glwe_n
                                // -> split raw_y in poly_y, coef_y and bitreverse only the coef_y
                                let poly_y = raw_y / glwe_n;
                                let coef_y = raw_y % glwe_n;
                                let brev_coef_y = rb_conv.idx_rev(coef_y);
                                let abs_y = poly_y * glwe_n + brev_coef_y;
                                Some(abs_y)
                            } else {
                                None
                            };

                            let pack_z: u64 = (0..ks_p.lbz).fold(0, |acc, inner_z| {
                                let raw_z = outer_z + inner_z;
                                let abs_z = if raw_z < pbs_p.ks_level {
                                    Some(raw_z)
                                } else {
                                    None
                                };
                                let cur_coef = match (abs_x, abs_y, abs_z) {
                                    (Some(x), Some(y), Some(z)) => {
                                        *KskIndex { x, y, z }.coef_view(&cpu_ksk)
                                    }
                                    _ => Scalar::ZERO, /* At least one dimension overflow
                                                        * -> return 0 */
                                };
                                // NB: Ksk modulus used within Hw could be different that the one
                                // used in Sw. In Sw, the
                                // information is kept in MSB, but Hw required them in LSB
                                // Handle rounding and bit alignment
                                let coef_rounded_ralign = {
                                    let coef_orig: u64 = cur_coef.cast_into();
                                    // Extract info bits and rounding if required
                                    let coef_info = coef_orig >> (u64::BITS - ks_p.width as u32);
                                    let coef_rounding = if (ks_p.width as u32) < u64::BITS {
                                        (coef_orig >> (u64::BITS - (ks_p.width + 1) as u32)) & 0x1
                                    } else {
                                        0
                                    };
                                    coef_info + coef_rounding
                                };
                                acc + (coef_rounded_ralign << (inner_z * ks_p.width))
                            });
                            hpu_ksk[hw_idx] = pack_z;
                            hw_idx += 1;
                        }
                    }
                }
            }
        }
        hpu_ksk
    }
}

/// Shuffling KSK in HW order required custom coefs interleaving.
/// The following structure enable OutOfOrder access of KSK coefs to ease
/// the interleaving description
/// Abstract tfhe-rs view from hw view (i.e polyhedron)
#[derive(Debug)]
struct KskIndex {
    pub x: usize,
    pub y: usize,
    pub z: usize,
}

impl KskIndex {
    /// Ease out of order iteration over a ksk coefs.
    fn coef_view<'a, Scalar: UnsignedInteger>(
        self,
        ksk: &'a LweKeyswitchKeyView<Scalar>,
    ) -> &'a Scalar {
        let decomp_level = ksk.decomposition_level_count().0;
        let in_lwe_elem = ksk.input_key_lwe_dimension().0;
        // NB: Decomposition is in reverse order in tfhe-rs (i.e MSB to LSB)
        // -> However, inversion is already handled during keyswitching key generation
        // Ksk coefs is order as follow (from outer dim to inner dim):
        //  * input_lwe_key_dim
        //  * decomp_lvl
        //  * out_lwe_key_size
        &ksk.as_ref()
            .split_into(in_lwe_elem)
            .nth(self.y)
            .unwrap()
            .split_into(decomp_level)
            .nth(self.z)
            .unwrap()[self.x]
    }

    /// Ease out of order mutable iteration over a ksk coefs.
    fn coef_mut_view<'a, Scalar: UnsignedInteger>(
        self,
        ksk: &'a mut LweKeyswitchKeyMutView<Scalar>,
    ) -> &'a mut Scalar {
        let decomp_level = ksk.decomposition_level_count().0;
        let in_lwe_elem = ksk.input_key_lwe_dimension().0;
        // NB: Decomposition is in reverse order in tfhe-rs (i.e MSB to LSB)
        // -> However, inversion is already handled during keyswitching key generation
        // Ksk coefs is order as follow (from outer dim to inner dim):
        //  * input_lwe_key_dim
        //  * decomp_lvl
        //  * out_lwe_key_size
        &mut ksk
            .as_mut()
            .split_into(in_lwe_elem)
            .nth(self.y)
            .unwrap()
            .split_into(decomp_level)
            .nth(self.z)
            .unwrap()[self.x]
    }
}

impl<'a, Scalar> From<HpuLweKeyswitchKeyView<'a, Scalar>> for LweKeyswitchKeyOwned<Scalar>
where
    Scalar: UnsignedInteger,
{
    fn from(hpu_ksk: HpuLweKeyswitchKeyView<'a, Scalar>) -> Self {
        let pbs_p = &hpu_ksk.params().pbs_params;

        let mut cpu_ksk = Self::new(
            Scalar::ZERO,
            DecompositionBaseLog(pbs_p.ks_base_log),
            DecompositionLevelCount(pbs_p.ks_level),
            LweDimension(pbs_p.glwe_dimension * pbs_p.polynomial_size),
            LweDimension(pbs_p.lwe_dimension),
            CiphertextModulus::new(1_u128 << pbs_p.ciphertext_width),
        );

        // Unshuffle Keyswitch key from Hw order to Cpu order

        // Allocate radix_basis converter
        let params = hpu_ksk.params();
        let mut rb_conv = order::RadixBasis::new(params.ntt_params.radix, params.ntt_params.stg_nb);

        // Extract params inner values for ease of writing
        let pbs_p = &params.pbs_params;
        let lwe_k = pbs_p.lwe_dimension;
        let glwe_k = pbs_p.glwe_dimension;
        let glwe_n = pbs_p.polynomial_size;
        let ks_p = &params.ks_params;

        // Revert transformation made in FromWith
        let mut hw_idx = 0;
        for outer_x in (0..lwe_k + 1).step_by(ks_p.lbx) {
            for inner_x in 0..ks_p.lbx {
                // -> Iterate over Slices
                let raw_x = outer_x + inner_x;
                let abs_x = if raw_x < (lwe_k + 1) {
                    Some(raw_x)
                } else {
                    None
                };

                for outer_y in (0..(glwe_k * glwe_n)).step_by(ks_p.lby) {
                    for outer_z in (0..pbs_p.ks_level).step_by(ks_p.lbz) {
                        // -> Iterate over rectangles lby*lbz
                        for inner_y in 0..ks_p.lby {
                            let raw_y = outer_y + inner_y;
                            let abs_y = if raw_y < (glwe_k * glwe_n) {
                                // Hw-order expect y-dim to be in bitreverse
                                // Compute it inflight
                                // NB: raw_y represent the index over Y in [0; glwe_k*glwe_n] and
                                // the bitreverse must be only
                                // applied over glwe_n
                                // -> split raw_y in poly_y, coef_y and bitreverse only the coef_y
                                let poly_y = raw_y / glwe_n;
                                let coef_y = raw_y % glwe_n;
                                let brev_coef_y = rb_conv.idx_rev(coef_y);
                                let abs_y = poly_y * glwe_n + brev_coef_y;
                                Some(abs_y)
                            } else {
                                None
                            };

                            // Unpack over Z dimension
                            (0..ks_p.lbz).for_each(|inner_z| {
                                let raw_z = outer_z + inner_z;
                                let abs_z = if raw_z < pbs_p.ks_level {
                                    Some(raw_z)
                                } else {
                                    None
                                };

                                if let (Some(x), Some(y), Some(z)) = (abs_x, abs_y, abs_z) {
                                    let mut cpu_ksk_view = cpu_ksk.as_mut_view();
                                    let cpu_coef =
                                        KskIndex { x, y, z }.coef_mut_view(&mut cpu_ksk_view);
                                    let hpu_val = (hpu_ksk[hw_idx] >> (inner_z * ks_p.width))
                                        & Scalar::cast_from((1 << ks_p.width) - 1);
                                    // Cpu expect value MSB Align
                                    *cpu_coef = hpu_val << (u64::BITS - ks_p.width as u32) as usize;
                                }
                                // Otherwise, at least one dimension overflow, it's padded with 0 in
                                // the Hw view => Skipped
                            });
                            hw_idx += 1;
                        }
                    }
                }
            }
        }
        cpu_ksk
    }
}
