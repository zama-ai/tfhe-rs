//! Module containing the definition of the HpuLweCiphertext conversion traits.
//!
//! NB: LweCiphertext need to be:
//!   * Sent to Hw -> Conversion from Cpu world to Hpu World
//!   * Retrieved from Hw -> Conversion from Hpu world to Cpu World

use tfhe_hpu_backend::prelude::*;

use super::algorithms::{modswitch, order};
use super::FromWith;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

impl<Scalar: UnsignedInteger> FromWith<LweCiphertextView<'_, Scalar>, HpuParameters>
    for HpuLweCiphertextOwned<Scalar>
{
    fn from_with(cpu_lwe: LweCiphertextView<'_, Scalar>, params: HpuParameters) -> Self {
        let mut hpu_lwe = Self::new(Scalar::ZERO, params.clone());
        let ntt_p = &params.ntt_params;
        let pbs_p = &params.pbs_params;
        let poly_size = pbs_p.polynomial_size;

        // NB: Glwe polynomial must be in reversed order
        // Allocate translation buffer and reversed vector here
        let mut rb_conv = order::RadixBasis::new(ntt_p.radix, ntt_p.stg_nb);
        let lwe_len = hpu_lwe.len();
        // Copy lwe mask in reverse order and update alignment
        cpu_lwe
            .get_mask()
            .as_ref()
            .chunks(poly_size)
            .enumerate()
            .for_each(|(pid, poly)| {
                for idx in 0..poly_size {
                    let dst_idx = pid * poly_size + idx;
                    let src_poly_idx =
                        order::idx_in_order(idx, order::PolyOrder::Reverse, &mut rb_conv);
                    hpu_lwe[dst_idx] = modswitch::msb2lsb(&params, poly[src_poly_idx]);
                }
            });
        // Add body
        hpu_lwe[lwe_len - 1] = modswitch::msb2lsb(&params, *cpu_lwe.get_body().data);

        hpu_lwe
    }
}

impl<Scalar: UnsignedInteger> From<HpuLweCiphertextView<'_, Scalar>>
    for LweCiphertextOwned<Scalar>
{
    fn from(hpu_lwe: HpuLweCiphertextView<'_, Scalar>) -> Self {
        // NB: HPU only handle Big Lwe over it's boundaries
        let ntt_p = &hpu_lwe.params().ntt_params;
        let pbs_p = &hpu_lwe.params().pbs_params;
        let poly_size = pbs_p.polynomial_size;

        let mut cpu_lwe = Self::new(
            Scalar::ZERO,
            LweSize(hpu_lwe.len()),
            CiphertextModulus::try_new_power_of_2(pbs_p.ciphertext_width).unwrap(),
        );

        // Reverse Glwe back to natural order
        // Allocate translation buffer and reversed vector here
        let mut rb_conv = order::RadixBasis::new(ntt_p.radix, ntt_p.stg_nb);
        let lwe_len = hpu_lwe.len();
        // Copy lwe mask in reverse order and update alignment
        cpu_lwe
            .get_mut_mask()
            .as_mut()
            .chunks_mut(poly_size)
            .enumerate()
            .for_each(|(pid, poly)| {
                for idx in 0..poly_size {
                    let src_poly_idx =
                        order::idx_in_order(idx, order::PolyOrder::Reverse, &mut rb_conv);
                    let src_idx = pid * poly_size + src_poly_idx;
                    poly[idx] = modswitch::lsb2msb(hpu_lwe.params(), hpu_lwe[src_idx]);
                }
            });
        // Add body
        *cpu_lwe.get_mut_body().data = modswitch::lsb2msb(hpu_lwe.params(), hpu_lwe[lwe_len - 1]);

        cpu_lwe
    }
}
