//! Module containing the definition of the HpuLweCiphertext conversion traits.
//!
//! NB: LweCiphertext need to be:
//!   * Sent to Hw -> Conversion from Cpu world to Hpu World
//!   * Retrieved from Hw -> Conversion from Hpu world to Cpu World

use tfhe_hpu_backend::prelude::*;

use super::algorithms::{modswitch, order};
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

impl<Scalar: UnsignedInteger> CreateFrom<LweCiphertextView<'_, Scalar>>
    for HpuLweCiphertextOwned<Scalar>
{
    type Metadata = HpuParameters;
    fn create_from(cpu_lwe: LweCiphertextView<'_, Scalar>, meta: Self::Metadata) -> Self {
        let mut hpu_lwe = Self::new(Scalar::ZERO, meta.clone());
        let ntt_p = &meta.ntt_params;
        let pbs_p = &meta.pbs_params;
        let poly_size = pbs_p.polynomial_size;

        // NB: lwe mask is view as polynomial and must be in reversed order
        // Allocate translation buffer and reversed vector here
        let rb_conv = order::RadixBasis::new(ntt_p.radix, ntt_p.stg_nb);
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
                    let src_poly_idx = rb_conv.idx_rev(idx);
                    hpu_lwe[dst_idx] = modswitch::msb2lsb(&meta, poly[src_poly_idx]);
                }
            });
        // Add body
        hpu_lwe[lwe_len - 1] = modswitch::msb2lsb(&meta, *cpu_lwe.get_body().data);

        hpu_lwe
    }
}

#[allow(clippy::fallible_impl_from)]
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
        let rb_conv = order::RadixBasis::new(ntt_p.radix, ntt_p.stg_nb);
        let lwe_len = hpu_lwe.len();
        // Copy lwe mask in reverse order and update alignment
        cpu_lwe
            .get_mut_mask()
            .as_mut()
            .chunks_mut(poly_size)
            .enumerate()
            .for_each(|(pid, poly)| {
                for (idx, coeff) in poly.iter_mut().enumerate().take(poly_size) {
                    let src_poly_idx = rb_conv.idx_rev(idx);
                    let src_idx = pid * poly_size + src_poly_idx;
                    *coeff = modswitch::lsb2msb(hpu_lwe.params(), hpu_lwe[src_idx]);
                }
            });
        // Add body
        *cpu_lwe.get_mut_body().data = modswitch::lsb2msb(hpu_lwe.params(), hpu_lwe[lwe_len - 1]);

        cpu_lwe
    }
}
