//! Module containing the definition of the HpuLweCiphertext conversion traits.//!
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

        // NB: Glwe polynomial must be in reversed order
        // Allocate translation buffer and reversed vector here
        let mut rb_conv = order::RadixBasis::new(ntt_p.radix, ntt_p.stg_nb);
        let lwe_len = hpu_lwe.as_ref().len();
        // Put lwe mask in reverse order
        std::iter::zip(
            hpu_lwe.as_mut()[0..lwe_len - 1].chunks_mut(pbs_p.polynomial_size),
            cpu_lwe.get_mask().as_ref().chunks(pbs_p.polynomial_size),
        )
        .for_each(|(dst, src)| {
            order::poly_order(dst, src, order::PolyOrder::Reverse, &mut rb_conv, |x| x)
        });
        // Add body
        hpu_lwe.as_mut()[lwe_len - 1] = *cpu_lwe.get_body().data;
        // Align all coefs on lsb
        modswitch::msb2lsb_align(&params, hpu_lwe.as_mut());

        hpu_lwe
    }
}

impl<Scalar: UnsignedInteger> From<HpuLweCiphertextView<'_, Scalar>>
    for LweCiphertextOwned<Scalar>
{
    fn from(hpu_lwe: HpuLweCiphertextView<'_, Scalar>) -> Self {
        // NB: HPU only handle Big Lwe over it's boundaries
        let pbs_p = &hpu_lwe.params().pbs_params;

        let mut cpu_lwe = Self::new(
            Scalar::ZERO,
            LweSize(hpu_lwe.as_ref().len()),
            CiphertextModulus::try_new_power_of_2(pbs_p.ciphertext_width).unwrap(),
        );
        let ntt_p = hpu_lwe.params().ntt_params.clone();

        // Reverse Glwe back to natural order
        // Allocate translation buffer and reversed vector here
        let mut rb_conv = order::RadixBasis::new(ntt_p.radix, ntt_p.stg_nb);
        let lwe_len = hpu_lwe.as_ref().len();
        // Put lwe mask in reverse order
        std::iter::zip(
            cpu_lwe
                .get_mut_mask()
                .as_mut()
                .chunks_mut(ntt_p.radix.pow(ntt_p.stg_nb as u32)),
            hpu_lwe.as_ref()[0..lwe_len - 1].chunks(ntt_p.radix.pow(ntt_p.stg_nb as u32)),
        )
        .for_each(|(dst, src)| {
            order::poly_order(dst, src, order::PolyOrder::Reverse, &mut rb_conv, |x| x)
        });
        // Add body
        *cpu_lwe.get_mut_body().data = hpu_lwe.as_ref()[lwe_len - 1];
        // Align all coefs on lsb
        modswitch::lsb2msb_align(hpu_lwe.params(), cpu_lwe.as_mut());
        cpu_lwe
    }
}
