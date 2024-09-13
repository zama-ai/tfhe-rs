//! Module containing the definition of the HpuGlweCiphertext.

use hpu_asm::PbsLut;
use tfhe_hpu_backend::prelude::*;

use super::algorithms::{modswitch, order};
use super::{FromWith, IntoWith};
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::shortint::ClassicPBSParameters;

impl<Scalar: UnsignedInteger> FromWith<GlweCiphertextView<'_, Scalar>, HpuParameters>
    for HpuGlweLookuptableOwned<Scalar>
{
    fn from_with(cpu_glwe: GlweCiphertextView<'_, Scalar>, params: HpuParameters) -> Self {
        let mut hpu_lut = Self::new(Scalar::ZERO, params.clone());
        let ntt_p = &params.ntt_params;

        // NB: Glwe polynomial must be in reversed order
        let mut rb_conv = order::RadixBasis::new(ntt_p.radix, ntt_p.stg_nb);

        // Put glwe in reverse order and align on lsb
        // Only handle Body since Lut is encoded as trivial Glwe
        order::poly_order(
            hpu_lut.as_mut(),
            cpu_glwe.get_body().as_polynomial().into_container(),
            order::PolyOrder::Reverse,
            &mut rb_conv,
            |x| x,
        );
        modswitch::msb2lsb_align(&params, hpu_lut.as_mut());
        hpu_lut
    }
}

impl From<HpuGlweLookuptableView<'_, u64>> for GlweCiphertextOwned<u64> {
    fn from(hpu_lut: HpuGlweLookuptableView<'_, u64>) -> Self {
        let hpu_p = hpu_lut.params();
        let pbs_p = ClassicPBSParameters::from(hpu_p);

        let mut cpu_glwe = Self::new(
            0,
            pbs_p.glwe_dimension.to_glwe_size(),
            pbs_p.polynomial_size,
            pbs_p.ciphertext_modulus,
        );
        // NB: GlweLut polynomial is in reversed order
        let mut rb_conv = order::RadixBasis::new(hpu_p.ntt_params.radix, hpu_p.ntt_params.stg_nb);

        // Put HpuLut back in standard order and align on msb
        order::poly_order(
            cpu_glwe.get_mut_body().as_mut_polynomial().into_container(),
            // hpu_lut.as_view().into_container(),
            hpu_lut.as_ref(),
            order::PolyOrder::Reverse,
            &mut rb_conv,
            |x| x,
        );
        modswitch::lsb2msb_align(
            hpu_p,
            cpu_glwe.get_mut_body().as_mut_polynomial().into_container(),
        );
        cpu_glwe
    }
}

pub fn create_hpu_lookuptable(
    params: HpuParameters,
    pbs: hpu_asm::Pbs,
) -> HpuGlweLookuptableOwned<u64> {
    // Create Glwe
    let pbs_p = ClassicPBSParameters::from(params.clone());
    let mut cpu_acc = GlweCiphertext::new(
        0,
        pbs_p.glwe_dimension.to_glwe_size(),
        pbs_p.polynomial_size,
        pbs_p.ciphertext_modulus,
    );

    // Zeroed mask
    let mut cpu_acc_view = cpu_acc.as_mut_view();
    cpu_acc_view.get_mut_mask().as_mut().fill(0);

    // Populate body
    // Modulus of the msg contained in the msg bits and operations buffer
    let modulus_sup = (pbs_p.message_modulus.0 * pbs_p.carry_modulus.0) as usize;

    // N/(p/2) = size of each block
    let box_size = pbs_p.polynomial_size.0 / modulus_sup;

    // Value of the shift we multiply our messages by
    let delta = (1_u64 << 63) / (pbs_p.message_modulus.0 * pbs_p.carry_modulus.0) as u64;

    let mut body = cpu_acc_view.get_mut_body();
    let body_u64 = body.as_mut();

    let digits_params = hpu_asm::DigitParameters {
        msg_w: params.pbs_params.message_width,
        carry_w: params.pbs_params.carry_width,
    };

    for i in 0..modulus_sup {
        let index = i * box_size;
        let f_eval = pbs.eval(&digits_params, i as usize) as u64;
        body_u64[index..index + box_size].fill(f_eval * delta);
    }

    let half_box_size = box_size / 2;

    // Negate the first half_box_size coefficients
    for a_i in body_u64[0..half_box_size].iter_mut() {
        *a_i = (*a_i).wrapping_neg();
    }

    // Rotate the accumulator
    body_u64.rotate_left(half_box_size);

    cpu_acc.as_view().into_with(params)
}
