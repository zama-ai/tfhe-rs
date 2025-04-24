//! Module containing the definition of the HpuGlweCiphertext.

use hpu_asm::PbsLut;
use tfhe_hpu_backend::prelude::*;

use super::algorithms::{modswitch, order};
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::prelude::{CiphertextModulus, GlweDimension, PolynomialSize};

impl<Scalar: UnsignedInteger> CreateFrom<GlweCiphertextView<'_, Scalar>>
    for HpuGlweLookuptableOwned<Scalar>
{
    type Metadata = HpuParameters;
    fn create_from(cpu_glwe: GlweCiphertextView<'_, Scalar>, meta: Self::Metadata) -> Self {
        let mut hpu_lut = Self::new(Scalar::ZERO, meta.clone());
        let ntt_p = &meta.ntt_params;

        // NB: Glwe polynomial must be in reversed order
        let rb_conv = order::RadixBasis::new(ntt_p.radix, ntt_p.stg_nb);

        // Put glwe in reverse order and align on lsb
        // Only handle Body since Lut is encoded as trivial Glwe
        order::poly_order(
            hpu_lut.as_mut(),
            cpu_glwe.get_body().as_polynomial().into_container(),
            &rb_conv,
            |x| x,
        );
        modswitch::msb2lsb_align(&meta, hpu_lut.as_mut());
        hpu_lut
    }
}

impl From<HpuGlweLookuptableView<'_, u64>> for GlweCiphertextOwned<u64> {
    fn from(hpu_lut: HpuGlweLookuptableView<'_, u64>) -> Self {
        let hpu_p = hpu_lut.params();
        let pbs_p = hpu_p.pbs_params;

        let mut cpu_glwe = Self::new(
            0,
            GlweDimension(pbs_p.glwe_dimension).to_glwe_size(),
            PolynomialSize(pbs_p.polynomial_size),
            CiphertextModulus::try_new_power_of_2(pbs_p.ciphertext_width)
                .expect("Invalid ciphertext width"),
        );
        // NB: GlweLut polynomial is in reversed order
        let rb_conv = order::RadixBasis::new(hpu_p.ntt_params.radix, hpu_p.ntt_params.stg_nb);

        // Put HpuLut back in standard order and align on msb
        order::poly_order(
            cpu_glwe.get_mut_body().as_mut_polynomial().into_container(),
            // hpu_lut.as_view().into_container(),
            hpu_lut.as_ref(),
            &rb_conv,
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
    pbs: &hpu_asm::Pbs,
) -> HpuGlweLookuptableOwned<u64> {
    // Create Glwe
    let pbs_p = params.pbs_params;
    let mut cpu_acc = GlweCiphertext::new(
        0,
        GlweDimension(pbs_p.glwe_dimension).to_glwe_size(),
        PolynomialSize(pbs_p.polynomial_size),
        CiphertextModulus::try_new_power_of_2(pbs_p.ciphertext_width)
            .expect("Invalid ciphertext width"),
    );

    // Zeroed mask
    let mut cpu_acc_view = cpu_acc.as_mut_view();
    cpu_acc_view.get_mut_mask().as_mut().fill(0);

    // Populate body
    // Modulus of the msg contained in the msg bits and operations buffer
    let modulus_sup = 1 << (pbs_p.message_width + pbs_p.carry_width);

    // N/(p/2) = size of each block
    let box_size = pbs_p.polynomial_size / modulus_sup;

    // Value of the shift we multiply our messages by
    // NB: Tfhe-rs always align information in MSB whatever power_of_two modulus is used
    //     This is why we compute the encoding delta based on container width instead of
    //     real modulus width
    let encode = |x: Cleartext<u64>| {
        let cleartext_and_padding_width = pbs_p.message_width + pbs_p.carry_width + 1;
        let delta = 1 << (u64::BITS - cleartext_and_padding_width as u32);
        Plaintext(x.0.wrapping_mul(delta))
    };

    let mut body = cpu_acc_view.get_mut_body();
    let body_u64 = body.as_mut();

    let digits_params = hpu_asm::DigitParameters {
        msg_w: params.pbs_params.message_width,
        carry_w: params.pbs_params.carry_width,
    };

    let lut_nb = pbs.lut_nb() as usize;

    let single_function_sub_lut_size = (modulus_sup / lut_nb) * box_size;

    for (pos, function_sub_lut) in body_u64
        .chunks_mut(single_function_sub_lut_size)
        .enumerate()
    {
        for (msg_value, sub_lut_box) in function_sub_lut.chunks_exact_mut(box_size).enumerate() {
            let function_eval = pbs.fn_at(pos, &digits_params, msg_value) as u64;
            sub_lut_box.fill(encode(Cleartext(function_eval)).0);
        }
    }

    let half_box_size = box_size / 2;

    // Negate the first half_box_size coefficients
    for a_i in body_u64[0..half_box_size].iter_mut() {
        *a_i = (*a_i).wrapping_neg();
    }

    // Rotate the accumulator
    body_u64.rotate_left(half_box_size);

    HpuGlweLookuptableOwned::create_from(cpu_acc.as_view(), params)
}
