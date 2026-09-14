//! Module containing the definition of the HpuGlweCiphertext.

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

pub fn create_hpu_lookuptable(params: &HpuParameters, lut: &[u64]) -> HpuGlweLookuptableOwned<u64> {
    let pbs_p = params.pbs_params;

    // Check that lut definition match with message/carry width
    assert_eq!(lut.len(), 1 << (pbs_p.message_width + pbs_p.carry_width));

    // Create Glwe
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

    // N/p = size of each box
    let box_size = pbs_p.polynomial_size / modulus_sup;

    // Value of the shift we multiply our messages by
    // NB: Tfhe-rs always align information in MSB whatever power_of_two modulus is used
    //     This is why we compute the encoding delta based on container width instead of
    //     real modulus width
    let encode = |x: u64| {
        let cleartext_and_padding_width = pbs_p.message_width + pbs_p.carry_width + 1;
        let delta = 1 << (u64::BITS - cleartext_and_padding_width as u32);
        Plaintext(x.wrapping_mul(delta))
    };

    let mut body = cpu_acc_view.get_mut_body();
    let body_u64 = body.as_mut();

    for (pos, lut_box) in body_u64.chunks_mut(box_size).enumerate() {
        lut_box.fill(encode(lut[pos]).0);
    }

    let half_box_size = box_size / 2;

    // Negate the first half_box_size coefficients
    for a_i in body_u64[0..half_box_size].iter_mut() {
        *a_i = (*a_i).wrapping_neg();
    }

    // Rotate the accumulator
    body_u64.rotate_left(half_box_size);

    HpuGlweLookuptableOwned::create_from(cpu_acc.as_view(), params.clone())
}
