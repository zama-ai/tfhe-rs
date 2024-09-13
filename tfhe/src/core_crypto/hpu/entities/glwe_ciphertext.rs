//! Module containing the definition of the HpuGlweCiphertext.

use tfhe_hpu_backend::prelude::*;

use super::algorithms::{modswitch, order};
use super::FromWith;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

impl<Scalar: UnsignedInteger> FromWith<GlweCiphertextView<'_, Scalar>, HpuParameters>
    for HpuGlweCiphertextOwned<Scalar>
{
    fn from_with(cpu_glwe: GlweCiphertextView<'_, Scalar>, params: HpuParameters) -> Self {
        let mut hpu_glwe = Self::new(Scalar::ZERO, params.clone());

        let ntt_p = &params.ntt_params;
        let pbs_p = &params.pbs_params;

        // NB: Glwe polynomial must be in reversed order
        let mut rb_conv = order::RadixBasis::new(ntt_p.radix, ntt_p.stg_nb);

        // Put glwe in reverse order and align on lsb
        std::iter::zip(
            hpu_glwe.as_mut().chunks_mut(pbs_p.polynomial_size),
            cpu_glwe.as_polynomial_list().iter(),
        )
        .for_each(|(hw, cpu)| {
            order::poly_order(
                hw,
                cpu.into_container(),
                order::PolyOrder::Reverse,
                &mut rb_conv,
                |x| x,
            );
            modswitch::msb2lsb_align(&params, hw);
        });
        hpu_glwe
    }
}
