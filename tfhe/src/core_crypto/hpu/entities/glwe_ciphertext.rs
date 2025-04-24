//! Module containing the definition of the HpuGlweCiphertext.

use tfhe_hpu_backend::prelude::*;

use super::algorithms::{modswitch, order};
use crate::core_crypto::prelude::*;

impl<Scalar: UnsignedInteger> CreateFrom<GlweCiphertextView<'_, Scalar>>
    for HpuGlweCiphertextOwned<Scalar>
{
    type Metadata = HpuParameters;
    fn create_from(cpu_glwe: GlweCiphertextView<'_, Scalar>, meta: Self::Metadata) -> Self {
        let mut hpu_glwe = Self::new(Scalar::ZERO, meta.clone());

        let ntt_p = &meta.ntt_params;
        let pbs_p = &meta.pbs_params;

        // NB: Glwe polynomial must be in reversed order
        let rb_conv = order::RadixBasis::new(ntt_p.radix, ntt_p.stg_nb);

        // Put glwe in reverse order and align on lsb
        std::iter::zip(
            hpu_glwe.as_mut().chunks_mut(pbs_p.polynomial_size),
            cpu_glwe.as_polynomial_list().iter(),
        )
        .for_each(|(hw, cpu)| {
            order::poly_order(hw, cpu.into_container(), &rb_conv, |x| x);
            modswitch::msb2lsb_align(&meta, hw);
        });
        hpu_glwe
    }
}
