//! Module containing the definition of the HpuLweCiphertext conversion traits.
//!
//! NB: LweCiphertext need to be:
//!   * Sent to Hw -> Conversion from Cpu world to Hpu World
//!   * Retrieved from Hw -> Conversion from Hpu world to Cpu World

use tfhe_hpu_backend::prelude::*;

use super::algorithms::modswitch;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

impl<Scalar: UnsignedInteger> CreateFrom<LweCiphertextView<'_, Scalar>>
    for HpuLweCiphertextOwned<Scalar>
{
    type Metadata = HpuParameters;
    fn create_from(cpu_lwe: LweCiphertextView<'_, Scalar>, meta: Self::Metadata) -> Self {
        let mut hpu_lwe = Self::new(Scalar::ZERO, meta.clone());
        let lwe_len = hpu_lwe.len();

        for (i, &src) in cpu_lwe.get_mask().as_ref().iter().enumerate() {
            hpu_lwe[i] = modswitch::msb2lsb(&meta, src);
        }

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
        let params = hpu_lwe.params();
        let pbs_p = &params.pbs_params;
        let lwe_len = hpu_lwe.len();

        let mut cpu_lwe = Self::new(
            Scalar::ZERO,
            LweSize(lwe_len),
            CiphertextModulus::try_new_power_of_2(pbs_p.ciphertext_width).unwrap(),
        );

        // FPGA outputs natural order, we start by simply copying the body (last coef)
        *cpu_lwe.get_mut_body().data = modswitch::lsb2msb(params, hpu_lwe[lwe_len - 1]);

        // For performance, we iterate depending on pem_pc and chunk size.
        let pem_pc = params.pc_params.pem_pc;
        let chunk_size = params.regf_params.coef_nb / pem_pc;
        let shift = Scalar::BITS - params.ntt_params.ct_width as usize;
        let pc_data = hpu_lwe.into_container(); // raw pc buffer

        // orders data from each PC chunks so that we avoid sorting element per element
        cpu_lwe
            .get_mut_mask()
            .as_mut()
            .chunks_mut(chunk_size)
            .enumerate()
            .for_each(|(k, run)| {
                let offset = (k / pem_pc) * chunk_size;
                let src = &pc_data[k % pem_pc][offset..offset + run.len()];
                for (dst, &coef) in run.iter_mut().zip(src) {
                    *dst = coef << shift;
                }
            });

        cpu_lwe
    }
}
