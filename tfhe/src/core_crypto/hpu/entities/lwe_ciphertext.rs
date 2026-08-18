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

        // FPGA outputs natural order, a flat walk over the mask is sufficient.
        let mut mask = cpu_lwe.get_mut_mask();

        for (i, dst) in mask.as_mut().iter_mut().enumerate() {
            *dst = modswitch::lsb2msb(params, hpu_lwe[i]);
        }
        *cpu_lwe.get_mut_body().data = modswitch::lsb2msb(params, hpu_lwe[lwe_len - 1]);

        cpu_lwe
    }
}
