use tfhe_hpu_backend::prelude::*;

use crate::core_crypto::hpu::from_with::FromWith;
use crate::core_crypto::prelude::LweCiphertextOwned;
use crate::integer::RadixCiphertext;
use crate::shortint::ciphertext::{Degree, NoiseLevel};
use crate::shortint::{Ciphertext, ClassicPBSParameters};

/// Simple wrapper over HpuVar
/// Add method to convert from/to cpu radix ciphertext
#[derive(Clone)]
pub struct HpuRadixCiphertext(pub(crate) HpuVarWrapped);

#[cfg(feature = "hpu-debug")]
/// Implement dedicated interface for trace application
impl HpuRadixCiphertext {
    pub fn new(hpu_var: HpuVarWrapped) -> Self {
        Self(hpu_var)
    }
    pub fn into_var(self) -> HpuVarWrapped {
        self.0
    }
}

impl HpuRadixCiphertext {
    /// Create a Hpu Radix ciphertext based on a Cpu one.
    /// No xfer with Fpga occured until operation is request on HpuRadixCiphertext
    /// TODO Rework the way to iterate over RadixCihpertext
    pub fn from_radix_ciphertext(cpu_ct: &RadixCiphertext, device: &HpuDevice) -> Self {
        let params = device.params();

        let hpu_ct = cpu_ct
            .blocks
            .iter()
            .map(|blk| HpuLweCiphertextOwned::from_with(blk.ct.as_view(), params.clone()))
            .collect::<Vec<_>>();

        Self(device.new_var_from(hpu_ct))
    }

    /// Create a Cpu radix ciphertext copy from a Hpu one.
    pub fn to_radix_ciphertext(&self) -> RadixCiphertext {
        // NB: We clone the inner part of HpuRadixCiphertext but it is not costly since
        // it's wrapped inside an Arc
        let hpu_ct = self.0.clone().into_ct();
        let cpu_ct = hpu_ct
            .into_iter()
            .map(|ct| {
                let pbs_p = ClassicPBSParameters::from(ct.params());
                let cpu_ct = LweCiphertextOwned::from(ct.as_view());
                // Hpu output clean ciphertext without carry
                Ciphertext::new(
                    cpu_ct,
                    Degree::new(pbs_p.message_modulus.0 - 1),
                    NoiseLevel::NOMINAL,
                    pbs_p.message_modulus,
                    pbs_p.carry_modulus,
                    pbs_p.encryption_key_choice.into(),
                )
            })
            .collect::<Vec<_>>();
        RadixCiphertext { blocks: cpu_ct }
    }
}
