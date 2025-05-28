use super::common::*;
use crate::core_crypto::commons::parameters::LweSize;
use crate::core_crypto::entities::lwe_ciphertext::LweCiphertextOwned;
use crate::shortint::backward_compatibility::ciphertext::SquashedNoiseCiphertextVersions;
use crate::shortint::parameters::{CarryModulus, CoreCiphertextModulus, MessageModulus};
use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Versionize)]
#[versionize(SquashedNoiseCiphertextVersions)]
#[must_use]
pub struct SquashedNoiseCiphertext {
    ct: LweCiphertextOwned<u128>,
    degree: Degree,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
}

impl SquashedNoiseCiphertext {
    #[allow(dead_code)]
    pub(crate) fn new(
        ct: LweCiphertextOwned<u128>,
        degree: Degree,
        message_modulus: MessageModulus,
        carry_modulus: CarryModulus,
    ) -> Self {
        Self {
            ct,
            degree,
            message_modulus,
            carry_modulus,
        }
    }
    pub(crate) fn new_zero(
        lwe_size: LweSize,
        ciphertext_modulus: CoreCiphertextModulus<u128>,
        message_modulus: MessageModulus,
        carry_modulus: CarryModulus,
    ) -> Self {
        Self {
            ct: LweCiphertextOwned::new(0, lwe_size, ciphertext_modulus),
            degree: Degree::new(0),
            message_modulus,
            carry_modulus,
        }
    }

    pub fn lwe_ciphertext(&self) -> &LweCiphertextOwned<u128> {
        &self.ct
    }

    pub fn lwe_ciphertext_mut(&mut self) -> &mut LweCiphertextOwned<u128> {
        &mut self.ct
    }

    pub fn degree(&self) -> Degree {
        self.degree
    }

    pub fn message_modulus(&self) -> MessageModulus {
        self.message_modulus
    }

    pub fn carry_modulus(&self) -> CarryModulus {
        self.carry_modulus
    }

    pub fn set_degree(&mut self, new_degree: Degree) {
        self.degree = new_degree;
    }
}
