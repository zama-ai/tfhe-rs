//! Module with the definition of the Ciphertext.
use super::super::parameters::CiphertextConformanceParams;
use super::common::*;
use crate::backward_compatibility::shortint::ciphertext::CiphertextVersions;
use crate::conformance::ParameterSetConformant;
use crate::core_crypto::entities::*;
use crate::shortint::parameters::{CarryModulus, MessageModulus};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use tfhe_versionable::Versionize;

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Versionize)]
#[versionize(CiphertextVersions)]
#[must_use]
pub struct Ciphertext {
    pub ct: LweCiphertextOwned<u64>,
    pub degree: Degree,
    pub(crate) noise_level: NoiseLevel,
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
    pub pbs_order: PBSOrder,
}

impl crate::named::Named for Ciphertext {
    const NAME: &'static str = "shortint::Ciphertext";
}

impl ParameterSetConformant for Ciphertext {
    type ParameterSet = CiphertextConformanceParams;

    fn is_conformant(&self, param: &CiphertextConformanceParams) -> bool {
        self.ct.is_conformant(&param.ct_params)
            && self.message_modulus == param.message_modulus
            && self.carry_modulus == param.carry_modulus
            && self.pbs_order == param.pbs_order
            && self.degree == param.degree
            && self.noise_level == param.noise_level
    }
}

// Use destructuring to also have a compile error
// if ever a new member is added to Ciphertext
// and is not handled here.
//
// And a warning if a member is destructured but not used.
impl Clone for Ciphertext {
    fn clone(&self) -> Self {
        let Self {
            ct: src_ct,
            degree: src_degree,
            message_modulus: src_message_modulus,
            carry_modulus: src_carry_modulus,
            pbs_order: src_pbs_order,
            noise_level: src_noise_level,
        } = self;

        Self {
            ct: src_ct.clone(),
            degree: *src_degree,
            message_modulus: *src_message_modulus,
            carry_modulus: *src_carry_modulus,
            pbs_order: *src_pbs_order,
            noise_level: *src_noise_level,
        }
    }

    fn clone_from(&mut self, source: &Self) {
        let Self {
            ct: dst_ct,
            degree: dst_degree,
            message_modulus: dst_message_modulus,
            carry_modulus: dst_carry_modulus,
            pbs_order: dst_pbs_order,
            noise_level: dst_noise_level,
        } = self;

        let Self {
            ct: src_ct,
            degree: src_degree,
            message_modulus: src_message_modulus,
            carry_modulus: src_carry_modulus,
            pbs_order: src_pbs_order,
            noise_level: src_noise_level,
        } = source;

        if dst_ct.ciphertext_modulus() != src_ct.ciphertext_modulus()
            || dst_ct.lwe_size() != src_ct.lwe_size()
        {
            *dst_ct = src_ct.clone();
        } else {
            dst_ct.as_mut().copy_from_slice(src_ct.as_ref());
        }
        *dst_degree = *src_degree;
        *dst_message_modulus = *src_message_modulus;
        *dst_carry_modulus = *src_carry_modulus;
        *dst_pbs_order = *src_pbs_order;
        *dst_noise_level = *src_noise_level;
    }
}

impl Ciphertext {
    pub fn new(
        ct: LweCiphertextOwned<u64>,
        degree: Degree,
        noise_level: NoiseLevel,
        message_modulus: MessageModulus,
        carry_modulus: CarryModulus,
        pbs_order: PBSOrder,
    ) -> Self {
        Self {
            ct,
            degree,
            noise_level,
            message_modulus,
            carry_modulus,
            pbs_order,
        }
    }
    pub fn carry_is_empty(&self) -> bool {
        self.degree.get() < self.message_modulus.0
    }

    pub fn is_trivial(&self) -> bool {
        self.noise_level() == NoiseLevel::ZERO
            && self.ct.get_mask().as_ref().iter().all(|&x| x == 0u64)
    }

    pub fn noise_level(&self) -> NoiseLevel {
        self.noise_level
    }

    pub fn set_noise_level(&mut self, noise_level: NoiseLevel) {
        self.noise_level = noise_level;
    }

    /// Decrypts a trivial ciphertext
    ///
    /// Trivial ciphertexts are ciphertexts which are not encrypted
    /// meaning they can be decrypted by any key, or even without a key.
    ///
    /// For debugging it can be useful to use trivial ciphertext to speed up
    /// execution, and use [Self::decrypt_trivial] to decrypt temporary values
    /// and debug.
    ///
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    /// use tfhe::shortint::{gen_keys, Ciphertext};
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg = 1;
    /// let msg2 = 2;
    ///
    /// // Trivial encryption
    /// let trivial_ct = sks.create_trivial(msg);
    /// let non_trivial_ct = cks.encrypt(msg2);
    ///
    /// let res = trivial_ct.decrypt_trivial();
    /// assert_eq!(Ok(1), res);
    ///
    /// let res = non_trivial_ct.decrypt_trivial();
    /// matches!(res, Err(_));
    ///
    /// // Doing operations that mixes trivial and non trivial
    /// // will always return a non trivial
    /// let ct_res = sks.add(&trivial_ct, &non_trivial_ct);
    /// let res = ct_res.decrypt_trivial();
    /// matches!(res, Err(_));
    ///
    /// // Doing operations using only trivial ciphertexts
    /// // will return a trivial
    /// let ct_res = sks.add(&trivial_ct, &trivial_ct);
    /// let res = ct_res.decrypt_trivial();
    /// assert_eq!(Ok(2), res);
    /// ```
    pub fn decrypt_trivial(&self) -> Result<u64, NotTrivialCiphertextError> {
        self.decrypt_trivial_message_and_carry()
            .map(|x| x % self.message_modulus.0 as u64)
    }

    /// See [Self::decrypt_trivial].
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    /// use tfhe::shortint::{gen_keys, Ciphertext};
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg = 2u64;
    /// let clear = 3u64;
    ///
    /// let mut trivial_ct = sks.create_trivial(msg);
    ///
    /// sks.unchecked_scalar_add_assign(&mut trivial_ct, clear as u8);
    ///
    /// let res = trivial_ct.decrypt_trivial();
    /// let expected = (msg + clear) % PARAM_MESSAGE_2_CARRY_2_KS_PBS.message_modulus.0 as u64;
    /// assert_eq!(Ok(expected), res);
    ///
    /// let res = trivial_ct.decrypt_trivial_message_and_carry();
    /// assert_eq!(Ok(msg + clear), res);
    /// ```
    pub fn decrypt_trivial_message_and_carry(&self) -> Result<u64, NotTrivialCiphertextError> {
        if self.is_trivial() {
            let delta = (1u64 << 63) / (self.message_modulus.0 * self.carry_modulus.0) as u64;
            Ok(self.ct.get_body().data / delta)
        } else {
            Err(NotTrivialCiphertextError)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shortint::CiphertextModulus;

    #[test]
    fn test_clone_from_same_lwe_size_and_modulus_ci_run_filter() {
        let mut c1 = Ciphertext {
            ct: LweCiphertextOwned::from_container(
                vec![1u64; 256],
                CiphertextModulus::new_native(),
            ),
            degree: Degree::new(1),
            message_modulus: MessageModulus(1),
            carry_modulus: CarryModulus(1),
            pbs_order: PBSOrder::KeyswitchBootstrap,
            noise_level: NoiseLevel::NOMINAL,
        };

        let c2 = Ciphertext {
            ct: LweCiphertextOwned::from_container(
                vec![2323858949u64; 256],
                CiphertextModulus::new_native(),
            ),
            degree: Degree::new(42),
            message_modulus: MessageModulus(2),
            carry_modulus: CarryModulus(2),
            pbs_order: PBSOrder::BootstrapKeyswitch,
            noise_level: NoiseLevel::NOMINAL,
        };

        assert_ne!(c1, c2);

        c1.clone_from(&c2);
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_clone_from_same_lwe_size_different_modulus_ci_run_filter() {
        let mut c1 = Ciphertext {
            ct: LweCiphertextOwned::from_container(
                vec![1u64; 256],
                CiphertextModulus::try_new_power_of_2(32).unwrap(),
            ),
            degree: Degree::new(1),
            message_modulus: MessageModulus(1),
            carry_modulus: CarryModulus(1),
            pbs_order: PBSOrder::KeyswitchBootstrap,
            noise_level: NoiseLevel::NOMINAL,
        };

        let c2 = Ciphertext {
            ct: LweCiphertextOwned::from_container(
                vec![2323858949u64; 256],
                CiphertextModulus::new_native(),
            ),
            degree: Degree::new(42),
            message_modulus: MessageModulus(2),
            carry_modulus: CarryModulus(2),
            pbs_order: PBSOrder::BootstrapKeyswitch,
            noise_level: NoiseLevel::NOMINAL,
        };

        assert_ne!(c1, c2);

        c1.clone_from(&c2);
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_clone_from_different_lwe_size_same_modulus_ci_run_filter() {
        let mut c1 = Ciphertext {
            ct: LweCiphertextOwned::from_container(
                vec![1u64; 512],
                CiphertextModulus::new_native(),
            ),
            degree: Degree::new(1),
            message_modulus: MessageModulus(1),
            carry_modulus: CarryModulus(1),
            pbs_order: PBSOrder::KeyswitchBootstrap,
            noise_level: NoiseLevel::NOMINAL,
        };

        let c2 = Ciphertext {
            ct: LweCiphertextOwned::from_container(
                vec![2323858949u64; 256],
                CiphertextModulus::new_native(),
            ),
            degree: Degree::new(42),
            message_modulus: MessageModulus(2),
            carry_modulus: CarryModulus(2),
            pbs_order: PBSOrder::BootstrapKeyswitch,
            noise_level: NoiseLevel::NOMINAL,
        };

        assert_ne!(c1, c2);

        c1.clone_from(&c2);
        assert_eq!(c1, c2);
    }
}
