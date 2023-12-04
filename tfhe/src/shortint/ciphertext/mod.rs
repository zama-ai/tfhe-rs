//! Module with the definition of the Ciphertext.
use crate::conformance::ParameterSetConformant;
pub use crate::core_crypto::commons::parameters::PBSOrder;
use crate::core_crypto::entities::*;
use crate::shortint::parameters::{CarryModulus, MessageModulus};
use serde::{Deserialize, Serialize};
use std::cmp;
use std::fmt::Debug;

use super::parameters::{CiphertextConformanceParams, CiphertextListConformanceParams};
use super::CheckError;

/// Error for when a non trivial ciphertext was used when a trivial was expected
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct NotTrivialCiphertextError;

impl std::fmt::Display for NotTrivialCiphertextError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "The ciphertext is a not a trivial ciphertext")
    }
}

impl std::error::Error for NotTrivialCiphertextError {}

/// This tracks the maximal amount of noise of a [Ciphertext]
/// that guarantees the target p-error when doing a PBS on it
#[derive(Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize)]
pub struct MaxNoiseLevel(usize);

impl MaxNoiseLevel {
    pub fn new(value: usize) -> Self {
        Self(value)
    }

    pub fn get(&self) -> usize {
        self.0
    }

    // This function is valid for current parameters as they guarantee the p-error for a norm2 noise
    // limit equal to the norm2 limit which guarantees a clean padding bit
    //
    // TODO: remove this functions once noise norm2 constraint is decorrelated and stored in
    // parameter sets
    pub fn from_msg_carry_modulus(
        msg_modulus: MessageModulus,
        carry_modulus: CarryModulus,
    ) -> Self {
        Self((carry_modulus.0 * msg_modulus.0 - 1) / (msg_modulus.0 - 1))
    }

    pub fn validate(&self, noise_level: NoiseLevel) -> Result<(), CheckError> {
        if noise_level.0 > self.0 {
            return Err(CheckError::NoiseTooBig {
                noise_level,
                max_noise_level: *self,
            });
        }
        Ok(())
    }
}

/// This tracks the amount of noise in a ciphertext.
#[derive(Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize)]
pub struct NoiseLevel(usize);

impl NoiseLevel {
    pub const NOMINAL: Self = Self(1);
    pub const ZERO: Self = Self(0);
    // To force a refresh no matter the tolerance of the server key, useful for serialization update
    // for formats which did not have noise levels saved
    pub const MAX: Self = Self(usize::MAX);
    // As a safety measure the unknown noise level is set to the max value
    pub const UNKNOWN: Self = Self::MAX;
}

impl NoiseLevel {
    pub fn get(&self) -> usize {
        self.0
    }
}

impl std::ops::AddAssign for NoiseLevel {
    fn add_assign(&mut self, rhs: Self) {
        self.0 = self.0.saturating_add(rhs.0);
    }
}

impl std::ops::Add for NoiseLevel {
    type Output = Self;

    fn add(mut self, rhs: Self) -> Self {
        self += rhs;
        self
    }
}

impl std::ops::MulAssign<usize> for NoiseLevel {
    fn mul_assign(&mut self, rhs: usize) {
        self.0 = self.0.saturating_mul(rhs);
    }
}

impl std::ops::Mul<usize> for NoiseLevel {
    type Output = Self;

    fn mul(mut self, rhs: usize) -> Self::Output {
        self *= rhs;

        self
    }
}

/// Maximum value that the degree can reach.
#[derive(Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize)]
pub struct MaxDegree(usize);

impl MaxDegree {
    pub fn new(value: usize) -> Self {
        Self(value)
    }

    pub fn get(&self) -> usize {
        self.0
    }

    pub fn from_msg_carry_modulus(
        msg_modulus: MessageModulus,
        carry_modulus: CarryModulus,
    ) -> Self {
        Self(carry_modulus.0 * msg_modulus.0 - 1)
    }

    pub fn validate(&self, degree: Degree) -> Result<(), CheckError> {
        if degree.get() > self.0 {
            return Err(CheckError::CarryFull {
                degree,
                max_degree: *self,
            });
        }
        Ok(())
    }
}

/// This tracks the number of operations that has been done.
#[derive(Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize)]
pub struct Degree(usize);

impl Degree {
    pub fn new(degree: usize) -> Self {
        Self(degree)
    }

    pub fn get(self) -> usize {
        self.0
    }
}

#[cfg(test)]
impl AsMut<usize> for Degree {
    fn as_mut(&mut self) -> &mut usize {
        &mut self.0
    }
}

impl Degree {
    pub(crate) fn after_bitxor(self, other: Self) -> Self {
        let max = cmp::max(self.0, other.0);
        let min = cmp::min(self.0, other.0);
        let mut result = max;

        //Try every possibility to find the worst case
        for i in 0..min + 1 {
            if max ^ i > result {
                result = max ^ i;
            }
        }

        Self(result)
    }

    pub(crate) fn after_bitor(self, other: Self) -> Self {
        let max = cmp::max(self.0, other.0);
        let min = cmp::min(self.0, other.0);
        let mut result = max;

        for i in 0..min + 1 {
            if max | i > result {
                result = max | i;
            }
        }

        Self(result)
    }

    pub(crate) fn after_bitand(self, other: Self) -> Self {
        Self(cmp::min(self.0, other.0))
    }

    pub(crate) fn after_left_shift(self, shift: u8, modulus: usize) -> Self {
        let mut result = 0;

        for i in 0..self.0 + 1 {
            let tmp = (i << shift) % modulus;
            if tmp > result {
                result = tmp;
            }
        }

        Self(result)
    }

    #[allow(dead_code)]
    pub(crate) fn after_pbs<F>(self, f: F) -> Self
    where
        F: Fn(usize) -> usize,
    {
        let mut result = 0;

        for i in 0..self.0 + 1 {
            let tmp = f(i);
            if tmp > result {
                result = tmp;
            }
        }

        Self(result)
    }
}

impl std::ops::AddAssign for Degree {
    fn add_assign(&mut self, rhs: Self) {
        self.0 = self.0.saturating_add(rhs.0);
    }
}

impl std::ops::Add for Degree {
    type Output = Self;

    fn add(mut self, rhs: Self) -> Self {
        self += rhs;
        self
    }
}

impl std::ops::MulAssign<usize> for Degree {
    fn mul_assign(&mut self, rhs: usize) {
        self.0 = self.0.saturating_mul(rhs);
    }
}

impl std::ops::Mul<usize> for Degree {
    type Output = Self;

    fn mul(mut self, rhs: usize) -> Self::Output {
        self *= rhs;

        self
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[must_use]
pub struct Ciphertext {
    pub ct: LweCiphertextOwned<u64>,
    pub degree: Degree,
    noise_level: NoiseLevel,
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

/// A structure representing a compressed shortint ciphertext.
/// It is used to homomorphically evaluate a shortint circuits.
/// Internally, it uses a LWE ciphertext.
#[derive(Clone, Serialize, Deserialize)]
pub struct CompressedCiphertext {
    pub ct: SeededLweCiphertext<u64>,
    pub degree: Degree,
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
    pub pbs_order: PBSOrder,
    pub noise_level: NoiseLevel,
}

impl ParameterSetConformant for CompressedCiphertext {
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

impl CompressedCiphertext {
    pub fn decompress(self) -> Ciphertext {
        let Self {
            ct,
            degree,
            message_modulus,
            carry_modulus,
            pbs_order,
            noise_level,
        } = self;

        Ciphertext {
            ct: ct.decompress_into_lwe_ciphertext(),
            degree,
            message_modulus,
            carry_modulus,
            pbs_order,
            noise_level,
        }
    }
}

impl From<CompressedCiphertext> for Ciphertext {
    fn from(value: CompressedCiphertext) -> Self {
        value.decompress()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactCiphertextList {
    pub ct_list: LweCompactCiphertextListOwned<u64>,
    pub degree: Degree,
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
    pub pbs_order: PBSOrder,
    pub noise_level: NoiseLevel,
}

impl ParameterSetConformant for CompactCiphertextList {
    type ParameterSet = CiphertextListConformanceParams;

    fn is_conformant(&self, param: &CiphertextListConformanceParams) -> bool {
        self.ct_list.is_conformant(&param.ct_list_params)
            && self.message_modulus == param.message_modulus
            && self.carry_modulus == param.carry_modulus
            && self.pbs_order == param.pbs_order
            && self.degree == param.degree
            && self.noise_level == param.noise_level
    }
}

impl CompactCiphertextList {
    pub fn expand(&self) -> Vec<Ciphertext> {
        let mut output_lwe_ciphertext_list = LweCiphertextList::new(
            0u64,
            self.ct_list.lwe_size(),
            self.ct_list.lwe_ciphertext_count(),
            self.ct_list.ciphertext_modulus(),
        );

        // No parallelism allowed
        #[cfg(all(feature = "__wasm_api", not(feature = "parallel-wasm-api")))]
        {
            use crate::core_crypto::prelude::expand_lwe_compact_ciphertext_list;
            expand_lwe_compact_ciphertext_list(&mut output_lwe_ciphertext_list, &self.ct_list);
        }

        // Parallelism allowed
        #[cfg(any(not(feature = "__wasm_api"), feature = "parallel-wasm-api"))]
        {
            use crate::core_crypto::prelude::par_expand_lwe_compact_ciphertext_list;
            par_expand_lwe_compact_ciphertext_list(&mut output_lwe_ciphertext_list, &self.ct_list);
        }

        output_lwe_ciphertext_list
            .as_ref()
            .chunks_exact(self.ct_list.lwe_size().0)
            .map(|lwe_data| {
                let ct = LweCiphertext::from_container(
                    lwe_data.to_vec(),
                    self.ct_list.ciphertext_modulus(),
                );
                Ciphertext {
                    ct,
                    degree: self.degree,
                    message_modulus: self.message_modulus,
                    carry_modulus: self.carry_modulus,
                    pbs_order: self.pbs_order,
                    noise_level: self.noise_level,
                }
            })
            .collect::<Vec<_>>()
    }

    pub fn size_elements(&self) -> usize {
        self.ct_list.size_elements()
    }

    pub fn size_bytes(&self) -> usize {
        self.ct_list.size_bytes()
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

    #[test]
    fn test_noise_level_ci_run_filter() {
        use rand::{thread_rng, Rng};

        let mut rng = thread_rng();

        assert_eq!(NoiseLevel::UNKNOWN, NoiseLevel::MAX);

        let max_noise_level = NoiseLevel::MAX;
        let random_addend = rng.gen::<usize>();
        let add = max_noise_level + NoiseLevel(random_addend);
        assert_eq!(add, NoiseLevel::MAX);

        let random_positive_multiplier = rng.gen_range(1usize..=usize::MAX);
        let mul = max_noise_level * random_positive_multiplier;
        assert_eq!(mul, NoiseLevel::MAX);
    }

    #[test]
    fn test_max_noise_level_from_msg_carry_modulus() {
        let max_noise_level =
            MaxNoiseLevel::from_msg_carry_modulus(MessageModulus(4), CarryModulus(4));

        assert_eq!(max_noise_level.0, 5);
    }
}
