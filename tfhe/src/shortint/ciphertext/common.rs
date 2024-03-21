use super::super::CheckError;
pub use crate::core_crypto::commons::parameters::PBSOrder;
use crate::shortint::parameters::{CarryModulus, MessageModulus};
use serde::{Deserialize, Serialize};
use std::cmp;
use std::fmt::Debug;

/// Error for when a non trivial ciphertext was used when a trivial was expected
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct NotTrivialCiphertextError;

impl std::fmt::Display for NotTrivialCiphertextError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "The ciphertext is a not a trivial ciphertext")
    }
}

impl std::error::Error for NotTrivialCiphertextError {}

/// This tracks the maximal amount of noise of a [super::Ciphertext]
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
pub struct Degree(pub(super) usize);

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

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn degree_after_bitxor_ci_run_filter() {
        let data = [
            (Degree(3), Degree(3), Degree(3)),
            (Degree(3), Degree(1), Degree(3)),
            (Degree(1), Degree(3), Degree(3)),
            (Degree(3), Degree(2), Degree(3)),
            (Degree(2), Degree(3), Degree(3)),
            (Degree(2), Degree(2), Degree(3)),
            (Degree(2), Degree(1), Degree(3)),
            (Degree(1), Degree(2), Degree(3)),
            (Degree(1), Degree(1), Degree(1)),
            (Degree(0), Degree(1), Degree(1)),
            (Degree(0), Degree(1), Degree(1)),
        ];

        for (lhs, rhs, expected) in data {
            let result = lhs.after_bitxor(rhs);
            assert_eq!(
                result, expected,
                "For a bitxor between variables of degree {lhs:?} and {rhs:?},\
             expected resulting degree: {expected:?}, got {result:?}"
            );
        }
    }
    #[test]
    fn degree_after_bitor_ci_run_filter() {
        let data = [
            (Degree(3), Degree(3), Degree(3)),
            (Degree(3), Degree(1), Degree(3)),
            (Degree(1), Degree(3), Degree(3)),
            (Degree(3), Degree(2), Degree(3)),
            (Degree(2), Degree(3), Degree(3)),
            (Degree(2), Degree(2), Degree(3)),
            (Degree(2), Degree(1), Degree(3)),
            (Degree(1), Degree(2), Degree(3)),
            (Degree(1), Degree(1), Degree(1)),
            (Degree(0), Degree(1), Degree(1)),
            (Degree(0), Degree(1), Degree(1)),
        ];

        for (lhs, rhs, expected) in data {
            let result = lhs.after_bitor(rhs);
            assert_eq!(
                result, expected,
                "For a bitor between variables of degree {lhs:?} and {rhs:?},\
             expected resulting degree: {expected:?}, got {result:?}"
            );
        }
    }

    #[test]
    fn degree_after_bitand_ci_run_filter() {
        let data = [
            (Degree(3), Degree(3), Degree(3)),
            (Degree(3), Degree(1), Degree(1)),
            (Degree(1), Degree(3), Degree(1)),
            (Degree(3), Degree(2), Degree(2)),
            (Degree(2), Degree(3), Degree(2)),
            (Degree(2), Degree(2), Degree(2)),
            (Degree(2), Degree(1), Degree(1)),
            (Degree(1), Degree(2), Degree(1)),
            (Degree(1), Degree(1), Degree(1)),
            (Degree(0), Degree(1), Degree(0)),
            (Degree(0), Degree(1), Degree(0)),
        ];

        for (lhs, rhs, expected) in data {
            let result = lhs.after_bitand(rhs);
            assert_eq!(
                result, expected,
                "For a bitand between variables of degree {lhs:?} and {rhs:?},\
             expected resulting degree: {expected:?}, got {result:?}"
            );
        }
    }
}
