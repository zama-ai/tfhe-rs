//! This module implements the generation of the client secret keys, together with the
//! encryption and decryption methods.

pub(crate) mod utils;

use crate::ciphertext::Ciphertext;
use serde::{Deserialize, Serialize};
use tfhe::shortint;
use tfhe::shortint::{ClassicPBSParameters, WopbsParameters};
pub use utils::radix_decomposition;

/// The number of ciphertexts in the vector.
#[derive(Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize)]
pub struct VecLength(pub usize);

/// A structure containing the client key, which must be kept secret.
#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct ClientKey {
    pub(crate) key: shortint::client_key::ClientKey,
    pub(crate) vector_length_mantissa: VecLength,
    pub(crate) vector_length_exponent: VecLength,
}

impl ClientKey {
    /// Allocates and generates a client key.
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_float::client_key::ClientKey;
    /// use concrete_float::parameters::{PARAM_MESSAGE_2_CARRY_2_32, WOP_PARAM_MESSAGE_2_CARRY_2_32};
    /// use concrete_shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // Generate the client key associated to integers over 4 blocks
    /// // of messages with modulus over 2 bits
    /// let param = (PARAM_MESSAGE_2_CARRY_2_32, WOP_PARAM_MESSAGE_2_CARRY_2_32);
    /// let cks = ClientKey::new(param, 4, 1);
    /// ```
    pub fn new(
        parameter_set: (ClassicPBSParameters, WopbsParameters),
        size_mantissa: usize,
        size_exponent: usize,
    ) -> Self {
        let key = shortint::ClientKey::new(parameter_set);
        Self {
            key,
            vector_length_mantissa: VecLength(size_mantissa),
            vector_length_exponent: VecLength(size_exponent),
        }
    }

    /// Returns the parameters used by the client key.
    pub fn parameters(&self) -> shortint::parameters::ShortintParameterSet {
        self.key.parameters
    }

    /// Encrypts a float message using the client key.
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_float::client_key::ClientKey;
    /// use concrete_float::parameters::{PARAM_MESSAGE_2_CARRY_2_32, WOP_PARAM_MESSAGE_2_CARRY_2_32};
    ///
    /// let param = (PARAM_MESSAGE_2_CARRY_2_32, WOP_PARAM_MESSAGE_2_CARRY_2_32);
    /// let mut cks = ClientKey::new(param, 3, 1);
    ///
    /// let msg = 1844640.;
    /// // Encryption of one message:
    /// let ct = cks.encrypt(msg);
    /// let res = cks.decrypt(&ct);
    ///
    /// //approximation less than 0.1%
    /// assert_eq!(res, msg)
    /// ```
    pub fn encrypt(&self, message: f64) -> Ciphertext {
        let ct_sign = self.encrypt_sign(message);

        let log_msg_modulus = f64::log2(self.parameters().message_modulus().0 as f64) as usize;
        let e_min = -((1 << (self.vector_length_exponent.0 * log_msg_modulus - 1)) as i64)
            - (self.vector_length_mantissa.0 as i64 - 1);
        if message == 0. {
            let exponent = 0;
            let mantissa = 0.0;
            let ct_vec_mantissa = self.encrypt_mantissa(mantissa as u64);
            let ct_vec_exponent = self.encrypt_exponent(exponent as u64);
            Ciphertext {
                ct_vec_mantissa,
                ct_vec_exponent,
                ct_sign,
                e_min,
            }
        } else {
            let length_mantissa = self.vector_length_mantissa.0;
            let log_message_modulus =
                f64::log2(self.parameters().message_modulus().0 as f64) as usize;

            let value_exponent = log_message_modulus as u64;
            let mut exponent = e_min.abs();
            let mut cpy_message = message.abs();
            while cpy_message < (1_u128 << (length_mantissa * log_message_modulus)) as f64 {
                cpy_message *= (1 << value_exponent) as f64;
                exponent -= 1;
            }
            while cpy_message >= (1_u128 << (length_mantissa * log_message_modulus)) as f64 {
                cpy_message /= (1 << value_exponent) as f64;
                exponent += 1;
            }
            //TODO
            if exponent >= (1 << (log_message_modulus * self.vector_length_exponent.0) as i64) {
                println!("encrypt overflow");
            }
            if exponent < 0 {
                for _ in 0..exponent.abs() {
                    cpy_message /= (1 << value_exponent) as f64;
                }
                exponent = 0;
                //panic!()
            }
            let mantissa = cpy_message.round() as u64;
            let ct_vec_mantissa = self.encrypt_mantissa(mantissa);
            let ct_vec_exponent = self.encrypt_exponent(exponent as u64);
            Ciphertext {
                ct_vec_mantissa,
                ct_vec_exponent,
                ct_sign,
                e_min,
            }
        }
    }

    fn encrypt_sign(&self, message: f64) -> shortint::ciphertext::Ciphertext {
        let sign: u64;
        if message >= 0. {
            sign = 0;
        } else {
            sign = 1
        }
        self.key.encrypt_without_padding(
            sign * (self.key.parameters.message_modulus().0 * self.key.parameters.carry_modulus().0
                / 2) as u64,
        )
    }

    fn encrypt_mantissa(&self, mantissa: u64) -> Vec<shortint::Ciphertext> {
        let mut ct_vec_mantissa: Vec<shortint::ciphertext::Ciphertext> = Vec::new();
        let mut power = 1_u128;
        let message_modulus = self.parameters().message_modulus().0 as u128;
        for _ in 0..self.vector_length_mantissa.0 {
            let mut decomp = mantissa as u128 & ((message_modulus - 1) * power);
            decomp /= power;

            // encryption
            let ct = self.key.encrypt(decomp as u64);
            ct_vec_mantissa.push(ct);
            //modulus to the power i
            power *= message_modulus;
        }
        ct_vec_mantissa
    }

    fn encrypt_exponent(&self, exponent: u64) -> Vec<shortint::Ciphertext> {
        let mut ct_vec_exponent: Vec<shortint::ciphertext::Ciphertext> = Vec::new();
        let mut power = 1_u64;
        let message_modulus = self.parameters().message_modulus().0 as u64;
        for _ in 0..self.vector_length_exponent.0 {
            let mut decomp = exponent as u64 & ((message_modulus - 1) * power);
            decomp /= power;

            // encryption
            let ct = self.key.encrypt(decomp);
            ct_vec_exponent.push(ct);
            //modulus to the power i
            power *= message_modulus;
        }
        ct_vec_exponent
    }

    /// Decrypts a ciphertext encrypting an float message
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_float::client_key::ClientKey;
    /// use concrete_float::parameters::{PARAM_MESSAGE_2_CARRY_2_32, WOP_PARAM_MESSAGE_2_CARRY_2_32};
    ///
    /// let param = (PARAM_MESSAGE_2_CARRY_2_32, WOP_PARAM_MESSAGE_2_CARRY_2_32);
    /// let mut cks = ClientKey::new(param, 3, 1);
    ///
    /// let msg = 1844640.;
    /// // Encryption of one message:
    /// let ct = cks.encrypt(msg);
    /// let res = cks.decrypt(&ct);
    ///
    /// //approximation less than 0.1%
    /// assert_eq!(res, msg)
    /// ```
    pub fn decrypt(&self, ctxt: &Ciphertext) -> f64 {
        let log_message_modulus = f64::log2(self.parameters().message_modulus().0 as f64) as usize;
        let value_exponent = log_message_modulus as i64;

        let mut mantissa = self.decrypt_mantissa(&ctxt.ct_vec_mantissa) as f64;
        let mut exponent = self.decrypt_exponent(&ctxt.ct_vec_exponent) as i64;
        let sign = self.decrypt_sign(&ctxt.ct_sign);

        exponent += ctxt.e_min;
        if exponent > 0 {
            for _ in 0..exponent.abs() {
                mantissa *= (1_u128 << value_exponent) as f64
            }
        } else {
            for _ in 0..exponent.abs() {
                mantissa /= (1_u128 << value_exponent) as f64
            }
        }

        let res;
        if sign == 1 {
            res = -mantissa
        } else {
            res = mantissa
        }
        res
    }

    pub fn decrypt_mantissa(&self, ctxt: &Vec<shortint::Ciphertext>) -> u128 {
        let mut result = 0_u128;
        let mut shift = 1_u128;
        for c_i in ctxt.iter() {
            //decrypt the component i of the integer and multiply it by the radix product
            let tmp = (self.key.decrypt_message_and_carry(c_i) as u128).wrapping_mul(shift);

            // update the result
            result = result.wrapping_add(tmp as u128);

            // update the shift for the next iteration
            shift = shift.wrapping_mul(self.parameters().message_modulus().0 as u128);
        }

        result
    }

    pub fn decrypt_exponent(&self, ctxt: &Vec<shortint::Ciphertext>) -> u64 {
        let mut result = 0_u64;
        let mut shift = 1_u64;
        for c_i in ctxt.iter() {
            //decrypt the component i of the integer and multiply it by the radix product
            let tmp = self.key.decrypt_message_and_carry(c_i).wrapping_mul(shift);

            // update the result
            result = result.wrapping_add(tmp);

            // update the shift for the next iteration
            shift = shift.wrapping_mul(self.parameters().message_modulus().0 as u64);
        }
        result
    }

    pub fn decrypt_sign(&self, ctxt: &shortint::Ciphertext) -> u64 {
        let result = self.key.decrypt_message_and_carry_without_padding(ctxt);
        result
            / (self.key.parameters.message_modulus().0 * self.key.parameters.carry_modulus().0 / 2)
                as u64
    }
}
