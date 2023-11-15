//! This module implements the generation of the client secret keys, together with the
//! encryption and decryption methods.

pub(crate) mod utils;

use crate::float_wopbs::ciphertext::Ciphertext;
use serde::{Deserialize, Serialize};
pub use utils::radix_decomposition;
use crate::shortint::ClassicPBSParameters;
use crate::shortint::WopbsParameters;

/// The number of ciphertexts in the vector.
#[derive(Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize)]
pub struct VecLength(pub usize);

/// A structure containing the client key, which must be kept secret.
#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct ClientKey {
    pub(crate) key: crate::shortint::client_key::ClientKey,
}

impl ClientKey {
    pub fn new(parameter_set: (ClassicPBSParameters, WopbsParameters))-> Self {
        Self {
            key: crate::shortint::ClientKey::new(parameter_set),
        }
    }

    pub fn from_shortint(key: crate::shortint::client_key::ClientKey) -> Self {
        Self { key }
    }

    /// Returns the parameters used by the client key.
    pub fn parameters(&self) -> crate::shortint::parameters::ShortintParameterSet {
        self.key.parameters
    }

    pub fn encrypt(
        &self,
        message: f64,
        e_min: i64,
        nb_bit_mantissa: usize,
        nb_bit_exponent: usize,
    ) -> Ciphertext {
        let uint = float_to_uint(message, e_min, nb_bit_mantissa, nb_bit_exponent);
        let mut ct_vec_float: Vec<crate::shortint::ciphertext::Ciphertext> = Vec::new();
        let message_modulus = f64::log2((self.parameters().message_modulus().0) as f64) as usize;
        let mut vector_length = (nb_bit_mantissa + nb_bit_exponent + 1) / message_modulus;
        if vector_length * message_modulus != nb_bit_mantissa + nb_bit_exponent + 1 {
            vector_length += 1;
        }
        let mut power = 1_u64;
        for _ in 0..vector_length {
            let mut decomp = uint & (((1 << message_modulus) - 1) * power);
            decomp /= power;

            // encryption
            let ct = self.key.encrypt(decomp);
            ct_vec_float.push(ct);
            //modulus to the power i
            power *= 1 << message_modulus;
        }

        Ciphertext {
            ct_vec_float,
            nb_bit_mantissa,
            nb_bit_exponent,
            e_min,
            key_id_vec: vec![],
        }
    }

    //decrypt function for the all wopbs representation
    pub fn decrypt(&self, ctxt: &Ciphertext) -> f64 {
        let integer_result = self.decrypt_(ctxt);
        uint_to_float(
            integer_result,
            ctxt.e_min,
            ctxt.nb_bit_mantissa,
            ctxt.nb_bit_exponent,
        )
    }

    pub fn decrypt_(&self, ctxt: &Ciphertext) -> u64 {
        let mut result = 0_u64;
        let mut shift = 1_u64;
        for c_i in ctxt.ct_vec_float.iter() {
            //decrypt the component i of the integer and multiply it by the radix product
            let tmp = self.key.decrypt_message_and_carry(c_i).wrapping_mul(shift);

            // update the result
            result = result.wrapping_add(tmp);

            // update the shift for the next iteration
            shift = shift.wrapping_mul(self.parameters().message_modulus().0 as u64);
        }
        result
    }
}

pub fn float_to_uint(
    mut float: f64,
    e_min: i64,
    nb_bit_mantissa: usize,
    nb_bit_exponent: usize,
) -> u64 {
    let min = 2.0_f64.powi(e_min as i32);
    let max = (2.0_f64.powi(nb_bit_mantissa as i32) - 1.) * (2.0_f64.powi(nb_bit_exponent as i32 + e_min as i32) );

    let sign: u64;
    if float > 0. {
        sign = 0;
    } else {
        sign = 1;
        float *= -1.;
    }

    let mut exponent = 0;
    let mut mantissa;
    if float == 0. {
        exponent = 0;
        mantissa = 0;
    } else if float >= max {
        //infinity
        exponent = (1 << nb_bit_exponent) - 1;
        mantissa = 0;
    } else if float < min {
        //subnormal values
        exponent = 0;
        mantissa =
            (float * ((1 << (nb_bit_mantissa - 1)) * (1 << (e_min.abs() - 1))) as f64) as u64;
    } else {
        //Normalized values
        while float < 1. {
            float *= 2.;
            exponent -= 1
        }
        while float > 1. {
            float /= 2.;
            exponent += 1
        }
        mantissa = (float * (1 << (nb_bit_mantissa)) as f64).round() as u64;
        if mantissa >= 1 << (nb_bit_mantissa){
            mantissa = mantissa >> 1;
            exponent += 1
        }
        exponent -= e_min;
    }
    let mantissa = mantissa & ((1 << nb_bit_mantissa) - 1);

    let exponent = (exponent as u64) & ((1 << nb_bit_exponent) - 1);
    (sign << (nb_bit_mantissa + nb_bit_exponent)) + (exponent << nb_bit_mantissa) + mantissa
}

pub fn uint_to_float(int: u64, e_min: i64, nb_bit_mantissa: usize, nb_bit_exponent: usize) -> f64 {
    let mantissa = (int % (1 << nb_bit_mantissa)) as f64 / (1 << (nb_bit_mantissa)) as f64;
    let exponent = ((int >> nb_bit_mantissa) % (1 << nb_bit_exponent)) as i64;
    let sign = int >> (nb_bit_exponent + nb_bit_mantissa);
    let value = mantissa * 2_f64.powi((exponent + e_min) as i32);
    if sign == 0 {
        value
    } else {
        -value
    }
}