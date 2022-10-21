//! All the `ShortintEngine` method related to client side (encrypt / decrypt)
use super::{EngineResult, ShortintEngine};
use crate::core_crypto::prelude::*;
use crate::shortint::ciphertext::Degree;
use crate::shortint::parameters::{CarryModulus, MessageModulus};
use crate::shortint::{Ciphertext, ClientKey, Parameters};

impl ShortintEngine {
    pub fn new_client_key(&mut self, parameters: Parameters) -> EngineResult<ClientKey> {
        // generate the lwe secret key
        let small_lwe_secret_key: LweSecretKey64 = self
            .engine
            .generate_new_lwe_secret_key(parameters.lwe_dimension)?;

        // generate the rlwe secret key
        let glwe_secret_key: GlweSecretKey64 = self
            .engine
            .generate_new_glwe_secret_key(parameters.glwe_dimension, parameters.polynomial_size)?;

        let large_lwe_secret_key = self
            .engine
            .transform_glwe_secret_key_to_lwe_secret_key(glwe_secret_key.clone())?;

        // pack the keys in the client key set
        Ok(ClientKey {
            lwe_secret_key: large_lwe_secret_key,
            glwe_secret_key,
            lwe_secret_key_after_ks: small_lwe_secret_key,
            parameters,
        })
    }

    pub fn encrypt(&mut self, client_key: &ClientKey, message: u64) -> EngineResult<Ciphertext> {
        self.encrypt_with_message_modulus(
            client_key,
            message,
            client_key.parameters.message_modulus,
        )
    }

    pub(crate) fn encrypt_with_message_modulus(
        &mut self,
        client_key: &ClientKey,
        message: u64,
        message_modulus: MessageModulus,
    ) -> EngineResult<Ciphertext> {
        //This ensures that the space message_modulus*carry_modulus < param.message_modulus *
        // param.carry_modulus
        let carry_modulus = (client_key.parameters.message_modulus.0
            * client_key.parameters.carry_modulus.0)
            / message_modulus.0;

        //The delta is the one defined by the parameters
        let delta = (1_u64 << 63)
            / (client_key.parameters.message_modulus.0 * client_key.parameters.carry_modulus.0)
                as u64;

        //The input is reduced modulus the message_modulus
        let m = message % message_modulus.0 as u64;

        let shifted_message = m * delta;
        // encode the message
        let plain: Plaintext64 = self.engine.create_plaintext_from(&shifted_message)?;

        // convert into a variance
        let var = Variance(client_key.parameters.lwe_modular_std_dev.get_variance());

        // encryption
        let ct = self
            .engine
            .encrypt_lwe_ciphertext(&client_key.lwe_secret_key, &plain, var)?;

        Ok(Ciphertext {
            ct,
            degree: Degree(message_modulus.0 - 1),
            message_modulus,
            carry_modulus: CarryModulus(carry_modulus),
        })
    }

    pub(crate) fn unchecked_encrypt(
        &mut self,
        client_key: &ClientKey,
        message: u64,
    ) -> EngineResult<Ciphertext> {
        let delta = (1_u64 << 63)
            / (client_key.parameters.message_modulus.0 * client_key.parameters.carry_modulus.0)
                as u64;
        let shifted_message = message * delta;
        // encode the message
        let plain: Plaintext64 = self.engine.create_plaintext_from(&shifted_message)?;

        // convert into a variance
        let var = Variance(client_key.parameters.lwe_modular_std_dev.get_variance());

        // encryption
        let ct = self
            .engine
            .encrypt_lwe_ciphertext(&client_key.lwe_secret_key, &plain, var)?;
        Ok(Ciphertext {
            ct,
            degree: Degree(
                client_key.parameters.message_modulus.0 * client_key.parameters.carry_modulus.0 - 1,
            ),
            message_modulus: client_key.parameters.message_modulus,
            carry_modulus: client_key.parameters.carry_modulus,
        })
    }

    pub(crate) fn decrypt_message_and_carry(
        &mut self,
        client_key: &ClientKey,
        ct: &Ciphertext,
    ) -> EngineResult<u64> {
        // decryption
        let decrypted = self
            .engine
            .decrypt_lwe_ciphertext(&client_key.lwe_secret_key, &ct.ct)?;

        let mut decrypted_u64: u64 = 0;
        self.engine
            .discard_retrieve_plaintext(&mut decrypted_u64, &decrypted)?;

        let delta = (1_u64 << 63)
            / (client_key.parameters.message_modulus.0 * client_key.parameters.carry_modulus.0)
                as u64;

        //The bit before the message
        let rounding_bit = delta >> 1;

        //compute the rounding bit
        let rounding = (decrypted_u64 & rounding_bit) << 1;

        Ok((decrypted_u64.wrapping_add(rounding)) / delta)
    }

    pub fn decrypt(&mut self, client_key: &ClientKey, ct: &Ciphertext) -> EngineResult<u64> {
        self.decrypt_message_and_carry(client_key, ct)
            .map(|message_and_carry| message_and_carry % ct.message_modulus.0 as u64)
    }

    pub(crate) fn encrypt_without_padding(
        &mut self,
        client_key: &ClientKey,
        message: u64,
    ) -> EngineResult<Ciphertext> {
        //Multiply by 2 to reshift and exclude the padding bit
        let delta = ((1_u64 << 63)
            / (client_key.parameters.message_modulus.0 * client_key.parameters.carry_modulus.0)
                as u64)
            * 2;

        let shifted_message = message * delta;
        // encode the message
        let plain: Plaintext64 = self.engine.create_plaintext_from(&shifted_message)?;

        // convert into a variance
        let var = Variance(client_key.parameters.lwe_modular_std_dev.get_variance());

        // encryption
        let ct = self
            .engine
            .encrypt_lwe_ciphertext(&client_key.lwe_secret_key, &plain, var)?;

        Ok(Ciphertext {
            ct,
            degree: Degree(client_key.parameters.message_modulus.0 - 1),
            message_modulus: client_key.parameters.message_modulus,
            carry_modulus: client_key.parameters.carry_modulus,
        })
    }

    pub(crate) fn decrypt_message_and_carry_without_padding(
        &mut self,
        client_key: &ClientKey,
        ct: &Ciphertext,
    ) -> EngineResult<u64> {
        // decryption
        let decrypted = self
            .engine
            .decrypt_lwe_ciphertext(&client_key.lwe_secret_key, &ct.ct)?;

        let mut decrypted_u64: u64 = 0;
        self.engine
            .discard_retrieve_plaintext(&mut decrypted_u64, &decrypted)?;

        let delta = ((1_u64 << 63)
            / (client_key.parameters.message_modulus.0 * client_key.parameters.carry_modulus.0)
                as u64)
            * 2;

        //The bit before the message
        let rounding_bit = delta >> 1;

        //compute the rounding bit
        let rounding = (decrypted_u64 & rounding_bit) << 1;

        Ok((decrypted_u64.wrapping_add(rounding)) / delta)
    }

    pub(crate) fn decrypt_without_padding(
        &mut self,
        client_key: &ClientKey,
        ct: &Ciphertext,
    ) -> EngineResult<u64> {
        self.decrypt_message_and_carry_without_padding(client_key, ct)
            .map(|message_and_carry| message_and_carry % ct.message_modulus.0 as u64)
    }

    pub(crate) fn encrypt_native_crt(
        &mut self,
        client_key: &ClientKey,
        message: u64,
        message_modulus: u8,
    ) -> EngineResult<Ciphertext> {
        let carry_modulus = 1;
        let m = (message % message_modulus as u64) as u128;
        let shifted_message = m * (1 << 64) / message_modulus as u128;
        // encode the message
        let plain: Plaintext64 = self
            .engine
            .create_plaintext_from(&(shifted_message as u64))?;

        // convert into a variance
        let var = Variance(client_key.parameters.lwe_modular_std_dev.get_variance());

        // encryption
        let ct = self
            .engine
            .encrypt_lwe_ciphertext(&client_key.lwe_secret_key, &plain, var)?;
        Ok(Ciphertext {
            ct,
            degree: Degree(message_modulus as usize - 1),
            message_modulus: MessageModulus(message_modulus as usize),
            carry_modulus: CarryModulus(carry_modulus),
        })
    }

    pub(crate) fn decrypt_message_native_crt(
        &mut self,
        client_key: &ClientKey,
        ct: &Ciphertext,
        basis: u64,
    ) -> EngineResult<u64> {
        // decryption
        let decrypted = self
            .engine
            .decrypt_lwe_ciphertext(&client_key.lwe_secret_key, &ct.ct)?;

        let mut decrypted_u64: u64 = 0;
        self.engine
            .discard_retrieve_plaintext(&mut decrypted_u64, &decrypted)?;

        let mut result = decrypted_u64 as u128 * basis as u128;
        result = result.wrapping_add((result & 1 << 63) << 1) / (1 << 64);

        Ok(result as u64 % basis)
    }
}
