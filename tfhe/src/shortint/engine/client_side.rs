//! All the `ShortintEngine` method related to client side (encrypt / decrypt)
use super::ShortintEngine;
use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::dispersion::DispersionParameter;
use crate::core_crypto::entities::*;
use crate::shortint::ciphertext::{Degree, NoiseLevel};
use crate::shortint::parameters::{CarryModulus, MessageModulus};
use crate::shortint::{
    Ciphertext, ClientKey, CompressedCiphertext, PBSOrder, ShortintParameterSet,
};

impl ShortintEngine {
    pub fn new_client_key(&mut self, parameters: ShortintParameterSet) -> ClientKey {
        // generate the lwe secret key
        let small_lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
            parameters.lwe_dimension(),
            &mut self.secret_generator,
        );

        // generate the rlwe secret key
        let glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
            parameters.glwe_dimension(),
            parameters.polynomial_size(),
            &mut self.secret_generator,
        );

        let large_lwe_secret_key = glwe_secret_key.clone().into_lwe_secret_key();

        // pack the keys in the client key set
        ClientKey {
            large_lwe_secret_key,
            glwe_secret_key,
            small_lwe_secret_key,
            parameters,
        }
    }

    pub fn encrypt(&mut self, client_key: &ClientKey, message: u64) -> Ciphertext {
        self.encrypt_with_message_modulus(
            client_key,
            message,
            client_key.parameters.message_modulus(),
        )
    }

    pub fn encrypt_compressed(
        &mut self,
        client_key: &ClientKey,
        message: u64,
    ) -> CompressedCiphertext {
        self.encrypt_with_message_modulus_compressed(
            client_key,
            message,
            client_key.parameters.message_modulus(),
        )
    }

    fn encrypt_inner_ct(
        &mut self,
        client_key_parameters: &ShortintParameterSet,
        client_lwe_sk: &LweSecretKeyOwned<u64>,
        noise_parameter: impl DispersionParameter,
        message: u64,
        message_modulus: MessageModulus,
    ) -> LweCiphertextOwned<u64> {
        //The delta is the one defined by the parameters
        let delta = (1_u64 << 63)
            / (client_key_parameters.message_modulus().0 * client_key_parameters.carry_modulus().0)
                as u64;

        //The input is reduced modulus the message_modulus
        let m = message % message_modulus.0 as u64;

        let shifted_message = m * delta;

        let encoded = Plaintext(shifted_message);

        allocate_and_encrypt_new_lwe_ciphertext(
            client_lwe_sk,
            encoded,
            noise_parameter,
            client_key_parameters.ciphertext_modulus(),
            &mut self.encryption_generator,
        )
    }

    pub(crate) fn encrypt_with_message_modulus(
        &mut self,
        client_key: &ClientKey,
        message: u64,
        message_modulus: MessageModulus,
    ) -> Ciphertext {
        let params_op_order: PBSOrder = client_key.parameters.encryption_key_choice().into();

        let (encryption_lwe_sk, encryption_noise) = match params_op_order {
            PBSOrder::KeyswitchBootstrap => (
                &client_key.large_lwe_secret_key,
                client_key.parameters.glwe_modular_std_dev(),
            ),
            PBSOrder::BootstrapKeyswitch => (
                &client_key.small_lwe_secret_key,
                client_key.parameters.lwe_modular_std_dev(),
            ),
        };

        let ct = self.encrypt_inner_ct(
            &client_key.parameters,
            encryption_lwe_sk,
            encryption_noise,
            message,
            message_modulus,
        );

        //This ensures that the space message_modulus*carry_modulus < param.message_modulus *
        // param.carry_modulus
        let carry_modulus = (client_key.parameters.message_modulus().0
            * client_key.parameters.carry_modulus().0)
            / message_modulus.0;

        Ciphertext::new(
            ct,
            Degree::new(message_modulus.0 - 1),
            NoiseLevel::NOMINAL,
            message_modulus,
            CarryModulus(carry_modulus),
            params_op_order,
        )
    }

    pub(crate) fn encrypt_with_message_and_carry_modulus(
        &mut self,
        client_key: &ClientKey,
        message: u64,
        message_modulus: MessageModulus,
        carry_modulus: CarryModulus,
    ) -> Ciphertext {
        assert!(
            message_modulus.0 * carry_modulus.0
                <= client_key.parameters.message_modulus().0
                    * client_key.parameters.carry_modulus().0,
            "MessageModulus * CarryModulus should be \
            smaller or equal to the max given by the parameter set."
        );

        let params_op_order: PBSOrder = client_key.parameters.encryption_key_choice().into();

        let (encryption_lwe_sk, encryption_noise) = match params_op_order {
            PBSOrder::KeyswitchBootstrap => (
                &client_key.large_lwe_secret_key,
                client_key.parameters.glwe_modular_std_dev(),
            ),
            PBSOrder::BootstrapKeyswitch => (
                &client_key.small_lwe_secret_key,
                client_key.parameters.lwe_modular_std_dev(),
            ),
        };

        let ct = self.encrypt_inner_ct(
            &client_key.parameters,
            encryption_lwe_sk,
            encryption_noise,
            message,
            message_modulus,
        );

        Ciphertext::new(
            ct,
            Degree::new(message_modulus.0 - 1),
            NoiseLevel::NOMINAL,
            message_modulus,
            carry_modulus,
            params_op_order,
        )
    }

    pub(crate) fn encrypt_with_message_modulus_compressed(
        &mut self,
        client_key: &ClientKey,
        message: u64,
        message_modulus: MessageModulus,
    ) -> CompressedCiphertext {
        //This ensures that the space message_modulus*carry_modulus < param.message_modulus *
        // param.carry_modulus
        let carry_modulus = (client_key.parameters.message_modulus().0
            * client_key.parameters.carry_modulus().0)
            / message_modulus.0;

        //The delta is the one defined by the parameters
        let delta = (1_u64 << 63)
            / (client_key.parameters.message_modulus().0 * client_key.parameters.carry_modulus().0)
                as u64;

        //The input is reduced modulus the message_modulus
        let m = message % message_modulus.0 as u64;

        let shifted_message = m * delta;

        let encoded = Plaintext(shifted_message);

        let params_op_order: PBSOrder = client_key.parameters.encryption_key_choice().into();

        let (encryption_lwe_sk, encryption_noise) = match params_op_order {
            PBSOrder::KeyswitchBootstrap => (
                &client_key.large_lwe_secret_key,
                client_key.parameters.glwe_modular_std_dev(),
            ),
            PBSOrder::BootstrapKeyswitch => (
                &client_key.small_lwe_secret_key,
                client_key.parameters.lwe_modular_std_dev(),
            ),
        };

        let ct = allocate_and_encrypt_new_seeded_lwe_ciphertext(
            encryption_lwe_sk,
            encoded,
            encryption_noise,
            client_key.parameters.ciphertext_modulus(),
            &mut self.seeder,
        );

        CompressedCiphertext {
            ct,
            degree: Degree::new(message_modulus.0 - 1),
            message_modulus,
            carry_modulus: CarryModulus(carry_modulus),
            pbs_order: params_op_order,
            noise_level: NoiseLevel::NOMINAL,
        }
    }

    pub(crate) fn unchecked_encrypt(&mut self, client_key: &ClientKey, message: u64) -> Ciphertext {
        let params_op_order: PBSOrder = client_key.parameters.encryption_key_choice().into();

        let (encryption_lwe_sk, encryption_noise) = match params_op_order {
            PBSOrder::KeyswitchBootstrap => (
                &client_key.large_lwe_secret_key,
                client_key.parameters.glwe_modular_std_dev(),
            ),
            PBSOrder::BootstrapKeyswitch => (
                &client_key.small_lwe_secret_key,
                client_key.parameters.lwe_modular_std_dev(),
            ),
        };

        let delta = (1_u64 << 63)
            / (client_key.parameters.message_modulus().0 * client_key.parameters.carry_modulus().0)
                as u64;
        let shifted_message = message * delta;

        let encoded = Plaintext(shifted_message);

        let ct = allocate_and_encrypt_new_lwe_ciphertext(
            encryption_lwe_sk,
            encoded,
            encryption_noise,
            client_key.parameters.ciphertext_modulus(),
            &mut self.encryption_generator,
        );

        Ciphertext::new(
            ct,
            Degree::new(
                client_key.parameters.message_modulus().0 * client_key.parameters.carry_modulus().0
                    - 1,
            ),
            NoiseLevel::NOMINAL,
            client_key.parameters.message_modulus(),
            client_key.parameters.carry_modulus(),
            params_op_order,
        )
    }

    pub(crate) fn encrypt_without_padding(
        &mut self,
        client_key: &ClientKey,
        message: u64,
    ) -> Ciphertext {
        //Multiply by 2 to reshift and exclude the padding bit
        let delta = ((1_u64 << 63)
            / (client_key.parameters.message_modulus().0 * client_key.parameters.carry_modulus().0)
                as u64)
            * 2;

        let shifted_message = message * delta;

        let encoded = Plaintext(shifted_message);

        let params_op_order: PBSOrder = client_key.parameters.encryption_key_choice().into();

        let (encryption_lwe_sk, encryption_noise) = match params_op_order {
            PBSOrder::KeyswitchBootstrap => (
                &client_key.large_lwe_secret_key,
                client_key.parameters.glwe_modular_std_dev(),
            ),
            PBSOrder::BootstrapKeyswitch => (
                &client_key.small_lwe_secret_key,
                client_key.parameters.lwe_modular_std_dev(),
            ),
        };

        let ct = allocate_and_encrypt_new_lwe_ciphertext(
            encryption_lwe_sk,
            encoded,
            encryption_noise,
            client_key.parameters.ciphertext_modulus(),
            &mut self.encryption_generator,
        );

        Ciphertext::new(
            ct,
            Degree::new(client_key.parameters.message_modulus().0 - 1),
            NoiseLevel::NOMINAL,
            client_key.parameters.message_modulus(),
            client_key.parameters.carry_modulus(),
            params_op_order,
        )
    }

    pub(crate) fn encrypt_without_padding_compressed(
        &mut self,
        client_key: &ClientKey,
        message: u64,
    ) -> CompressedCiphertext {
        //Multiply by 2 to reshift and exclude the padding bit
        let delta = ((1_u64 << 63)
            / (client_key.parameters.message_modulus().0 * client_key.parameters.carry_modulus().0)
                as u64)
            * 2;

        let shifted_message = message * delta;

        let encoded = Plaintext(shifted_message);

        let params_op_order: PBSOrder = client_key.parameters.encryption_key_choice().into();

        let (encryption_lwe_sk, encryption_noise) = match params_op_order {
            PBSOrder::KeyswitchBootstrap => (
                &client_key.large_lwe_secret_key,
                client_key.parameters.glwe_modular_std_dev(),
            ),
            PBSOrder::BootstrapKeyswitch => (
                &client_key.small_lwe_secret_key,
                client_key.parameters.lwe_modular_std_dev(),
            ),
        };

        let ct = allocate_and_encrypt_new_seeded_lwe_ciphertext(
            encryption_lwe_sk,
            encoded,
            encryption_noise,
            client_key.parameters.ciphertext_modulus(),
            &mut self.seeder,
        );

        CompressedCiphertext {
            ct,
            degree: Degree::new(client_key.parameters.message_modulus().0 - 1),
            message_modulus: client_key.parameters.message_modulus(),
            carry_modulus: client_key.parameters.carry_modulus(),
            pbs_order: params_op_order,
            noise_level: NoiseLevel::NOMINAL,
        }
    }

    pub(crate) fn encrypt_native_crt(
        &mut self,
        client_key: &ClientKey,
        message: u64,
        message_modulus: u8,
    ) -> Ciphertext {
        let carry_modulus = 1;
        let m = (message % message_modulus as u64) as u128;
        let shifted_message = (m * (1 << 64) / message_modulus as u128) as u64;

        let encoded = Plaintext(shifted_message);

        let params_op_order: PBSOrder = client_key.parameters.encryption_key_choice().into();

        let (encryption_lwe_sk, encryption_noise) = match params_op_order {
            PBSOrder::KeyswitchBootstrap => (
                &client_key.large_lwe_secret_key,
                client_key.parameters.glwe_modular_std_dev(),
            ),
            PBSOrder::BootstrapKeyswitch => (
                &client_key.small_lwe_secret_key,
                client_key.parameters.lwe_modular_std_dev(),
            ),
        };

        let ct = allocate_and_encrypt_new_lwe_ciphertext(
            encryption_lwe_sk,
            encoded,
            encryption_noise,
            client_key.parameters.ciphertext_modulus(),
            &mut self.encryption_generator,
        );

        Ciphertext::new(
            ct,
            Degree::new(message_modulus as usize - 1),
            NoiseLevel::NOMINAL,
            MessageModulus(message_modulus as usize),
            CarryModulus(carry_modulus),
            params_op_order,
        )
    }

    pub(crate) fn encrypt_native_crt_compressed(
        &mut self,
        client_key: &ClientKey,
        message: u64,
        message_modulus: u8,
    ) -> CompressedCiphertext {
        let carry_modulus = 1;
        let m = (message % message_modulus as u64) as u128;
        let shifted_message = (m * (1 << 64) / message_modulus as u128) as u64;

        let encoded = Plaintext(shifted_message);

        let params_op_order: PBSOrder = client_key.parameters.encryption_key_choice().into();

        let (encryption_lwe_sk, encryption_noise) = match params_op_order {
            PBSOrder::KeyswitchBootstrap => (
                &client_key.large_lwe_secret_key,
                client_key.parameters.glwe_modular_std_dev(),
            ),
            PBSOrder::BootstrapKeyswitch => (
                &client_key.small_lwe_secret_key,
                client_key.parameters.lwe_modular_std_dev(),
            ),
        };

        let ct = allocate_and_encrypt_new_seeded_lwe_ciphertext(
            encryption_lwe_sk,
            encoded,
            encryption_noise,
            client_key.parameters.ciphertext_modulus(),
            &mut self.seeder,
        );

        CompressedCiphertext {
            ct,
            degree: Degree::new(message_modulus as usize - 1),
            message_modulus: MessageModulus(message_modulus as usize),
            carry_modulus: CarryModulus(carry_modulus),
            pbs_order: params_op_order,
            noise_level: NoiseLevel::NOMINAL,
        }
    }
}
