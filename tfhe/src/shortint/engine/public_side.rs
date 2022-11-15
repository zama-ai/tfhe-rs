//! All the `ShortintEngine` method related to public side (encrypt / decrypt)
use super::{EngineResult, ShortintEngine};
use crate::core_crypto::commons::crypto::encoding::PlaintextList;
use crate::core_crypto::commons::crypto::lwe::LweSeededList;
use crate::core_crypto::commons::math::random::CompressionSeed;
use crate::core_crypto::commons::math::tensor::{AsMutTensor, AsRefTensor};
use crate::core_crypto::prelude::*;
use crate::shortint::ciphertext::Degree;
use crate::shortint::parameters::{CarryModulus, MessageModulus, Parameters};
use crate::shortint::{Ciphertext, ClientKey, CompressedPublicKey, PublicKey, ServerKey};

// We have q = 2^64 so log2q = 64
const LOG2_Q_64: usize = 64;

// Formula is (k*N + 1) * log2(q) + 128
fn public_key_zero_encryption_count(client_parameters: &Parameters) -> usize {
    (client_parameters.polynomial_size.0 * client_parameters.glwe_dimension.0 + 1) * LOG2_Q_64 + 128
}

impl ShortintEngine {
    pub(crate) fn new_public_key(&mut self, client_key: &ClientKey) -> EngineResult<PublicKey> {
        let client_parameters = client_key.parameters;

        let zero_encryption_count =
            LwePublicKeyZeroEncryptionCount(public_key_zero_encryption_count(&client_parameters));

        Ok(PublicKey {
            lwe_public_key: self.par_engine.generate_new_lwe_public_key(
                &client_key.lwe_secret_key,
                Variance(client_key.parameters.lwe_modular_std_dev.get_variance()),
                zero_encryption_count,
            )?,
            parameters: client_key.parameters.to_owned(),
        })
    }

    pub(crate) fn new_compressed_public_key(
        &mut self,
        client_key: &ClientKey,
    ) -> EngineResult<CompressedPublicKey> {
        let client_parameters = client_key.parameters;

        let zero_encryption_count = public_key_zero_encryption_count(&client_parameters);

        let seeder = self.engine.get_seedeer();

        let mut compressed_public_key: LweSeededList<Vec<u64>> = LweSeededList::allocate(
            client_key.lwe_secret_key.lwe_dimension(),
            CiphertextCount(zero_encryption_count),
            CompressionSeed {
                seed: seeder.seed(),
            },
        );

        let zeros = PlaintextList::allocate(0u64, PlaintextCount(zero_encryption_count));

        client_key
            .lwe_secret_key
            .0
            .encrypt_seeded_lwe_list::<_, _, _, _, _, ActivatedRandomGenerator>(
                &mut compressed_public_key,
                &zeros,
                client_key.parameters.lwe_modular_std_dev,
                seeder,
            );

        Ok(CompressedPublicKey {
            lwe_public_key: compressed_public_key,
            parameters: client_key.parameters.to_owned(),
        })
    }

    pub(crate) fn encrypt_with_public_key(
        &mut self,
        public_key: &PublicKey,
        server_key: &ServerKey,
        message: u64,
    ) -> EngineResult<Ciphertext> {
        let mut ciphertext = self.encrypt_with_message_modulus_and_public_key(
            public_key,
            message,
            public_key.parameters.message_modulus,
        )?;

        let acc = self.generate_accumulator(server_key, |x| x)?;

        self.programmable_bootstrap_keyswitch_assign(server_key, &mut ciphertext, &acc)?;

        Ok(ciphertext)
    }

    pub(crate) fn encrypt_with_compressed_public_key(
        &mut self,
        public_key: &CompressedPublicKey,
        server_key: &ServerKey,
        message: u64,
    ) -> EngineResult<Ciphertext> {
        let mut ciphertext = self.encrypt_with_message_modulus_and_compressed_public_key(
            public_key,
            message,
            public_key.parameters.message_modulus,
        )?;

        let acc = self.generate_accumulator(server_key, |x| x)?;

        self.programmable_bootstrap_keyswitch_assign(server_key, &mut ciphertext, &acc)?;

        Ok(ciphertext)
    }

    pub(crate) fn encrypt_with_message_modulus_and_public_key(
        &mut self,
        public_key: &PublicKey,
        message: u64,
        message_modulus: MessageModulus,
    ) -> EngineResult<Ciphertext> {
        //This ensures that the space message_modulus*carry_modulus < param.message_modulus *
        // param.carry_modulus
        let carry_modulus = (public_key.parameters.message_modulus.0
            * public_key.parameters.carry_modulus.0)
            / message_modulus.0;

        //The delta is the one defined by the parameters
        let delta = (1_u64 << 63)
            / (public_key.parameters.message_modulus.0 * public_key.parameters.carry_modulus.0)
                as u64;

        //The input is reduced modulus the message_modulus
        let m = message % message_modulus.0 as u64;

        let shifted_message = m * delta;
        // encode the message
        let plain: Plaintext64 = self.engine.create_plaintext_from(&shifted_message)?;

        // This allocates the required ct
        let mut encrypted_ct = self.engine.trivially_encrypt_lwe_ciphertext(
            public_key.lwe_public_key.lwe_dimension().to_lwe_size(),
            &plain,
        )?;

        // encryption
        self.engine.discard_encrypt_lwe_ciphertext_with_public_key(
            &public_key.lwe_public_key,
            &mut encrypted_ct,
            &plain,
        )?;

        Ok(Ciphertext {
            ct: encrypted_ct,
            degree: Degree(message_modulus.0 - 1),
            message_modulus,
            carry_modulus: CarryModulus(carry_modulus),
        })
    }

    pub(crate) fn encrypt_with_message_modulus_and_compressed_public_key(
        &mut self,
        public_key: &CompressedPublicKey,
        message: u64,
        message_modulus: MessageModulus,
    ) -> EngineResult<Ciphertext> {
        //This ensures that the space message_modulus*carry_modulus < param.message_modulus *
        // param.carry_modulus
        let carry_modulus = (public_key.parameters.message_modulus.0
            * public_key.parameters.carry_modulus.0)
            / message_modulus.0;

        //The delta is the one defined by the parameters
        let delta = (1_u64 << 63)
            / (public_key.parameters.message_modulus.0 * public_key.parameters.carry_modulus.0)
                as u64;

        //The input is reduced modulus the message_modulus
        let m = message % message_modulus.0 as u64;

        let shifted_message = m * delta;
        // encode the message
        let plain: Plaintext64 = self.engine.create_plaintext_from(&shifted_message)?;

        // This allocates the required ct
        let mut encrypted_ct = self
            .engine
            .trivially_encrypt_lwe_ciphertext(public_key.lwe_public_key.lwe_size(), &plain)?;

        // encryption
        let ct_choice = self
            .engine
            .get_secret_generator()
            .random_binary_tensor::<u64>(public_key.lwe_public_key.count().0);

        for (&chosen, public_encryption_of_zero) in ct_choice.as_container().iter().zip(
            public_key
                .lwe_public_key
                .ciphertext_iter::<_, ActivatedRandomGenerator>(),
        ) {
            if chosen == 1 {
                encrypted_ct
                    .0
                    .as_mut_tensor()
                    .update_with_wrapping_add(public_encryption_of_zero.as_tensor());
            }
        }

        Ok(Ciphertext {
            ct: encrypted_ct,
            degree: Degree(message_modulus.0 - 1),
            message_modulus,
            carry_modulus: CarryModulus(carry_modulus),
        })
    }

    pub(crate) fn encrypt_without_padding_with_public_key(
        &mut self,
        public_key: &PublicKey,
        message: u64,
    ) -> EngineResult<Ciphertext> {
        //Multiply by 2 to reshift and exclude the padding bit
        let delta = ((1_u64 << 63)
            / (public_key.parameters.message_modulus.0 * public_key.parameters.carry_modulus.0)
                as u64)
            * 2;

        let shifted_message = message * delta;
        // encode the message
        let plain: Plaintext64 = self.engine.create_plaintext_from(&shifted_message)?;

        // This allocates the required ct
        let mut encrypted_ct = self.engine.trivially_encrypt_lwe_ciphertext(
            public_key.lwe_public_key.lwe_dimension().to_lwe_size(),
            &plain,
        )?;

        // encryption
        self.engine.discard_encrypt_lwe_ciphertext_with_public_key(
            &public_key.lwe_public_key,
            &mut encrypted_ct,
            &plain,
        )?;

        Ok(Ciphertext {
            ct: encrypted_ct,
            degree: Degree(public_key.parameters.message_modulus.0 - 1),
            message_modulus: public_key.parameters.message_modulus,
            carry_modulus: public_key.parameters.carry_modulus,
        })
    }

    pub(crate) fn encrypt_native_crt_with_public_key(
        &mut self,
        public_key: &PublicKey,
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

        // This allocates the required ct
        let mut encrypted_ct = self.engine.trivially_encrypt_lwe_ciphertext(
            public_key.lwe_public_key.lwe_dimension().to_lwe_size(),
            &plain,
        )?;

        // encryption
        self.engine.discard_encrypt_lwe_ciphertext_with_public_key(
            &public_key.lwe_public_key,
            &mut encrypted_ct,
            &plain,
        )?;

        Ok(Ciphertext {
            ct: encrypted_ct,
            degree: Degree(message_modulus as usize - 1),
            message_modulus: MessageModulus(message_modulus as usize),
            carry_modulus: CarryModulus(carry_modulus),
        })
    }

    pub(crate) fn unchecked_encrypt_with_public_key(
        &mut self,
        public_key: &PublicKey,
        message: u64,
    ) -> EngineResult<Ciphertext> {
        let delta = (1_u64 << 63)
            / (public_key.parameters.message_modulus.0 * public_key.parameters.carry_modulus.0)
                as u64;
        let shifted_message = message * delta;
        // encode the message
        let plain: Plaintext64 = self.engine.create_plaintext_from(&shifted_message)?;

        // This allocates the required ct
        let mut encrypted_ct = self.engine.trivially_encrypt_lwe_ciphertext(
            public_key.lwe_public_key.lwe_dimension().to_lwe_size(),
            &plain,
        )?;

        // encryption
        self.engine.discard_encrypt_lwe_ciphertext_with_public_key(
            &public_key.lwe_public_key,
            &mut encrypted_ct,
            &plain,
        )?;

        Ok(Ciphertext {
            ct: encrypted_ct,
            degree: Degree(
                public_key.parameters.message_modulus.0 * public_key.parameters.carry_modulus.0 - 1,
            ),
            message_modulus: public_key.parameters.message_modulus,
            carry_modulus: public_key.parameters.carry_modulus,
        })
    }
}
