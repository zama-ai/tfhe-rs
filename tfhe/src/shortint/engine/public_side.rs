//! All the `ShortintEngine` method related to public side (encrypt / decrypt)
use super::{EngineResult, ShortintEngine};
use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::entities::*;
use crate::shortint::ciphertext::Degree;
use crate::shortint::parameters::{CarryModulus, MessageModulus};
use crate::shortint::{
    CiphertextBase, ClientKey, CompressedPublicKeyBase, PBSOrderMarker, PublicKeyBase,
};

// We have q = 2^64 so log2q = 64
const LOG2_Q_64: usize = 64;

pub fn shortint_public_key_zero_encryption_count(
    pk_lwe_size: LweSize,
) -> LwePublicKeyZeroEncryptionCount {
    // Formula is (n + 1) * log2(q) + 128
    // or in the case of a GLWE secret key reinterpreted as an LWE secret key
    // (k*N + 1) * log2(q) + 128
    LwePublicKeyZeroEncryptionCount(pk_lwe_size.0 * LOG2_Q_64 + 128)
}

impl ShortintEngine {
    pub(crate) fn new_public_key<OpOrder: PBSOrderMarker>(
        &mut self,
        client_key: &ClientKey<OpOrder>,
    ) -> EngineResult<PublicKeyBase<OpOrder>> {
        let client_parameters = client_key.parameters;

        let (secret_encryption_key, encryption_noise) = match OpOrder::pbs_order() {
            crate::shortint::PBSOrder::KeyswitchBootstrap => (
                &client_key.large_lwe_secret_key,
                client_parameters.glwe_modular_std_dev,
            ),
            crate::shortint::PBSOrder::BootstrapKeyswitch => (
                &client_key.small_lwe_secret_key,
                client_parameters.lwe_modular_std_dev,
            ),
        };

        let zero_encryption_count = shortint_public_key_zero_encryption_count(
            secret_encryption_key.lwe_dimension().to_lwe_size(),
        );

        #[cfg(not(feature = "__wasm_api"))]
        let lwe_public_key = par_allocate_and_generate_new_lwe_public_key(
            secret_encryption_key,
            zero_encryption_count,
            encryption_noise,
            &mut self.encryption_generator,
        );

        #[cfg(feature = "__wasm_api")]
        let lwe_public_key = allocate_and_generate_new_lwe_public_key(
            secret_encryption_key,
            zero_encryption_count,
            encryption_noise,
            &mut self.encryption_generator,
        );

        Ok(PublicKeyBase {
            lwe_public_key,
            parameters: client_key.parameters.to_owned(),
        })
    }

    pub(crate) fn new_compressed_public_key<OpOrder: PBSOrderMarker>(
        &mut self,
        client_key: &ClientKey<OpOrder>,
    ) -> EngineResult<CompressedPublicKeyBase<OpOrder>> {
        let client_parameters = client_key.parameters;

        let (secret_encryption_key, encryption_noise) = match OpOrder::pbs_order() {
            crate::shortint::PBSOrder::KeyswitchBootstrap => (
                &client_key.large_lwe_secret_key,
                client_parameters.glwe_modular_std_dev,
            ),
            crate::shortint::PBSOrder::BootstrapKeyswitch => (
                &client_key.small_lwe_secret_key,
                client_parameters.lwe_modular_std_dev,
            ),
        };

        let zero_encryption_count = shortint_public_key_zero_encryption_count(
            secret_encryption_key.lwe_dimension().to_lwe_size(),
        );

        #[cfg(not(feature = "__wasm_api"))]
        let compressed_public_key = par_allocate_and_generate_new_seeded_lwe_public_key(
            secret_encryption_key,
            zero_encryption_count,
            encryption_noise,
            &mut self.seeder,
        );

        #[cfg(feature = "__wasm_api")]
        let compressed_public_key = allocate_and_generate_new_seeded_lwe_public_key(
            secret_encryption_key,
            zero_encryption_count,
            encryption_noise,
            &mut self.seeder,
        );

        Ok(CompressedPublicKeyBase {
            lwe_public_key: compressed_public_key,
            parameters: client_key.parameters.to_owned(),
        })
    }

    pub(crate) fn encrypt_with_public_key<OpOrder: PBSOrderMarker>(
        &mut self,
        public_key: &PublicKeyBase<OpOrder>,
        message: u64,
    ) -> EngineResult<CiphertextBase<OpOrder>> {
        let ciphertext = self.encrypt_with_message_modulus_and_public_key(
            public_key,
            message,
            public_key.parameters.message_modulus,
        )?;

        Ok(ciphertext)
    }

    pub(crate) fn encrypt_with_compressed_public_key<OpOrder: PBSOrderMarker>(
        &mut self,
        public_key: &CompressedPublicKeyBase<OpOrder>,
        message: u64,
    ) -> EngineResult<CiphertextBase<OpOrder>> {
        let ciphertext = self.encrypt_with_message_modulus_and_compressed_public_key(
            public_key,
            message,
            public_key.parameters.message_modulus,
        )?;

        Ok(ciphertext)
    }

    pub(crate) fn encrypt_with_message_modulus_and_public_key<OpOrder: PBSOrderMarker>(
        &mut self,
        public_key: &PublicKeyBase<OpOrder>,
        message: u64,
        message_modulus: MessageModulus,
    ) -> EngineResult<CiphertextBase<OpOrder>> {
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
        let plain = Plaintext(shifted_message);

        // This allocates the required ct
        let mut encrypted_ct = LweCiphertextOwned::new(0u64, public_key.lwe_public_key.lwe_size());

        encrypt_lwe_ciphertext_with_public_key(
            &public_key.lwe_public_key,
            &mut encrypted_ct,
            plain,
            &mut self.secret_generator,
        );

        Ok(CiphertextBase {
            ct: encrypted_ct,
            degree: Degree(message_modulus.0 - 1),
            message_modulus,
            carry_modulus: CarryModulus(carry_modulus),
            _order_marker: Default::default(),
        })
    }

    pub(crate) fn encrypt_with_message_modulus_and_compressed_public_key<
        OpOrder: PBSOrderMarker,
    >(
        &mut self,
        public_key: &CompressedPublicKeyBase<OpOrder>,
        message: u64,
        message_modulus: MessageModulus,
    ) -> EngineResult<CiphertextBase<OpOrder>> {
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
        let plain = Plaintext(shifted_message);

        // This allocates the required ct
        let mut encrypted_ct = LweCiphertext::new(0u64, public_key.lwe_public_key.lwe_size());

        // encryption
        encrypt_lwe_ciphertext_with_seeded_public_key(
            &public_key.lwe_public_key,
            &mut encrypted_ct,
            plain,
            &mut self.secret_generator,
        );

        Ok(CiphertextBase {
            ct: encrypted_ct,
            degree: Degree(message_modulus.0 - 1),
            message_modulus,
            carry_modulus: CarryModulus(carry_modulus),
            _order_marker: Default::default(),
        })
    }

    pub(crate) fn encrypt_without_padding_with_public_key<OpOrder: PBSOrderMarker>(
        &mut self,
        public_key: &PublicKeyBase<OpOrder>,
        message: u64,
    ) -> EngineResult<CiphertextBase<OpOrder>> {
        //Multiply by 2 to reshift and exclude the padding bit
        let delta = ((1_u64 << 63)
            / (public_key.parameters.message_modulus.0 * public_key.parameters.carry_modulus.0)
                as u64)
            * 2;

        let shifted_message = message * delta;
        // encode the message
        let plain = Plaintext(shifted_message);

        // This allocates the required ct
        let mut encrypted_ct = LweCiphertextOwned::new(0u64, public_key.lwe_public_key.lwe_size());

        // encryption
        encrypt_lwe_ciphertext_with_public_key(
            &public_key.lwe_public_key,
            &mut encrypted_ct,
            plain,
            &mut self.secret_generator,
        );

        Ok(CiphertextBase {
            ct: encrypted_ct,
            degree: Degree(public_key.parameters.message_modulus.0 - 1),
            message_modulus: public_key.parameters.message_modulus,
            carry_modulus: public_key.parameters.carry_modulus,
            _order_marker: Default::default(),
        })
    }

    pub(crate) fn encrypt_without_padding_with_compressed_public_key<OpOrder: PBSOrderMarker>(
        &mut self,
        public_key: &CompressedPublicKeyBase<OpOrder>,
        message: u64,
    ) -> EngineResult<CiphertextBase<OpOrder>> {
        //Multiply by 2 to reshift and exclude the padding bit
        let delta = ((1_u64 << 63)
            / (public_key.parameters.message_modulus.0 * public_key.parameters.carry_modulus.0)
                as u64)
            * 2;

        let shifted_message = message * delta;
        // encode the message
        let plain = Plaintext(shifted_message);

        // This allocates the required ct
        let mut encrypted_ct = LweCiphertextOwned::new(0u64, public_key.lwe_public_key.lwe_size());

        // encryption
        encrypt_lwe_ciphertext_with_seeded_public_key(
            &public_key.lwe_public_key,
            &mut encrypted_ct,
            plain,
            &mut self.secret_generator,
        );

        Ok(CiphertextBase {
            ct: encrypted_ct,
            degree: Degree(public_key.parameters.message_modulus.0 - 1),
            message_modulus: public_key.parameters.message_modulus,
            carry_modulus: public_key.parameters.carry_modulus,
            _order_marker: Default::default(),
        })
    }

    pub(crate) fn encrypt_native_crt_with_public_key<OpOrder: PBSOrderMarker>(
        &mut self,
        public_key: &PublicKeyBase<OpOrder>,
        message: u64,
        message_modulus: u8,
    ) -> EngineResult<CiphertextBase<OpOrder>> {
        let carry_modulus = 1;
        let m = (message % message_modulus as u64) as u128;
        let shifted_message = m * (1 << 64) / message_modulus as u128;
        // encode the message

        let plain = Plaintext(shifted_message as u64);

        // This allocates the required ct
        let mut encrypted_ct = LweCiphertextOwned::new(0u64, public_key.lwe_public_key.lwe_size());

        encrypt_lwe_ciphertext_with_public_key(
            &public_key.lwe_public_key,
            &mut encrypted_ct,
            plain,
            &mut self.secret_generator,
        );

        Ok(CiphertextBase {
            ct: encrypted_ct,
            degree: Degree(message_modulus as usize - 1),
            message_modulus: MessageModulus(message_modulus as usize),
            carry_modulus: CarryModulus(carry_modulus),
            _order_marker: Default::default(),
        })
    }

    pub(crate) fn encrypt_native_crt_with_compressed_public_key<OpOrder: PBSOrderMarker>(
        &mut self,
        public_key: &CompressedPublicKeyBase<OpOrder>,
        message: u64,
        message_modulus: u8,
    ) -> EngineResult<CiphertextBase<OpOrder>> {
        let carry_modulus = 1;
        let m = (message % message_modulus as u64) as u128;
        let shifted_message = m * (1 << 64) / message_modulus as u128;
        // encode the message

        let plain = Plaintext(shifted_message as u64);

        // This allocates the required ct
        let mut encrypted_ct = LweCiphertextOwned::new(0u64, public_key.lwe_public_key.lwe_size());

        encrypt_lwe_ciphertext_with_seeded_public_key(
            &public_key.lwe_public_key,
            &mut encrypted_ct,
            plain,
            &mut self.secret_generator,
        );

        Ok(CiphertextBase {
            ct: encrypted_ct,
            degree: Degree(message_modulus as usize - 1),
            message_modulus: MessageModulus(message_modulus as usize),
            carry_modulus: CarryModulus(carry_modulus),
            _order_marker: Default::default(),
        })
    }

    pub(crate) fn unchecked_encrypt_with_public_key<OpOrder: PBSOrderMarker>(
        &mut self,
        public_key: &PublicKeyBase<OpOrder>,
        message: u64,
    ) -> EngineResult<CiphertextBase<OpOrder>> {
        let delta = (1_u64 << 63)
            / (public_key.parameters.message_modulus.0 * public_key.parameters.carry_modulus.0)
                as u64;
        let shifted_message = message * delta;
        // encode the message
        let plain = Plaintext(shifted_message);

        // This allocates the required ct
        let mut encrypted_ct = LweCiphertextOwned::new(0u64, public_key.lwe_public_key.lwe_size());

        encrypt_lwe_ciphertext_with_public_key(
            &public_key.lwe_public_key,
            &mut encrypted_ct,
            plain,
            &mut self.secret_generator,
        );

        Ok(CiphertextBase {
            ct: encrypted_ct,
            degree: Degree(
                public_key.parameters.message_modulus.0 * public_key.parameters.carry_modulus.0 - 1,
            ),
            message_modulus: public_key.parameters.message_modulus,
            carry_modulus: public_key.parameters.carry_modulus,
            _order_marker: Default::default(),
        })
    }

    pub(crate) fn unchecked_encrypt_with_compressed_public_key<OpOrder: PBSOrderMarker>(
        &mut self,
        public_key: &CompressedPublicKeyBase<OpOrder>,
        message: u64,
    ) -> EngineResult<CiphertextBase<OpOrder>> {
        let delta = (1_u64 << 63)
            / (public_key.parameters.message_modulus.0 * public_key.parameters.carry_modulus.0)
                as u64;
        let shifted_message = message * delta;
        // encode the message
        let plain = Plaintext(shifted_message);

        // This allocates the required ct
        let mut encrypted_ct = LweCiphertextOwned::new(0u64, public_key.lwe_public_key.lwe_size());

        encrypt_lwe_ciphertext_with_seeded_public_key(
            &public_key.lwe_public_key,
            &mut encrypted_ct,
            plain,
            &mut self.secret_generator,
        );

        Ok(CiphertextBase {
            ct: encrypted_ct,
            degree: Degree(
                public_key.parameters.message_modulus.0 * public_key.parameters.carry_modulus.0 - 1,
            ),
            message_modulus: public_key.parameters.message_modulus,
            carry_modulus: public_key.parameters.carry_modulus,
            _order_marker: Default::default(),
        })
    }
}
