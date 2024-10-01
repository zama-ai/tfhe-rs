//! All the `ShortintEngine` method related to public side (encrypt / decrypt)
use super::ShortintEngine;
use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::entities::*;
use crate::shortint::ciphertext::{Degree, NoiseLevel};
use crate::shortint::parameters::{CarryModulus, MessageModulus};
use crate::shortint::{
    Ciphertext, ClientKey, CompressedPublicKey, PaddingBit, PublicKey, ShortintEncoding,
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
    pub(crate) fn new_public_key(&mut self, client_key: &ClientKey) -> PublicKey {
        let (secret_encryption_key, encryption_noise_distribution) =
            client_key.encryption_key_and_noise();

        let zero_encryption_count = shortint_public_key_zero_encryption_count(
            secret_encryption_key.lwe_dimension().to_lwe_size(),
        );

        #[cfg(any(not(feature = "__wasm_api"), feature = "parallel-wasm-api"))]
        let lwe_public_key = par_allocate_and_generate_new_lwe_public_key(
            &secret_encryption_key,
            zero_encryption_count,
            encryption_noise_distribution,
            client_key.parameters.ciphertext_modulus(),
            &mut self.encryption_generator,
        );

        #[cfg(all(feature = "__wasm_api", not(feature = "parallel-wasm-api")))]
        let lwe_public_key = allocate_and_generate_new_lwe_public_key(
            &secret_encryption_key,
            zero_encryption_count,
            encryption_noise_distribution,
            client_key.parameters.ciphertext_modulus(),
            &mut self.encryption_generator,
        );
        PublicKey {
            lwe_public_key,
            parameters: client_key.parameters,
            pbs_order: client_key.parameters.encryption_key_choice().into(),
        }
    }

    pub(crate) fn new_compressed_public_key(
        &mut self,
        client_key: &ClientKey,
    ) -> CompressedPublicKey {
        let client_parameters = client_key.parameters;

        let (secret_encryption_key, encryption_noise_distribution) =
            client_key.encryption_key_and_noise();

        let zero_encryption_count = shortint_public_key_zero_encryption_count(
            secret_encryption_key.lwe_dimension().to_lwe_size(),
        );

        #[cfg(any(not(feature = "__wasm_api"), feature = "parallel-wasm-api"))]
        let compressed_public_key = par_allocate_and_generate_new_seeded_lwe_public_key(
            &secret_encryption_key,
            zero_encryption_count,
            encryption_noise_distribution,
            client_parameters.ciphertext_modulus(),
            &mut self.seeder,
        );

        #[cfg(all(feature = "__wasm_api", not(feature = "parallel-wasm-api")))]
        let compressed_public_key = allocate_and_generate_new_seeded_lwe_public_key(
            &secret_encryption_key,
            zero_encryption_count,
            encryption_noise_distribution,
            client_parameters.ciphertext_modulus(),
            &mut self.seeder,
        );

        CompressedPublicKey {
            lwe_public_key: compressed_public_key,
            parameters: client_key.parameters,
            pbs_order: client_key.parameters.encryption_key_choice().into(),
        }
    }

    pub(crate) fn encrypt_with_public_key(
        &mut self,
        public_key: &PublicKey,
        message: u64,
    ) -> Ciphertext {
        self.encrypt_with_message_modulus_and_public_key(
            public_key,
            message,
            public_key.parameters.message_modulus(),
        )
    }

    pub(crate) fn encrypt_with_compressed_public_key(
        &mut self,
        public_key: &CompressedPublicKey,
        message: u64,
    ) -> Ciphertext {
        self.encrypt_with_message_modulus_and_compressed_public_key(
            public_key,
            message,
            public_key.parameters.message_modulus(),
        )
    }

    pub(crate) fn encrypt_many_ciphertexts_with_compressed_public_key(
        &mut self,
        public_key: &CompressedPublicKey,
        messages: impl Iterator<Item = u64>,
    ) -> Vec<Ciphertext> {
        self.encrypt_many_ciphertexts_with_message_modulus_and_compressed_public_key(
            public_key,
            messages,
            public_key.parameters.message_modulus(),
        )
    }

    pub(crate) fn encrypt_with_message_modulus_and_public_key(
        &mut self,
        public_key: &PublicKey,
        message: u64,
        message_modulus: MessageModulus,
    ) -> Ciphertext {
        // This ensures that the space message_modulus*carry_modulus < param.message_modulus *
        // param.carry_modulus
        let carry_modulus = (public_key.parameters.message_modulus().0
            * public_key.parameters.carry_modulus().0)
            / message_modulus.0;

        let m = Cleartext(message % message_modulus.0);

        let plain =
            ShortintEncoding::from_parameters(public_key.parameters, PaddingBit::Yes).encode(m);

        // This allocates the required ct
        let mut encrypted_ct = LweCiphertextOwned::new(
            0u64,
            public_key.lwe_public_key.lwe_size(),
            public_key.lwe_public_key.ciphertext_modulus(),
        );

        encrypt_lwe_ciphertext_with_public_key(
            &public_key.lwe_public_key,
            &mut encrypted_ct,
            plain,
            &mut self.secret_generator,
        );

        Ciphertext::new(
            encrypted_ct,
            Degree::new(message_modulus.0 - 1),
            NoiseLevel::NOMINAL,
            message_modulus,
            CarryModulus(carry_modulus),
            public_key.pbs_order,
        )
    }

    pub(crate) fn encrypt_with_message_modulus_and_compressed_public_key(
        &mut self,
        public_key: &CompressedPublicKey,
        message: u64,
        message_modulus: MessageModulus,
    ) -> Ciphertext {
        self.encrypt_many_ciphertexts_with_message_modulus_and_compressed_public_key(
            public_key,
            std::iter::once(message),
            message_modulus,
        )
        .into_iter()
        .next()
        .unwrap()
    }

    pub(crate) fn encrypt_many_ciphertexts_with_message_modulus_and_compressed_public_key(
        &mut self,
        public_key: &CompressedPublicKey,
        messages: impl Iterator<Item = u64>,
        message_modulus: MessageModulus,
    ) -> Vec<Ciphertext> {
        // This ensures that the space message_modulus*carry_modulus < param.message_modulus *
        // param.carry_modulus
        let carry_modulus = (public_key.parameters.message_modulus().0
            * public_key.parameters.carry_modulus().0)
            / message_modulus.0;

        let encoded: Vec<_> = messages
            .into_iter()
            .map(move |message| {
                let m = message % message_modulus.0;

                ShortintEncoding::from_parameters(public_key.parameters, PaddingBit::Yes)
                    .encode(Cleartext(m))
            })
            .collect();

        // This allocates the required ct
        let mut encrypted_ct = vec![
            LweCiphertext::new(
                0u64,
                public_key.lwe_public_key.lwe_size(),
                public_key.lwe_public_key.ciphertext_modulus(),
            );
            encoded.len()
        ];

        encrypt_lwe_ciphertext_iterator_with_seeded_public_key(
            &public_key.lwe_public_key,
            encrypted_ct.iter_mut().map(|lwe| lwe.as_mut_view()),
            encoded,
            &mut self.secret_generator,
        );

        encrypted_ct
            .into_iter()
            .map(|lwe| {
                Ciphertext::new(
                    lwe,
                    Degree::new(message_modulus.0 - 1),
                    NoiseLevel::NOMINAL,
                    message_modulus,
                    CarryModulus(carry_modulus),
                    public_key.pbs_order,
                )
            })
            .collect()
    }

    pub(crate) fn encrypt_with_many_message_moduli_and_compressed_public_key(
        &mut self,
        public_key: &CompressedPublicKey,
        message: u64,
        message_moduli: impl Iterator<Item = MessageModulus>,
    ) -> Vec<Ciphertext> {
        let (encoded, moduli): (Vec<_>, Vec<_>) = message_moduli
            .map(|message_modulus| {
                //This ensures that the space message_modulus*carry_modulus < param.message_modulus
                // * param.carry_modulus
                let carry_modulus = CarryModulus(
                    (public_key.parameters.message_modulus().0
                        * public_key.parameters.carry_modulus().0)
                        / message_modulus.0,
                );

                let m = message % message_modulus.0;

                let encoded =
                    ShortintEncoding::from_parameters(public_key.parameters, PaddingBit::Yes)
                        .encode(Cleartext(m));

                (encoded, (message_modulus, carry_modulus))
            })
            .unzip();

        // This allocates the required ct
        let mut encrypted_ct = vec![
            LweCiphertext::new(
                0u64,
                public_key.lwe_public_key.lwe_size(),
                public_key.lwe_public_key.ciphertext_modulus(),
            );
            encoded.len()
        ];

        encrypt_lwe_ciphertext_iterator_with_seeded_public_key(
            &public_key.lwe_public_key,
            encrypted_ct.iter_mut().map(|lwe| lwe.as_mut_view()),
            encoded,
            &mut self.secret_generator,
        );

        encrypted_ct
            .into_iter()
            .zip(moduli)
            .map(|(lwe, (message_modulus, carry_modulus))| {
                Ciphertext::new(
                    lwe,
                    Degree::new(message_modulus.0 - 1),
                    NoiseLevel::NOMINAL,
                    message_modulus,
                    carry_modulus,
                    public_key.pbs_order,
                )
            })
            .collect()
    }

    pub(crate) fn encrypt_without_padding_with_public_key(
        &mut self,
        public_key: &PublicKey,
        message: u64,
    ) -> Ciphertext {
        let plain = ShortintEncoding::from_parameters(public_key.parameters, PaddingBit::No)
            .encode(Cleartext(message));

        // This allocates the required ct
        let mut encrypted_ct = LweCiphertextOwned::new(
            0u64,
            public_key.lwe_public_key.lwe_size(),
            public_key.lwe_public_key.ciphertext_modulus(),
        );

        encrypt_lwe_ciphertext_with_public_key(
            &public_key.lwe_public_key,
            &mut encrypted_ct,
            plain,
            &mut self.secret_generator,
        );

        Ciphertext::new(
            encrypted_ct,
            Degree::new(public_key.parameters.message_modulus().0 - 1),
            NoiseLevel::NOMINAL,
            public_key.parameters.message_modulus(),
            public_key.parameters.carry_modulus(),
            public_key.pbs_order,
        )
    }

    pub(crate) fn encrypt_without_padding_with_compressed_public_key(
        &mut self,
        public_key: &CompressedPublicKey,
        message: u64,
    ) -> Ciphertext {
        self.encrypt_many_ciphertexts_without_padding_with_compressed_public_key(
            public_key,
            std::iter::once(message),
        )
        .into_iter()
        .next()
        .unwrap()
    }

    pub(crate) fn encrypt_many_ciphertexts_without_padding_with_compressed_public_key(
        &mut self,
        public_key: &CompressedPublicKey,
        messages: impl Iterator<Item = u64>,
    ) -> Vec<Ciphertext> {
        let encoded: Vec<_> = messages
            .map(|message| {
                ShortintEncoding::from_parameters(public_key.parameters, PaddingBit::No)
                    .encode(Cleartext(message))
            })
            .collect();

        // This allocates the required ct
        let mut encrypted_ct = vec![
            LweCiphertextOwned::new(
                0u64,
                public_key.lwe_public_key.lwe_size(),
                public_key.lwe_public_key.ciphertext_modulus(),
            );
            encoded.len()
        ];

        encrypt_lwe_ciphertext_iterator_with_seeded_public_key(
            &public_key.lwe_public_key,
            encrypted_ct.iter_mut().map(|lwe| lwe.as_mut_view()),
            encoded,
            &mut self.secret_generator,
        );

        encrypted_ct
            .into_iter()
            .map(|lwe| {
                Ciphertext::new(
                    lwe,
                    Degree::new(public_key.parameters.message_modulus().0 - 1),
                    NoiseLevel::NOMINAL,
                    public_key.parameters.message_modulus(),
                    public_key.parameters.carry_modulus(),
                    public_key.pbs_order,
                )
            })
            .collect()
    }

    pub(crate) fn encrypt_native_crt_with_public_key(
        &mut self,
        public_key: &PublicKey,
        message: u64,
        message_modulus: MessageModulus,
    ) -> Ciphertext {
        let carry_modulus = CarryModulus(1);
        let m = (message % message_modulus.0) as u128;
        let shifted_message = m * (1 << 64) / message_modulus.0 as u128;
        // encode the message

        let plain = Plaintext(shifted_message as u64);

        // This allocates the required ct
        let mut encrypted_ct = LweCiphertextOwned::new(
            0u64,
            public_key.lwe_public_key.lwe_size(),
            public_key.lwe_public_key.ciphertext_modulus(),
        );

        encrypt_lwe_ciphertext_with_public_key(
            &public_key.lwe_public_key,
            &mut encrypted_ct,
            plain,
            &mut self.secret_generator,
        );

        Ciphertext::new(
            encrypted_ct,
            Degree::new(message_modulus.0 - 1),
            NoiseLevel::NOMINAL,
            message_modulus,
            carry_modulus,
            public_key.pbs_order,
        )
    }

    pub(crate) fn encrypt_native_crt_with_compressed_public_key(
        &mut self,
        public_key: &CompressedPublicKey,
        message: u64,
        message_modulus: MessageModulus,
    ) -> Ciphertext {
        let carry_modulus = CarryModulus(1);
        let m = (message % message_modulus.0) as u128;
        let shifted_message = m * (1 << 64) / message_modulus.0 as u128;
        // encode the message

        let plain = Plaintext(shifted_message as u64);

        // This allocates the required ct
        let mut encrypted_ct = LweCiphertextOwned::new(
            0u64,
            public_key.lwe_public_key.lwe_size(),
            public_key.lwe_public_key.ciphertext_modulus(),
        );

        encrypt_lwe_ciphertext_with_seeded_public_key(
            &public_key.lwe_public_key,
            &mut encrypted_ct,
            plain,
            &mut self.secret_generator,
        );

        Ciphertext::new(
            encrypted_ct,
            Degree::new(message_modulus.0 - 1),
            NoiseLevel::NOMINAL,
            message_modulus,
            carry_modulus,
            public_key.pbs_order,
        )
    }

    pub(crate) fn encrypt_native_crt_with_many_message_moduli_and_compressed_public_key(
        &mut self,
        public_key: &CompressedPublicKey,
        message: u64,
        message_moduli: impl Iterator<Item = MessageModulus>,
    ) -> Vec<Ciphertext> {
        let carry_modulus = CarryModulus(1);

        let (encoded, message_moduli): (Vec<_>, Vec<_>) = message_moduli
            .map(|message_modulus| {
                let m = (message % message_modulus.0) as u128;
                let shifted_message = m * (1 << 64) / message_modulus.0 as u128;
                // encode the message

                (Plaintext(shifted_message as u64), message_modulus)
            })
            .unzip();

        // This allocates the required ct
        let mut encrypted_ct = vec![
            LweCiphertext::new(
                0u64,
                public_key.lwe_public_key.lwe_size(),
                public_key.lwe_public_key.ciphertext_modulus(),
            );
            encoded.len()
        ];

        encrypt_lwe_ciphertext_iterator_with_seeded_public_key(
            &public_key.lwe_public_key,
            encrypted_ct.iter_mut().map(|lwe| lwe.as_mut_view()),
            encoded,
            &mut self.secret_generator,
        );

        encrypted_ct
            .into_iter()
            .zip(message_moduli)
            .map(|(lwe, message_modulus)| {
                Ciphertext::new(
                    lwe,
                    Degree::new(message_modulus.0 - 1),
                    NoiseLevel::NOMINAL,
                    message_modulus,
                    carry_modulus,
                    public_key.pbs_order,
                )
            })
            .collect()
    }

    pub(crate) fn unchecked_encrypt_with_public_key(
        &mut self,
        public_key: &PublicKey,
        message: u64,
    ) -> Ciphertext {
        let plain = ShortintEncoding::from_parameters(public_key.parameters, PaddingBit::Yes)
            .encode(Cleartext(message));

        // This allocates the required ct
        let mut encrypted_ct = LweCiphertextOwned::new(
            0u64,
            public_key.lwe_public_key.lwe_size(),
            public_key.lwe_public_key.ciphertext_modulus(),
        );

        encrypt_lwe_ciphertext_with_public_key(
            &public_key.lwe_public_key,
            &mut encrypted_ct,
            plain,
            &mut self.secret_generator,
        );

        Ciphertext::new(
            encrypted_ct,
            Degree::new(
                public_key.parameters.message_modulus().0 * public_key.parameters.carry_modulus().0
                    - 1,
            ),
            NoiseLevel::NOMINAL,
            public_key.parameters.message_modulus(),
            public_key.parameters.carry_modulus(),
            public_key.pbs_order,
        )
    }

    pub(crate) fn unchecked_encrypt_with_compressed_public_key(
        &mut self,
        public_key: &CompressedPublicKey,
        message: u64,
    ) -> Ciphertext {
        let plain = ShortintEncoding::from_parameters(public_key.parameters, PaddingBit::Yes)
            .encode(Cleartext(message));

        // This allocates the required ct
        let mut encrypted_ct = LweCiphertextOwned::new(
            0u64,
            public_key.lwe_public_key.lwe_size(),
            public_key.lwe_public_key.ciphertext_modulus(),
        );

        encrypt_lwe_ciphertext_with_seeded_public_key(
            &public_key.lwe_public_key,
            &mut encrypted_ct,
            plain,
            &mut self.secret_generator,
        );

        Ciphertext::new(
            encrypted_ct,
            Degree::new(
                public_key.parameters.message_modulus().0 * public_key.parameters.carry_modulus().0
                    - 1,
            ),
            NoiseLevel::NOMINAL,
            public_key.parameters.message_modulus(),
            public_key.parameters.carry_modulus(),
            public_key.pbs_order,
        )
    }
}
