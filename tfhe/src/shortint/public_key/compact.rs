#[cfg(feature = "zk-pok-experimental")]
use crate::core_crypto::algorithms::encrypt_and_prove_lwe_ciphertext_with_compact_public_key;
#[cfg(feature = "zk-pok-experimental")]
use crate::core_crypto::entities::Cleartext;
use crate::core_crypto::prelude::{
    allocate_and_generate_new_seeded_lwe_compact_public_key,
    encrypt_lwe_ciphertext_with_compact_public_key, generate_lwe_compact_public_key,
    LweCiphertextCount, LweCiphertextOwned, LweCompactCiphertextListOwned,
    LweCompactPublicKeyOwned, Plaintext, PlaintextList, SeededLweCompactPublicKeyOwned,
};
use crate::shortint::ciphertext::{CompactCiphertextList, Degree, NoiseLevel};
#[cfg(feature = "zk-pok-experimental")]
use crate::shortint::ciphertext::{ProvenCiphertext, ProvenCompactCiphertextList};
use crate::shortint::engine::ShortintEngine;
use crate::shortint::{Ciphertext, ClientKey, PBSOrder, ShortintParameterSet};
#[cfg(feature = "zk-pok-experimental")]
use crate::zk::{CompactPkePublicParams, ZkComputeLoad};
use serde::{Deserialize, Serialize};
use std::iter::once;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CompactPublicKey {
    pub(crate) key: LweCompactPublicKeyOwned<u64>,
    pub parameters: ShortintParameterSet,
    pub pbs_order: PBSOrder,
}

fn to_plaintext_iterator(
    message_iter: impl Iterator<Item = u64>,
    parameters: &ShortintParameterSet,
) -> impl Iterator<Item = Plaintext<u64>> {
    let message_modulus = parameters.message_modulus().0 as u64;
    let carry_modulus = parameters.carry_modulus().0 as u64;
    message_iter.map(move |message| {
        //The delta is the one defined by the parameters
        let delta = (1_u64 << 63) / (message_modulus * carry_modulus);

        //The input is reduced modulus the message_modulus
        let m = message % message_modulus;

        let shifted_message = m * delta;
        // encode the message
        Plaintext(shifted_message)
    })
}

impl CompactPublicKey {
    pub fn new(client_key: &ClientKey) -> Self {
        Self::try_new(client_key).expect(
            "Incompatible parameters, the lwe_dimension of the secret key must be a power of two",
        )
    }

    pub fn try_new(client_key: &ClientKey) -> Option<Self> {
        let parameters = client_key.parameters;
        let (secret_encryption_key, encryption_noise_distribution) =
            match client_key.parameters.encryption_key_choice().into() {
                crate::shortint::PBSOrder::KeyswitchBootstrap => (
                    client_key.large_lwe_secret_key(),
                    parameters.glwe_noise_distribution(),
                ),
                crate::shortint::PBSOrder::BootstrapKeyswitch => (
                    client_key.small_lwe_secret_key(),
                    parameters.lwe_noise_distribution(),
                ),
            };

        if !secret_encryption_key.lwe_dimension().0.is_power_of_two() {
            return None;
        }

        let mut key = LweCompactPublicKeyOwned::new(
            0u64,
            secret_encryption_key.lwe_dimension(),
            parameters.ciphertext_modulus(),
        );
        ShortintEngine::with_thread_local_mut(|engine| {
            generate_lwe_compact_public_key(
                &secret_encryption_key,
                &mut key,
                encryption_noise_distribution,
                &mut engine.encryption_generator,
            );
        });

        Some(Self {
            key,
            parameters,
            pbs_order: client_key.parameters.encryption_key_choice().into(),
        })
    }

    /// Deconstruct a [`CompactPublicKey`] into its constituents.
    pub fn into_raw_parts(
        self,
    ) -> (
        LweCompactPublicKeyOwned<u64>,
        ShortintParameterSet,
        PBSOrder,
    ) {
        let Self {
            key,
            parameters,
            pbs_order,
        } = self;

        (key, parameters, pbs_order)
    }

    /// Construct a [`CompactPublicKey`] from its constituents.
    ///
    /// # Panics
    ///
    /// Panics if the constituents are not compatible with each others.
    pub fn from_raw_parts(
        key: LweCompactPublicKeyOwned<u64>,
        parameters: ShortintParameterSet,
        pbs_order: PBSOrder,
    ) -> Self {
        let expected_pbs_order: PBSOrder = parameters.encryption_key_choice().into();

        assert_eq!(
            pbs_order, expected_pbs_order,
            "Mismatch between expected PBSOrder ({expected_pbs_order:?}) and \
            provided PBSOrder ({pbs_order:?})"
        );

        let ciphertext_lwe_dimension = match pbs_order {
            PBSOrder::KeyswitchBootstrap => parameters
                .glwe_dimension()
                .to_equivalent_lwe_dimension(parameters.polynomial_size()),
            PBSOrder::BootstrapKeyswitch => parameters.lwe_dimension(),
        };

        assert_eq!(
            key.lwe_dimension(),
            ciphertext_lwe_dimension,
            "Mismatch between the LweCompactPublicKey LweDimension ({:?}) and \
            the provided parameters LweDimension ({:?})",
            key.lwe_dimension(),
            ciphertext_lwe_dimension,
        );

        assert_eq!(
            key.ciphertext_modulus(),
            parameters.ciphertext_modulus(),
            "Mismatch between the LweCompactPublicKey CiphertextModulus ({:?}) and \
            the provided parameters CiphertextModulus ({:?})",
            key.ciphertext_modulus(),
            parameters.ciphertext_modulus(),
        );

        Self {
            key,
            parameters,
            pbs_order,
        }
    }

    pub fn encrypt(&self, message: u64) -> Ciphertext {
        let plain = to_plaintext_iterator(once(message), &self.parameters)
            .next()
            .unwrap();

        // This allocates the required ct
        let mut encrypted_ct = LweCiphertextOwned::new(
            0u64,
            self.key.lwe_dimension().to_lwe_size(),
            self.parameters.ciphertext_modulus(),
        );

        let encryption_noise_distribution = match self.pbs_order {
            PBSOrder::KeyswitchBootstrap => self.parameters.glwe_noise_distribution(),
            PBSOrder::BootstrapKeyswitch => self.parameters.lwe_noise_distribution(),
        };

        ShortintEngine::with_thread_local_mut(|engine| {
            encrypt_lwe_ciphertext_with_compact_public_key(
                &self.key,
                &mut encrypted_ct,
                plain,
                encryption_noise_distribution,
                encryption_noise_distribution,
                &mut engine.secret_generator,
                &mut engine.encryption_generator,
            );
        });

        let message_modulus = self.parameters.message_modulus();
        Ciphertext::new(
            encrypted_ct,
            Degree::new(message_modulus.0 - 1),
            NoiseLevel::NOMINAL,
            message_modulus,
            self.parameters.carry_modulus(),
            self.pbs_order,
        )
    }

    #[cfg(feature = "zk-pok-experimental")]
    pub fn encrypt_and_prove(
        &self,
        message: u64,
        public_params: &CompactPkePublicParams,
        load: ZkComputeLoad,
    ) -> crate::Result<ProvenCiphertext> {
        // This allocates the required ct
        let mut encrypted_ct = LweCiphertextOwned::new(
            0u64,
            self.key.lwe_dimension().to_lwe_size(),
            self.parameters.ciphertext_modulus(),
        );

        let encryption_noise_distribution = match self.pbs_order {
            PBSOrder::KeyswitchBootstrap => self.parameters.glwe_noise_distribution(),
            PBSOrder::BootstrapKeyswitch => self.parameters.lwe_noise_distribution(),
        };

        let plaintext_modulus =
            (self.parameters.message_modulus().0 * self.parameters.carry_modulus().0) as u64;
        let delta = (1u64 << 63) / plaintext_modulus;

        let proof = ShortintEngine::with_thread_local_mut(|engine| {
            encrypt_and_prove_lwe_ciphertext_with_compact_public_key(
                &self.key,
                &mut encrypted_ct,
                Cleartext(message),
                delta,
                encryption_noise_distribution,
                encryption_noise_distribution,
                &mut engine.secret_generator,
                &mut engine.encryption_generator,
                &mut engine.random_generator,
                public_params,
                load,
            )
        })?;

        let message_modulus = self.parameters.message_modulus();
        let ciphertext = Ciphertext::new(
            encrypted_ct,
            Degree::new(message_modulus.0 - 1),
            NoiseLevel::NOMINAL,
            message_modulus,
            self.parameters.carry_modulus(),
            self.pbs_order,
        );

        Ok(ProvenCiphertext { ciphertext, proof })
    }

    pub fn encrypt_slice(&self, messages: &[u64]) -> CompactCiphertextList {
        self.encrypt_iter(messages.iter().copied())
    }

    pub fn encrypt_iter(&self, messages: impl Iterator<Item = u64>) -> CompactCiphertextList {
        let plaintext_container = to_plaintext_iterator(messages, &self.parameters)
            .map(|plaintext| plaintext.0)
            .collect::<Vec<_>>();

        let plaintext_list = PlaintextList::from_container(plaintext_container);
        let mut ct_list = LweCompactCiphertextListOwned::new(
            0u64,
            self.key.lwe_dimension().to_lwe_size(),
            LweCiphertextCount(plaintext_list.plaintext_count().0),
            self.parameters.ciphertext_modulus(),
        );

        let encryption_noise_distribution = match self.pbs_order {
            PBSOrder::KeyswitchBootstrap => self.parameters.glwe_noise_distribution(),
            PBSOrder::BootstrapKeyswitch => self.parameters.lwe_noise_distribution(),
        };

        // No parallelism allowed
        #[cfg(all(feature = "__wasm_api", not(feature = "parallel-wasm-api")))]
        {
            use crate::core_crypto::prelude::encrypt_lwe_compact_ciphertext_list_with_compact_public_key;
            ShortintEngine::with_thread_local_mut(|engine| {
                encrypt_lwe_compact_ciphertext_list_with_compact_public_key(
                    &self.key,
                    &mut ct_list,
                    &plaintext_list,
                    encryption_noise_distribution,
                    encryption_noise_distribution,
                    &mut engine.secret_generator,
                    &mut engine.encryption_generator,
                );
            });
        }

        // Parallelism allowed
        #[cfg(any(not(feature = "__wasm_api"), feature = "parallel-wasm-api"))]
        {
            use crate::core_crypto::prelude::par_encrypt_lwe_compact_ciphertext_list_with_compact_public_key;
            ShortintEngine::with_thread_local_mut(|engine| {
                par_encrypt_lwe_compact_ciphertext_list_with_compact_public_key(
                    &self.key,
                    &mut ct_list,
                    &plaintext_list,
                    encryption_noise_distribution,
                    encryption_noise_distribution,
                    &mut engine.secret_generator,
                    &mut engine.encryption_generator,
                );
            });
        }

        let message_modulus = self.parameters.message_modulus();
        CompactCiphertextList {
            ct_list,
            degree: Degree::new(message_modulus.0 - 1),
            message_modulus,
            carry_modulus: self.parameters.carry_modulus(),
            pbs_order: self.pbs_order,
            noise_level: NoiseLevel::NOMINAL,
        }
    }

    #[cfg(feature = "zk-pok-experimental")]
    pub fn encrypt_and_prove_slice(
        &self,
        messages: &[u64],
        public_params: &CompactPkePublicParams,
        load: ZkComputeLoad,
    ) -> crate::Result<ProvenCompactCiphertextList> {
        let plaintext_modulus =
            (self.parameters.message_modulus().0 * self.parameters.carry_modulus().0) as u64;
        let delta = (1u64 << 63) / plaintext_modulus;

        let max_num_message = public_params.k;
        let num_lists = messages.len().div_ceil(max_num_message);
        let mut proved_lists = Vec::with_capacity(num_lists);
        for message_chunk in messages.chunks(max_num_message) {
            let mut ct_list = LweCompactCiphertextListOwned::new(
                0u64,
                self.key.lwe_dimension().to_lwe_size(),
                LweCiphertextCount(message_chunk.len()),
                self.parameters.ciphertext_modulus(),
            );

            let encryption_noise_distribution = match self.pbs_order {
                PBSOrder::KeyswitchBootstrap => self.parameters.glwe_noise_distribution(),
                PBSOrder::BootstrapKeyswitch => self.parameters.lwe_noise_distribution(),
            };

            // No parallelism allowed
            #[cfg(all(feature = "__wasm_api", not(feature = "parallel-wasm-api")))]
            let proof = {
                use crate::core_crypto::prelude::encrypt_and_prove_lwe_compact_ciphertext_list_with_compact_public_key;
                ShortintEngine::with_thread_local_mut(|engine| {
                    encrypt_and_prove_lwe_compact_ciphertext_list_with_compact_public_key(
                        &self.key,
                        &mut ct_list,
                        &message_chunk,
                        delta,
                        encryption_noise_distribution,
                        encryption_noise_distribution,
                        &mut engine.secret_generator,
                        &mut engine.encryption_generator,
                        &mut engine.random_generator,
                        public_params,
                        load,
                    )
                })
            }?;

            // Parallelism allowed  /
            #[cfg(any(not(feature = "__wasm_api"), feature = "parallel-wasm-api"))]
            let proof = {
                use crate::core_crypto::prelude::par_encrypt_and_prove_lwe_compact_ciphertext_list_with_compact_public_key;
                ShortintEngine::with_thread_local_mut(|engine| {
                    par_encrypt_and_prove_lwe_compact_ciphertext_list_with_compact_public_key(
                        &self.key,
                        &mut ct_list,
                        &message_chunk,
                        delta,
                        encryption_noise_distribution,
                        encryption_noise_distribution,
                        &mut engine.secret_generator,
                        &mut engine.encryption_generator,
                        &mut engine.random_generator,
                        public_params,
                        load,
                    )
                })
            }?;

            let message_modulus = self.parameters.message_modulus();
            let ciphertext = CompactCiphertextList {
                ct_list,
                degree: Degree::new(message_modulus.0 - 1),
                message_modulus,
                carry_modulus: self.parameters.carry_modulus(),
                pbs_order: self.pbs_order,
                noise_level: NoiseLevel::NOMINAL,
            };

            proved_lists.push((ciphertext, proof));
        }

        Ok(ProvenCompactCiphertextList { proved_lists })
    }

    pub fn size_elements(&self) -> usize {
        self.key.size_elements()
    }

    pub fn size_bytes(&self) -> usize {
        self.key.size_bytes()
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CompressedCompactPublicKey {
    pub(crate) key: SeededLweCompactPublicKeyOwned<u64>,
    pub parameters: ShortintParameterSet,
    pub pbs_order: PBSOrder,
}

impl CompressedCompactPublicKey {
    pub fn new(client_key: &ClientKey) -> Self {
        let parameters = client_key.parameters;
        let (secret_encryption_key, encryption_noise_distribution) =
            match client_key.parameters.encryption_key_choice().into() {
                crate::shortint::PBSOrder::KeyswitchBootstrap => (
                    client_key.large_lwe_secret_key(),
                    parameters.glwe_noise_distribution(),
                ),
                crate::shortint::PBSOrder::BootstrapKeyswitch => (
                    client_key.small_lwe_secret_key(),
                    parameters.lwe_noise_distribution(),
                ),
            };

        let key = ShortintEngine::with_thread_local_mut(|engine| {
            allocate_and_generate_new_seeded_lwe_compact_public_key(
                &secret_encryption_key,
                encryption_noise_distribution,
                parameters.ciphertext_modulus(),
                &mut engine.seeder,
            )
        });

        Self {
            key,
            parameters,
            pbs_order: client_key.parameters.encryption_key_choice().into(),
        }
    }

    /// Deconstruct a [`CompressedCompactPublicKey`] into its constituents.
    pub fn into_raw_parts(
        self,
    ) -> (
        SeededLweCompactPublicKeyOwned<u64>,
        ShortintParameterSet,
        PBSOrder,
    ) {
        let Self {
            key,
            parameters,
            pbs_order,
        } = self;

        (key, parameters, pbs_order)
    }

    /// Construct a [`CompressedCompactPublicKey`] from its constituents.
    ///
    /// # Panics
    ///
    /// Panics if the constituents are not compatible with each others.
    pub fn from_raw_parts(
        key: SeededLweCompactPublicKeyOwned<u64>,
        parameters: ShortintParameterSet,
        pbs_order: PBSOrder,
    ) -> Self {
        let expected_pbs_order: PBSOrder = parameters.encryption_key_choice().into();

        assert_eq!(
            pbs_order, expected_pbs_order,
            "Mismatch between expected PBSOrder ({expected_pbs_order:?}) and \
            provided PBSOrder ({pbs_order:?})"
        );

        let ciphertext_lwe_dimension = match pbs_order {
            PBSOrder::KeyswitchBootstrap => parameters
                .glwe_dimension()
                .to_equivalent_lwe_dimension(parameters.polynomial_size()),
            PBSOrder::BootstrapKeyswitch => parameters.lwe_dimension(),
        };

        assert_eq!(
            key.lwe_dimension(),
            ciphertext_lwe_dimension,
            "Mismatch between the SeededLweCompactPublicKeyOwned LweDimension ({:?}) and \
            the provided parameters LweDimension ({:?})",
            key.lwe_dimension(),
            ciphertext_lwe_dimension,
        );

        assert_eq!(
            key.ciphertext_modulus(),
            parameters.ciphertext_modulus(),
            "Mismatch between the SeededLweCompactPublicKeyOwned CiphertextModulus ({:?}) and \
            the provided parameters CiphertextModulus ({:?})",
            key.ciphertext_modulus(),
            parameters.ciphertext_modulus(),
        );

        Self {
            key,
            parameters,
            pbs_order,
        }
    }

    pub fn decompress(&self) -> CompactPublicKey {
        let decompressed_key = self.key.as_view().decompress_into_lwe_compact_public_key();
        CompactPublicKey {
            key: decompressed_key,
            parameters: self.parameters,
            pbs_order: self.pbs_order,
        }
    }
}
