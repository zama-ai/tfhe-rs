use serde::{Deserialize, Serialize};

use crate::core_crypto::prelude::{
    allocate_and_generate_new_seeded_lwe_compact_public_key, generate_lwe_compact_public_key,
    LweCiphertextCount, LweCiphertextOwned, LweCompactCiphertextListOwned,
    LweCompactPublicKeyOwned, Plaintext, PlaintextList, SeededLweCompactPublicKeyOwned,
};

use crate::core_crypto::prelude::encrypt_lwe_ciphertext_with_compact_public_key;

use crate::shortint::ciphertext::{
    BootstrapKeyswitch, CompactCiphertextList, Degree, KeyswitchBootstrap,
};
use crate::shortint::{CiphertextBase, ClientKey, PBSOrderMarker, ShortintParameterSet};

use crate::shortint::engine::ShortintEngine;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CompactPublicKeyBase<OpOrder: PBSOrderMarker> {
    pub(crate) key: LweCompactPublicKeyOwned<u64>,
    pub parameters: ShortintParameterSet,
    pub _order_marker: std::marker::PhantomData<OpOrder>,
}

pub type CompactPublicKeyBig = CompactPublicKeyBase<KeyswitchBootstrap>;
pub type CompactPublicKeySmall = CompactPublicKeyBase<BootstrapKeyswitch>;

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

impl<OpOrder: PBSOrderMarker> CompactPublicKeyBase<OpOrder> {
    pub fn new(client_key: &ClientKey) -> CompactPublicKeyBase<OpOrder> {
        Self::try_new(client_key).expect(
            "Incompatible parameters, the lwe_dimension of the secret key must be a power of two",
        )
    }

    pub fn try_new(client_key: &ClientKey) -> Option<CompactPublicKeyBase<OpOrder>> {
        let parameters = client_key.parameters;
        let (secret_encryption_key, encryption_noise) = match OpOrder::pbs_order() {
            crate::shortint::PBSOrder::KeyswitchBootstrap => (
                &client_key.large_lwe_secret_key,
                parameters.glwe_modular_std_dev(),
            ),
            crate::shortint::PBSOrder::BootstrapKeyswitch => (
                &client_key.small_lwe_secret_key,
                parameters.lwe_modular_std_dev(),
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
                secret_encryption_key,
                &mut key,
                encryption_noise,
                &mut engine.encryption_generator,
            );
        });

        Some(Self {
            key,
            parameters,
            _order_marker: std::marker::PhantomData,
        })
    }

    pub fn encrypt(&self, message: u64) -> CiphertextBase<OpOrder> {
        let plain = to_plaintext_iterator([message].iter().copied(), &self.parameters)
            .next()
            .unwrap();

        // This allocates the required ct
        let mut encrypted_ct = LweCiphertextOwned::new(
            0u64,
            self.key.lwe_dimension().to_lwe_size(),
            self.parameters.ciphertext_modulus(),
        );

        ShortintEngine::with_thread_local_mut(|engine| {
            encrypt_lwe_ciphertext_with_compact_public_key(
                &self.key,
                &mut encrypted_ct,
                plain,
                self.parameters.glwe_modular_std_dev(),
                self.parameters.lwe_modular_std_dev(),
                &mut engine.secret_generator,
                &mut engine.encryption_generator,
            );
        });

        let message_modulus = self.parameters.message_modulus();
        CiphertextBase {
            ct: encrypted_ct,
            degree: Degree(message_modulus.0 - 1),
            message_modulus,
            carry_modulus: self.parameters.carry_modulus(),
            _order_marker: Default::default(),
        }
    }

    pub fn encrypt_slice(&self, messages: &[u64]) -> CompactCiphertextList<OpOrder> {
        self.encrypt_iter(messages.iter().copied())
    }

    pub fn encrypt_iter(
        &self,
        messages: impl Iterator<Item = u64>,
    ) -> CompactCiphertextList<OpOrder> {
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

        // No parallelism allowed
        #[cfg(all(feature = "__wasm_api", not(feature = "parallel-wasm-api")))]
        {
            use crate::core_crypto::prelude::encrypt_lwe_compact_ciphertext_list_with_compact_public_key;
            ShortintEngine::with_thread_local_mut(|engine| {
                encrypt_lwe_compact_ciphertext_list_with_compact_public_key(
                    &self.key,
                    &mut ct_list,
                    &plaintext_list,
                    self.parameters.glwe_modular_std_dev(),
                    self.parameters.lwe_modular_std_dev(),
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
                    self.parameters.glwe_modular_std_dev(),
                    self.parameters.lwe_modular_std_dev(),
                    &mut engine.secret_generator,
                    &mut engine.encryption_generator,
                );
            });
        }

        let message_modulus = self.parameters.message_modulus();
        CompactCiphertextList {
            ct_list,
            degree: Degree(message_modulus.0 - 1),
            message_modulus,
            carry_modulus: self.parameters.carry_modulus(),
            _order_marker: Default::default(),
        }
    }

    pub fn size_elements(&self) -> usize {
        self.key.size_elements()
    }

    pub fn size_bytes(&self) -> usize {
        self.key.size_bytes()
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CompressedCompactPublicKeyBase<OpOrder: PBSOrderMarker> {
    pub(crate) key: SeededLweCompactPublicKeyOwned<u64>,
    pub parameters: ShortintParameterSet,
    pub _order_marker: std::marker::PhantomData<OpOrder>,
}

pub type CompressedCompactPublicKeyBig = CompressedCompactPublicKeyBase<KeyswitchBootstrap>;
pub type CompressedCompactPublicKeySmall = CompressedCompactPublicKeyBase<BootstrapKeyswitch>;

impl<OpOrder: PBSOrderMarker> CompressedCompactPublicKeyBase<OpOrder> {
    pub fn new(client_key: &ClientKey) -> Self {
        let parameters = client_key.parameters;
        let (secret_encryption_key, encryption_noise) = match OpOrder::pbs_order() {
            crate::shortint::PBSOrder::KeyswitchBootstrap => (
                &client_key.large_lwe_secret_key,
                parameters.glwe_modular_std_dev(),
            ),
            crate::shortint::PBSOrder::BootstrapKeyswitch => (
                &client_key.small_lwe_secret_key,
                parameters.lwe_modular_std_dev(),
            ),
        };

        let key = ShortintEngine::with_thread_local_mut(|engine| {
            allocate_and_generate_new_seeded_lwe_compact_public_key(
                secret_encryption_key,
                encryption_noise,
                parameters.ciphertext_modulus(),
                &mut engine.seeder,
            )
        });

        Self {
            key,
            parameters,
            _order_marker: std::marker::PhantomData,
        }
    }

    pub fn decompress(self) -> CompactPublicKeyBase<OpOrder> {
        let decompressed_key = self.key.decompress_into_lwe_compact_public_key();
        CompactPublicKeyBase {
            key: decompressed_key,
            parameters: self.parameters,
            _order_marker: self._order_marker,
        }
    }
}

impl<OpOrder: PBSOrderMarker> From<CompressedCompactPublicKeyBase<OpOrder>>
    for CompactPublicKeyBase<OpOrder>
{
    fn from(value: CompressedCompactPublicKeyBase<OpOrder>) -> Self {
        value.decompress()
    }
}
