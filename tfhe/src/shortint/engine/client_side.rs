//! All the `ShortintEngine` method related to client side (encrypt / decrypt)

use super::ShortintEngine;
use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::math::random::{Distribution, RandomGenerable};
use crate::core_crypto::entities::*;
use crate::shortint::ciphertext::{Degree, NoiseLevel};
use crate::shortint::client_key::atomic_pattern::{
    AtomicPatternClientKey, EncryptionAtomicPattern,
};
use crate::shortint::client_key::GenericClientKey;
use crate::shortint::parameters::{CarryModulus, MessageModulus};
use crate::shortint::{
    Ciphertext, ClientKey, CompressedCiphertext, PaddingBit, ShortintEncoding, ShortintParameterSet,
};

impl ShortintEngine {
    pub fn new_client_key<P>(&mut self, parameters: P) -> ClientKey
    where
        P: TryInto<ShortintParameterSet>,
        <P as TryInto<ShortintParameterSet>>::Error: std::fmt::Debug,
    {
        let shortint_params: ShortintParameterSet = parameters.try_into().unwrap();
        let ap_params = shortint_params.ap_parameters();

        let atomic_pattern = AtomicPatternClientKey::new_with_engine(ap_params, self);

        ClientKey { atomic_pattern }
    }

    pub fn encrypt<AP: EncryptionAtomicPattern>(
        &mut self,
        client_key: &GenericClientKey<AP>,
        message: u64,
    ) -> Ciphertext {
        self.encrypt_with_message_modulus(
            client_key,
            message,
            client_key.parameters().message_modulus(),
        )
    }

    pub fn encrypt_compressed<AP: EncryptionAtomicPattern>(
        &mut self,
        client_key: &GenericClientKey<AP>,
        message: u64,
    ) -> CompressedCiphertext {
        self.encrypt_with_message_modulus_compressed(
            client_key,
            message,
            client_key.parameters().message_modulus(),
        )
    }

    fn encrypt_inner_ct<KeyCont, NoiseDistribution>(
        &mut self,
        client_key_parameters: &ShortintParameterSet,
        client_lwe_sk: &LweSecretKey<KeyCont>,
        noise_distribution: NoiseDistribution,
        message: u64,
        message_modulus: MessageModulus,
    ) -> LweCiphertextOwned<u64>
    where
        NoiseDistribution: Distribution,
        u64: RandomGenerable<NoiseDistribution, CustomModulus = u64>,
        KeyCont: crate::core_crypto::commons::traits::Container<Element = u64>,
    {
        let m = Cleartext(message % message_modulus.0);

        let encoded =
            ShortintEncoding::from_parameters(*client_key_parameters, PaddingBit::Yes).encode(m);

        allocate_and_encrypt_new_lwe_ciphertext(
            client_lwe_sk,
            encoded,
            noise_distribution,
            client_key_parameters.ciphertext_modulus(),
            &mut self.encryption_generator,
        )
    }

    pub(crate) fn encrypt_with_message_modulus<AP: EncryptionAtomicPattern>(
        &mut self,
        client_key: &GenericClientKey<AP>,
        message: u64,
        message_modulus: MessageModulus,
    ) -> Ciphertext {
        let params_atomic_pattern = client_key.parameters().atomic_pattern();

        let (encryption_lwe_sk, encryption_noise_distribution) =
            client_key.encryption_key_and_noise();

        let ct = self.encrypt_inner_ct(
            &client_key.parameters(),
            &encryption_lwe_sk,
            encryption_noise_distribution,
            message,
            message_modulus,
        );

        //This ensures that the space message_modulus*carry_modulus < param.message_modulus *
        // param.carry_modulus
        let carry_modulus = (client_key.parameters().message_modulus().0
            * client_key.parameters().carry_modulus().0)
            / message_modulus.0;

        Ciphertext::new(
            ct,
            Degree::new(message_modulus.0 - 1),
            NoiseLevel::NOMINAL,
            message_modulus,
            CarryModulus(carry_modulus),
            params_atomic_pattern,
        )
    }

    pub(crate) fn encrypt_with_message_and_carry_modulus<AP: EncryptionAtomicPattern>(
        &mut self,
        client_key: &GenericClientKey<AP>,
        message: u64,
        message_modulus: MessageModulus,
        carry_modulus: CarryModulus,
    ) -> Ciphertext {
        assert!(
            message_modulus.0 * carry_modulus.0
                <= client_key.parameters().message_modulus().0
                    * client_key.parameters().carry_modulus().0,
            "MessageModulus * CarryModulus should be \
            smaller or equal to the max given by the parameter set."
        );

        let atomic_pattern = client_key.parameters().atomic_pattern();

        let (encryption_lwe_sk, encryption_noise_distribution) =
            client_key.encryption_key_and_noise();

        let ct = self.encrypt_inner_ct(
            &client_key.parameters(),
            &encryption_lwe_sk,
            encryption_noise_distribution,
            message,
            message_modulus,
        );

        Ciphertext::new(
            ct,
            Degree::new(message_modulus.0 - 1),
            NoiseLevel::NOMINAL,
            message_modulus,
            carry_modulus,
            atomic_pattern,
        )
    }

    pub(crate) fn encrypt_with_message_modulus_compressed<AP: EncryptionAtomicPattern>(
        &mut self,
        client_key: &GenericClientKey<AP>,
        message: u64,
        message_modulus: MessageModulus,
    ) -> CompressedCiphertext {
        // This ensures that the space message_modulus*carry_modulus < param.message_modulus *
        // param.carry_modulus
        let carry_modulus = (client_key.parameters().message_modulus().0
            * client_key.parameters().carry_modulus().0)
            / message_modulus.0;

        let m = Cleartext(message % message_modulus.0);

        let encoded =
            ShortintEncoding::from_parameters(client_key.parameters(), PaddingBit::Yes).encode(m);

        let atomic_pattern = client_key.parameters().atomic_pattern();

        let (encryption_lwe_sk, encryption_noise_distribution) =
            client_key.encryption_key_and_noise();

        let ct = allocate_and_encrypt_new_seeded_lwe_ciphertext(
            &encryption_lwe_sk,
            encoded,
            encryption_noise_distribution,
            client_key.parameters().ciphertext_modulus(),
            &mut self.seeder,
        );

        CompressedCiphertext {
            ct,
            degree: Degree::new(message_modulus.0 - 1),
            message_modulus,
            carry_modulus: CarryModulus(carry_modulus),
            atomic_pattern,
            noise_level: NoiseLevel::NOMINAL,
        }
    }

    pub(crate) fn unchecked_encrypt<AP: EncryptionAtomicPattern>(
        &mut self,
        client_key: &GenericClientKey<AP>,
        message: u64,
    ) -> Ciphertext {
        let atomic_pattern = client_key.parameters().atomic_pattern();

        let (encryption_lwe_sk, encryption_noise_distribution) =
            client_key.encryption_key_and_noise();

        let encoded = ShortintEncoding::from_parameters(client_key.parameters(), PaddingBit::Yes)
            .encode(Cleartext(message));

        let ct = allocate_and_encrypt_new_lwe_ciphertext(
            &encryption_lwe_sk,
            encoded,
            encryption_noise_distribution,
            client_key.parameters().ciphertext_modulus(),
            &mut self.encryption_generator,
        );

        Ciphertext::new(
            ct,
            Degree::new(
                client_key.parameters().message_modulus().0
                    * client_key.parameters().carry_modulus().0
                    - 1,
            ),
            NoiseLevel::NOMINAL,
            client_key.parameters().message_modulus(),
            client_key.parameters().carry_modulus(),
            atomic_pattern,
        )
    }

    pub(crate) fn encrypt_without_padding<AP: EncryptionAtomicPattern>(
        &mut self,
        client_key: &GenericClientKey<AP>,
        message: u64,
    ) -> Ciphertext {
        let encoded = ShortintEncoding::from_parameters(client_key.parameters(), PaddingBit::No)
            .encode(Cleartext(message));

        let atomic_pattern = client_key.parameters().atomic_pattern();

        let (encryption_lwe_sk, encryption_noise_distribution) =
            client_key.encryption_key_and_noise();

        let ct = allocate_and_encrypt_new_lwe_ciphertext(
            &encryption_lwe_sk,
            encoded,
            encryption_noise_distribution,
            client_key.parameters().ciphertext_modulus(),
            &mut self.encryption_generator,
        );

        Ciphertext::new(
            ct,
            Degree::new(client_key.parameters().message_modulus().0 - 1),
            NoiseLevel::NOMINAL,
            client_key.parameters().message_modulus(),
            client_key.parameters().carry_modulus(),
            atomic_pattern,
        )
    }

    pub(crate) fn encrypt_without_padding_compressed<AP: EncryptionAtomicPattern>(
        &mut self,
        client_key: &GenericClientKey<AP>,
        message: u64,
    ) -> CompressedCiphertext {
        let encoded = ShortintEncoding::from_parameters(client_key.parameters(), PaddingBit::No)
            .encode(Cleartext(message));

        let atomic_pattern = client_key.parameters().atomic_pattern();

        let (encryption_lwe_sk, encryption_noise_distribution) =
            client_key.encryption_key_and_noise();

        let ct = allocate_and_encrypt_new_seeded_lwe_ciphertext(
            &encryption_lwe_sk,
            encoded,
            encryption_noise_distribution,
            client_key.parameters().ciphertext_modulus(),
            &mut self.seeder,
        );

        CompressedCiphertext {
            ct,
            degree: Degree::new(client_key.parameters().message_modulus().0 - 1),
            message_modulus: client_key.parameters().message_modulus(),
            carry_modulus: client_key.parameters().carry_modulus(),
            atomic_pattern,
            noise_level: NoiseLevel::NOMINAL,
        }
    }

    pub(crate) fn encrypt_native_crt<AP: EncryptionAtomicPattern>(
        &mut self,
        client_key: &GenericClientKey<AP>,
        message: u64,
        message_modulus: MessageModulus,
    ) -> Ciphertext {
        let carry_modulus = CarryModulus(1);
        let m = (message % message_modulus.0) as u128;
        let shifted_message = (m * (1 << 64) / message_modulus.0 as u128) as u64;

        let encoded = Plaintext(shifted_message);

        let atomic_pattern = client_key.parameters().atomic_pattern();

        let (encryption_lwe_sk, encryption_noise_distribution) =
            client_key.encryption_key_and_noise();

        let ct = allocate_and_encrypt_new_lwe_ciphertext(
            &encryption_lwe_sk,
            encoded,
            encryption_noise_distribution,
            client_key.parameters().ciphertext_modulus(),
            &mut self.encryption_generator,
        );

        Ciphertext::new(
            ct,
            Degree::new(message_modulus.0 - 1),
            NoiseLevel::NOMINAL,
            message_modulus,
            carry_modulus,
            atomic_pattern,
        )
    }

    pub(crate) fn encrypt_native_crt_compressed<AP: EncryptionAtomicPattern>(
        &mut self,
        client_key: &GenericClientKey<AP>,
        message: u64,
        message_modulus: MessageModulus,
    ) -> CompressedCiphertext {
        let carry_modulus = CarryModulus(1);
        let m = (message % message_modulus.0) as u128;
        let shifted_message = (m * (1 << 64) / message_modulus.0 as u128) as u64;

        let encoded = Plaintext(shifted_message);

        let atomic_pattern = client_key.parameters().atomic_pattern();

        let (encryption_lwe_sk, encryption_noise_distribution) =
            client_key.encryption_key_and_noise();

        let ct = allocate_and_encrypt_new_seeded_lwe_ciphertext(
            &encryption_lwe_sk,
            encoded,
            encryption_noise_distribution,
            client_key.parameters().ciphertext_modulus(),
            &mut self.seeder,
        );

        CompressedCiphertext {
            ct,
            degree: Degree::new(message_modulus.0 - 1),
            message_modulus,
            carry_modulus,
            atomic_pattern,
            noise_level: NoiseLevel::NOMINAL,
        }
    }
}
