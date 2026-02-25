use crate::conformance::ParameterSetConformant;
use crate::core_crypto::prelude::{
    allocate_and_generate_new_binary_lwe_secret_key,
    allocate_and_generate_new_seeded_lwe_compact_public_key, generate_lwe_compact_public_key,
    Cleartext, Container, LweCiphertextCount, LweCompactCiphertextListOwned,
    LweCompactPublicKeyConformanceParams, LweCompactPublicKeyOwned, LweSecretKey, Plaintext,
    PlaintextList, SeededLweCompactPublicKeyOwned,
};
use crate::shortint::backward_compatibility::public_key::{
    CompactPrivateKeyVersions, CompactPublicKeyVersions, CompressedCompactPublicKeyVersions,
};
#[cfg(feature = "zk-pok")]
use crate::shortint::ciphertext::ProvenCompactCiphertextList;
use crate::shortint::ciphertext::{CompactCiphertextList, Degree};
use crate::shortint::client_key::secret_encryption_key::SecretEncryptionKeyView;
use crate::shortint::engine::ShortintEngine;
#[cfg(feature = "zk-pok")]
use crate::core_crypto::commons::generators::DeterministicSeeder;
#[cfg(feature = "zk-pok")]
use crate::core_crypto::commons::math::random::{DefaultRandomGenerator, Seed};
use crate::shortint::parameters::compact_public_key_only::CompactPublicKeyEncryptionParameters;
use crate::shortint::ClientKey;
#[cfg(feature = "zk-pok")]
use crate::shortint::ShortintEncoding;
#[cfg(feature = "zk-pok")]
use crate::zk::{CompactPkeCrs, ZkComputeLoad};
use crate::Error;
use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

/// Private key from which a [`CompactPublicKey`] can be built.
#[derive(Clone, Debug, Serialize, Deserialize, Versionize)]
#[versionize(CompactPrivateKeyVersions)]
pub struct CompactPrivateKey<KeyCont: Container<Element = u64>> {
    key: LweSecretKey<KeyCont>,
    parameters: CompactPublicKeyEncryptionParameters,
}

impl<C: Container<Element = u64>> CompactPrivateKey<C> {
    pub fn from_raw_parts(
        key: LweSecretKey<C>,
        parameters: CompactPublicKeyEncryptionParameters,
    ) -> Result<Self, Error> {
        if !parameters.is_valid() {
            return Err(Error::new(String::from(
                "Invalid CompactPublicKeyEncryptionParameters",
            )));
        }

        if key.lwe_dimension() != parameters.encryption_lwe_dimension {
            return Err(Error::new(String::from(
                "Mismatch between CompactPublicKeyEncryptionParameters encryption_lwe_dimension \
                and key lwe_dimension",
            )));
        }

        Ok(Self { key, parameters })
    }

    pub fn into_raw_parts(self) -> (LweSecretKey<C>, CompactPublicKeyEncryptionParameters) {
        let Self { key, parameters } = self;
        (key, parameters)
    }

    pub fn key(&self) -> LweSecretKey<&'_ [u64]> {
        self.key.as_view()
    }

    pub fn parameters(&self) -> CompactPublicKeyEncryptionParameters {
        self.parameters
    }

    pub fn as_view(&self) -> CompactPrivateKey<&[u64]> {
        CompactPrivateKey {
            key: self.key.as_view(),
            parameters: self.parameters(),
        }
    }
}

impl CompactPrivateKey<Vec<u64>> {
    pub fn new(parameters: CompactPublicKeyEncryptionParameters) -> Self {
        let parameters = parameters.validate();
        let encryption_lwe_dimension = parameters.encryption_lwe_dimension;

        let key = ShortintEngine::with_thread_local_mut(|engine| {
            allocate_and_generate_new_binary_lwe_secret_key(
                encryption_lwe_dimension,
                &mut engine.secret_generator,
            )
        });

        Self { key, parameters }
    }
}

impl<'key, C: Container<Element = u64>> From<&'key CompactPrivateKey<C>>
    for CompactPrivateKey<&'key [u64]>
{
    #[inline(always)]
    fn from(value: &'key CompactPrivateKey<C>) -> Self {
        value.as_view()
    }
}

impl<'key> TryFrom<&'key ClientKey> for CompactPrivateKey<&'key [u64]> {
    type Error = crate::Error;

    fn try_from(client_key: &'key ClientKey) -> Result<Self, Self::Error> {
        let parameters = client_key.parameters();
        let compact_encryption_parameters: CompactPublicKeyEncryptionParameters =
            parameters.try_into()?;

        Self::from_raw_parts(
            client_key.encryption_key_and_noise().0,
            compact_encryption_parameters,
        )
    }
}

impl<'key, C: Container<Element = u64>> From<&'key CompactPrivateKey<C>>
    for SecretEncryptionKeyView<'key>
{
    fn from(value: &'key CompactPrivateKey<C>) -> Self {
        Self {
            lwe_secret_key: value.key(),
            message_modulus: value.parameters().message_modulus,
            carry_modulus: value.parameters().carry_modulus,
        }
    }
}

/// Public key construction described in <https://eprint.iacr.org/2023/603> by M. Joye.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(CompactPublicKeyVersions)]
pub struct CompactPublicKey {
    pub(crate) key: LweCompactPublicKeyOwned<u64>,
    pub parameters: CompactPublicKeyEncryptionParameters,
}

fn to_plaintext_iterator(
    message_iter: impl Iterator<Item = u64>,
    encryption_modulus: u64,
    parameters: &CompactPublicKeyEncryptionParameters,
) -> impl Iterator<Item = Plaintext<u64>> {
    let message_modulus = parameters.message_modulus.0;
    let carry_modulus = parameters.carry_modulus.0;

    let full_modulus = message_modulus * carry_modulus;

    assert!(
        encryption_modulus <= full_modulus,
        "Encryption modulus cannot exceed the plaintext modulus"
    );

    let encoding = parameters.encoding();
    message_iter.map(move |message| {
        let m = message % encryption_modulus;
        encoding.encode(Cleartext(m))
    })
}

impl CompactPublicKey {
    pub fn new<'data, C, E>(compact_private_key: C) -> Self
    where
        C: TryInto<CompactPrivateKey<&'data [u64]>, Error = E>,
        Error: From<E>,
    {
        Self::try_new(compact_private_key).expect(
            "Incompatible parameters, the lwe_dimension of the secret key must be a power of two",
        )
    }

    pub fn try_new<'data, C, E>(input_key: C) -> Result<Self, Error>
    where
        C: TryInto<CompactPrivateKey<&'data [u64]>, Error = E>,
        Error: From<E>,
    {
        let compact_private_key: CompactPrivateKey<&[u64]> = input_key.try_into()?;

        let parameters = compact_private_key.parameters;

        if !parameters.is_valid() {
            return Err(Error::new(String::from(
                "Invalid CompactPublicKeyEncryptionParameters",
            )));
        }

        let (secret_encryption_key, encryption_noise_distribution) = (
            &compact_private_key.key,
            parameters.encryption_noise_distribution,
        );

        let mut key = LweCompactPublicKeyOwned::new(
            0u64,
            secret_encryption_key.lwe_dimension(),
            parameters.ciphertext_modulus,
        );
        ShortintEngine::with_thread_local_mut(|engine| {
            generate_lwe_compact_public_key(
                secret_encryption_key,
                &mut key,
                encryption_noise_distribution,
                &mut engine.encryption_generator,
            );
        });

        Ok(Self { key, parameters })
    }

    /// Deconstruct a [`CompactPublicKey`] into its constituents.
    pub fn into_raw_parts(
        self,
    ) -> (
        LweCompactPublicKeyOwned<u64>,
        CompactPublicKeyEncryptionParameters,
    ) {
        let Self { key, parameters } = self;

        (key, parameters)
    }

    /// Construct a [`CompactPublicKey`] from its constituents.
    ///
    /// # Panics
    ///
    /// Panics if the constituents are not compatible with each others.
    pub fn from_raw_parts(
        key: LweCompactPublicKeyOwned<u64>,
        parameters: CompactPublicKeyEncryptionParameters,
    ) -> Self {
        let ciphertext_lwe_dimension = parameters.encryption_lwe_dimension;

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
            parameters.ciphertext_modulus,
            "Mismatch between the LweCompactPublicKey CiphertextModulus ({:?}) and \
            the provided parameters CiphertextModulus ({:?})",
            key.ciphertext_modulus(),
            parameters.ciphertext_modulus,
        );

        Self { key, parameters }
    }

    #[cfg(feature = "zk-pok")]
    pub fn encrypt_and_prove(
        &self,
        message: u64,
        crs: &CompactPkeCrs,
        metadata: &[u8],
        load: ZkComputeLoad,
        encryption_modulus: u64,
    ) -> crate::Result<ProvenCompactCiphertextList> {
        self.encrypt_and_prove_slice(&[message], crs, metadata, load, encryption_modulus)
    }

    /// Encrypts the messages contained in the slice into a compact ciphertext list
    ///
    /// See [Self::encrypt_iter] for more details
    pub fn encrypt_slice(&self, messages: &[u64]) -> CompactCiphertextList {
        self.encrypt_slice_with_modulus(messages, self.parameters.message_modulus.0)
    }

    /// Encrypts the messages coming from the iterator into a compact ciphertext list
    ///
    /// Values of the messages should be in range [0..message_modulus[
    /// (a modulo operation is applied to each input)
    pub fn encrypt_iter(&self, messages: impl Iterator<Item = u64>) -> CompactCiphertextList {
        self.encrypt_iter_with_modulus(messages, self.parameters.message_modulus.0)
    }

    /// Encrypts the messages contained in the slice into a compact ciphertext list
    ///
    /// See [Self::encrypt_iter_with_modulus] for more details
    pub fn encrypt_slice_with_modulus(
        &self,
        messages: &[u64],
        encryption_modulus: u64,
    ) -> CompactCiphertextList {
        self.encrypt_iter_with_modulus(messages.iter().copied(), encryption_modulus)
    }

    /// Encrypts the messages coming from the iterator into a compact ciphertext list
    ///
    /// Values of the messages should be in range [0..encryption_modulus[
    /// (a modulo operation is applied to each input)
    ///
    /// # Panic
    ///
    /// - This will panic is encryption modulus is greater that message_modulus * carry_modulus
    pub fn encrypt_iter_with_modulus(
        &self,
        messages: impl Iterator<Item = u64>,
        encryption_modulus: u64,
    ) -> CompactCiphertextList {
        let plaintext_container =
            to_plaintext_iterator(messages, encryption_modulus, &self.parameters)
                .map(|plaintext| plaintext.0)
                .collect::<Vec<_>>();

        let plaintext_list = PlaintextList::from_container(plaintext_container);
        let mut ct_list = LweCompactCiphertextListOwned::new(
            0u64,
            self.key.lwe_dimension().to_lwe_size(),
            LweCiphertextCount(plaintext_list.plaintext_count().0),
            self.parameters.ciphertext_modulus,
        );

        let encryption_noise_distribution = self.parameters.encryption_noise_distribution;

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
                    engine.encryption_generator.noise_generator_mut(),
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
                    engine.encryption_generator.noise_generator_mut(),
                );
            });
        }

        let message_modulus = self.parameters.message_modulus;
        CompactCiphertextList {
            ct_list,
            degree: Degree::new(encryption_modulus - 1),
            message_modulus,
            carry_modulus: self.parameters.carry_modulus,
            expansion_kind: self.parameters.expansion_kind,
        }
    }

    #[cfg(feature = "zk-pok")]
    pub fn encrypt_and_prove_slice(
        &self,
        messages: &[u64],
        crs: &CompactPkeCrs,
        metadata: &[u8],
        load: ZkComputeLoad,
        encryption_modulus: u64,
    ) -> crate::Result<ProvenCompactCiphertextList> {
        let plaintext_modulus = self.parameters.message_modulus.0 * self.parameters.carry_modulus.0;
        assert!(encryption_modulus <= plaintext_modulus);
        let delta = self.encoding().delta();

        // This is the maximum number of lwe that can share the same mask in lwe compact pk
        // encryption
        let max_ciphertext_per_bin = self.key.lwe_dimension().0;
        // This is the maximum of lwe message a single proof can prove
        let max_num_messages = crs.max_num_messages().0;
        // One of the two is the limiting factor for how much we can pack messages
        let message_chunk_size = max_num_messages.min(max_ciphertext_per_bin);

        let num_lists = messages.len().div_ceil(message_chunk_size);
        let mut proved_lists = Vec::with_capacity(num_lists);
        for message_chunk in messages.chunks(message_chunk_size) {
            let mut ct_list = LweCompactCiphertextListOwned::new(
                0u64,
                self.key.lwe_dimension().to_lwe_size(),
                LweCiphertextCount(message_chunk.len()),
                self.parameters.ciphertext_modulus,
            );

            let encryption_noise_distribution = self.parameters.encryption_noise_distribution;

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
                        engine.encryption_generator.noise_generator_mut(),
                        &mut engine.random_generator,
                        crs,
                        metadata,
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
                        engine.encryption_generator.noise_generator_mut(),
                        &mut engine.random_generator,
                        crs,
                        metadata,
                        load,
                    )
                })
            }?;

            let message_modulus = self.parameters.message_modulus;
            let ciphertext = CompactCiphertextList {
                ct_list,
                degree: Degree::new(encryption_modulus - 1),
                message_modulus,
                carry_modulus: self.parameters.carry_modulus,
                expansion_kind: self.parameters.expansion_kind,
            };

            proved_lists.push((ciphertext, proof));
        }

        Ok(ProvenCompactCiphertextList { proved_lists })
    }

    #[cfg(feature = "zk-pok")]
    pub fn encrypt_and_prove_slice_seeded(
        &self,
        messages: &[u64],
        crs: &CompactPkeCrs,
        metadata: &[u8],
        load: ZkComputeLoad,
        encryption_modulus: u64,
        seed: Seed,
    ) -> crate::Result<ProvenCompactCiphertextList> {
        let plaintext_modulus = self.parameters.message_modulus.0 * self.parameters.carry_modulus.0;
        assert!(encryption_modulus <= plaintext_modulus);
        let delta = self.encoding().delta();

        let max_ciphertext_per_bin = self.key.lwe_dimension().0;
        let max_num_messages = crs.max_num_messages().0;
        let message_chunk_size = max_num_messages.min(max_ciphertext_per_bin);

        let mut deterministic_seeder =
            DeterministicSeeder::<DefaultRandomGenerator>::new(seed);
        let mut engine = ShortintEngine::new_from_seeder(&mut deterministic_seeder);

        let num_lists = messages.len().div_ceil(message_chunk_size);
        let mut proved_lists = Vec::with_capacity(num_lists);
        for message_chunk in messages.chunks(message_chunk_size) {
            let mut ct_list = LweCompactCiphertextListOwned::new(
                0u64,
                self.key.lwe_dimension().to_lwe_size(),
                LweCiphertextCount(message_chunk.len()),
                self.parameters.ciphertext_modulus,
            );

            let encryption_noise_distribution = self.parameters.encryption_noise_distribution;

            #[cfg(all(feature = "__wasm_api", not(feature = "parallel-wasm-api")))]
            let proof = {
                use crate::core_crypto::prelude::encrypt_and_prove_lwe_compact_ciphertext_list_with_compact_public_key;
                encrypt_and_prove_lwe_compact_ciphertext_list_with_compact_public_key(
                    &self.key,
                    &mut ct_list,
                    &message_chunk,
                    delta,
                    encryption_noise_distribution,
                    encryption_noise_distribution,
                    engine.encryption_generator.noise_generator_mut(),
                    &mut engine.random_generator,
                    crs,
                    metadata,
                    load,
                )
            }?;

            #[cfg(any(not(feature = "__wasm_api"), feature = "parallel-wasm-api"))]
            let proof = {
                use crate::core_crypto::prelude::par_encrypt_and_prove_lwe_compact_ciphertext_list_with_compact_public_key;
                par_encrypt_and_prove_lwe_compact_ciphertext_list_with_compact_public_key(
                    &self.key,
                    &mut ct_list,
                    &message_chunk,
                    delta,
                    encryption_noise_distribution,
                    encryption_noise_distribution,
                    engine.encryption_generator.noise_generator_mut(),
                    &mut engine.random_generator,
                    crs,
                    metadata,
                    load,
                )
            }?;

            let message_modulus = self.parameters.message_modulus;
            let ciphertext = CompactCiphertextList {
                ct_list,
                degree: Degree::new(encryption_modulus - 1),
                message_modulus,
                carry_modulus: self.parameters.carry_modulus,
                expansion_kind: self.parameters.expansion_kind,
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

    pub fn parameters(&self) -> CompactPublicKeyEncryptionParameters {
        self.parameters
    }

    #[cfg(feature = "zk-pok")]
    pub(crate) fn encoding(&self) -> ShortintEncoding<u64> {
        self.parameters.encoding()
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(CompressedCompactPublicKeyVersions)]
pub struct CompressedCompactPublicKey {
    pub(crate) key: SeededLweCompactPublicKeyOwned<u64>,
    pub parameters: CompactPublicKeyEncryptionParameters,
}

impl CompressedCompactPublicKey {
    pub fn new<'data, C>(input_key: C) -> Self
    where
        C: TryInto<CompactPrivateKey<&'data [u64]>>,
        C::Error: core::fmt::Debug,
    {
        let compact_private_key: CompactPrivateKey<&[u64]> = input_key.try_into().unwrap();

        let parameters = compact_private_key.parameters;
        let (secret_encryption_key, encryption_noise_distribution) = (
            compact_private_key.key,
            parameters.encryption_noise_distribution,
        );

        let key = ShortintEngine::with_thread_local_mut(|engine| {
            allocate_and_generate_new_seeded_lwe_compact_public_key(
                &secret_encryption_key,
                encryption_noise_distribution,
                parameters.ciphertext_modulus,
                &mut engine.seeder,
            )
        });

        Self { key, parameters }
    }

    /// Deconstruct a [`CompressedCompactPublicKey`] into its constituents.
    pub fn into_raw_parts(
        self,
    ) -> (
        SeededLweCompactPublicKeyOwned<u64>,
        CompactPublicKeyEncryptionParameters,
    ) {
        let Self { key, parameters } = self;

        (key, parameters)
    }

    /// Construct a [`CompressedCompactPublicKey`] from its constituents.
    ///
    /// # Panics
    ///
    /// Panics if the constituents are not compatible with each others.
    pub fn from_raw_parts(
        key: SeededLweCompactPublicKeyOwned<u64>,
        parameters: CompactPublicKeyEncryptionParameters,
    ) -> Self {
        let ciphertext_lwe_dimension = parameters.encryption_lwe_dimension;

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
            parameters.ciphertext_modulus,
            "Mismatch between the SeededLweCompactPublicKeyOwned CiphertextModulus ({:?}) and \
            the provided parameters CiphertextModulus ({:?})",
            key.ciphertext_modulus(),
            parameters.ciphertext_modulus,
        );

        Self { key, parameters }
    }

    pub fn decompress(&self) -> CompactPublicKey {
        let decompressed_key = self.key.as_view().decompress_into_lwe_compact_public_key();
        CompactPublicKey {
            key: decompressed_key,
            parameters: self.parameters,
        }
    }

    pub fn parameters(&self) -> CompactPublicKeyEncryptionParameters {
        self.parameters
    }
}

impl ParameterSetConformant for CompactPublicKey {
    type ParameterSet = CompactPublicKeyEncryptionParameters;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        let Self { key, parameters } = self;

        let core_params = LweCompactPublicKeyConformanceParams {
            encryption_lwe_dimension: parameter_set.encryption_lwe_dimension,
            ciphertext_modulus: parameter_set.ciphertext_modulus,
        };

        parameters == parameter_set && key.is_conformant(&core_params)
    }
}

impl ParameterSetConformant for CompressedCompactPublicKey {
    type ParameterSet = CompactPublicKeyEncryptionParameters;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        let Self { key, parameters } = self;

        let core_params = LweCompactPublicKeyConformanceParams {
            encryption_lwe_dimension: parameter_set.encryption_lwe_dimension,
            ciphertext_modulus: parameter_set.ciphertext_modulus,
        };

        parameters == parameter_set && key.is_conformant(&core_params)
    }
}
