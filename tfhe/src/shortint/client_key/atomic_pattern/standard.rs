use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

use crate::core_crypto::prelude::{
    allocate_and_generate_new_binary_glwe_secret_key,
    allocate_and_generate_new_binary_lwe_secret_key, allocate_and_generate_new_lwe_keyswitch_key,
    allocate_and_generate_new_seeded_lwe_keyswitch_key, LweKeyswitchKeyOwned,
    SeededLweKeyswitchKeyOwned,
};
use crate::shortint::backward_compatibility::client_key::atomic_pattern::StandardAtomicPatternClientKeyVersions;
use crate::shortint::client_key::secret_encryption_key::SecretEncryptionKeyView;
use crate::shortint::client_key::{GlweSecretKeyOwned, LweSecretKeyOwned, LweSecretKeyView};
use crate::shortint::engine::ShortintEngine;
use crate::shortint::list_compression::{
    CompressedCompressionKey, CompressedDecompressionKey, CompressionKey, CompressionPrivateKeys,
    DecompressionKey,
};
use crate::shortint::parameters::{
    CompressionParameters, DynamicDistribution, ShortintKeySwitchingParameters,
};
use crate::shortint::{
    AtomicPatternKind, EncryptionKeyChoice, PBSParameters, ShortintParameterSet,
};

use super::EncryptionAtomicPattern;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(StandardAtomicPatternClientKeyVersions)]
pub struct StandardAtomicPatternClientKey {
    pub(crate) glwe_secret_key: GlweSecretKeyOwned<u64>,
    /// Key used as the output of the keyswitch operation
    pub(crate) lwe_secret_key: LweSecretKeyOwned<u64>,
    pub parameters: PBSParameters,
}

impl StandardAtomicPatternClientKey {
    pub(crate) fn new_with_engine(parameters: PBSParameters, engine: &mut ShortintEngine) -> Self {
        // generate the lwe secret key
        let lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
            parameters.lwe_dimension(),
            &mut engine.secret_generator,
        );

        // generate the rlwe secret key
        let glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
            parameters.glwe_dimension(),
            parameters.polynomial_size(),
            &mut engine.secret_generator,
        );

        // pack the keys in the client key set
        Self {
            glwe_secret_key,
            lwe_secret_key,
            parameters,
        }
    }

    pub fn new(parameters: PBSParameters) -> Self {
        ShortintEngine::with_thread_local_mut(|engine| Self::new_with_engine(parameters, engine))
    }

    /// Deconstruct a [`StandardAtomicPatternClientKey`] into its constituents.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::client_key::atomic_pattern::StandardAtomicPatternClientKey;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key:
    /// let cks = StandardAtomicPatternClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS.into());
    ///
    /// let (glwe_secret_key, lwe_secret_key, parameters) = cks.into_raw_parts();
    /// ```
    pub fn into_raw_parts(
        self,
    ) -> (
        GlweSecretKeyOwned<u64>,
        LweSecretKeyOwned<u64>,
        PBSParameters,
    ) {
        let Self {
            glwe_secret_key,
            lwe_secret_key,
            parameters,
        } = self;

        (glwe_secret_key, lwe_secret_key, parameters)
    }

    /// construct a [`StandardAtomicPatternClientKey`] from its constituents.
    ///
    /// # Panics
    ///
    /// Panics if the keys are not compatible with the parameters provided as raw parts.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::client_key::atomic_pattern::StandardAtomicPatternClientKey;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key:
    /// let cks = StandardAtomicPatternClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS.into());
    ///
    /// let (glwe_secret_key, lwe_secret_key, parameters) = cks.into_raw_parts();
    ///
    /// let cks =
    ///     StandardAtomicPatternClientKey::from_raw_parts(glwe_secret_key, lwe_secret_key, parameters);
    /// ```
    pub fn from_raw_parts(
        glwe_secret_key: GlweSecretKeyOwned<u64>,
        lwe_secret_key: LweSecretKeyOwned<u64>,
        parameters: PBSParameters,
    ) -> Self {
        assert_eq!(
            lwe_secret_key.lwe_dimension(),
            parameters.lwe_dimension(),
            "Mismatch between the LweSecretKey LweDimension ({:?}) \
            and the parameters LweDimension ({:?})",
            lwe_secret_key.lwe_dimension(),
            parameters.lwe_dimension()
        );
        assert_eq!(
            glwe_secret_key.glwe_dimension(),
            parameters.glwe_dimension(),
            "Mismatch between the GlweSecretKey GlweDimension ({:?}) \
            and the parameters GlweDimension ({:?})",
            glwe_secret_key.glwe_dimension(),
            parameters.glwe_dimension()
        );
        assert_eq!(
            glwe_secret_key.polynomial_size(),
            parameters.polynomial_size(),
            "Mismatch between the GlweSecretKey PolynomialSize ({:?}) \
            and the parameters PolynomialSize ({:?})",
            glwe_secret_key.polynomial_size(),
            parameters.polynomial_size()
        );

        Self {
            glwe_secret_key,
            lwe_secret_key,
            parameters,
        }
    }

    pub fn try_from_lwe_encryption_key(
        encryption_key: LweSecretKeyOwned<u64>,
        parameters: PBSParameters,
    ) -> crate::Result<Self> {
        let expected_lwe_dimension = parameters.encryption_lwe_dimension();
        if encryption_key.lwe_dimension() != expected_lwe_dimension {
            return Err(
                crate::Error::new(
                    format!(
                        "The given encryption key does not have the correct LweDimension, expected: {:?}, got: {:?}",
                        encryption_key.lwe_dimension(),
                        expected_lwe_dimension)));
        }

        // The key we got is the one used to encrypt,
        // we have to generate the other key
        match parameters.encryption_key_choice() {
            EncryptionKeyChoice::Big => {
                // We have to generate the small lwe key
                let small_key = ShortintEngine::with_thread_local_mut(|engine| {
                    allocate_and_generate_new_binary_lwe_secret_key(
                        parameters.lwe_dimension(),
                        &mut engine.secret_generator,
                    )
                });

                Ok(Self {
                    glwe_secret_key: GlweSecretKeyOwned::from_container(
                        encryption_key.into_container(),
                        parameters.polynomial_size(),
                    ),
                    lwe_secret_key: small_key,
                    parameters,
                })
            }
            EncryptionKeyChoice::Small => {
                // We have to generate the big lwe key
                let glwe_secret_key = ShortintEngine::with_thread_local_mut(|engine| {
                    allocate_and_generate_new_binary_glwe_secret_key(
                        parameters.glwe_dimension(),
                        parameters.polynomial_size(),
                        &mut engine.secret_generator,
                    )
                });

                Ok(Self {
                    glwe_secret_key,
                    lwe_secret_key: encryption_key,
                    parameters,
                })
            }
        }
    }

    pub fn large_lwe_secret_key(&self) -> LweSecretKeyView<'_, u64> {
        self.glwe_secret_key.as_lwe_secret_key()
    }

    pub fn small_lwe_secret_key(&self) -> LweSecretKeyView<'_, u64> {
        self.lwe_secret_key.as_view()
    }

    pub fn keyswitch_encryption_key_and_noise(
        &self,
        params: ShortintKeySwitchingParameters,
    ) -> (LweSecretKeyView<'_, u64>, DynamicDistribution<u64>) {
        match params.destination_key {
            EncryptionKeyChoice::Big => (
                self.large_lwe_secret_key(),
                self.parameters().glwe_noise_distribution(),
            ),
            EncryptionKeyChoice::Small => (
                self.small_lwe_secret_key(),
                self.parameters().lwe_noise_distribution(),
            ),
        }
    }

    pub fn new_compression_key(
        &self,
        private_compression_key: &CompressionPrivateKeys,
    ) -> CompressionKey {
        ShortintEngine::with_thread_local_mut(|engine| {
            self.new_compression_key_with_engine(private_compression_key, engine)
        })
    }

    pub(crate) fn new_compression_key_with_engine(
        &self,
        private_compression_key: &CompressionPrivateKeys,
        engine: &mut ShortintEngine,
    ) -> CompressionKey {
        private_compression_key.new_compression_key_with_engine(
            &self.glwe_secret_key,
            self.parameters(),
            engine,
        )
    }

    pub fn new_compressed_compression_key(
        &self,
        private_compression_key: &CompressionPrivateKeys,
    ) -> CompressedCompressionKey {
        private_compression_key
            .new_compressed_compression_key(&self.glwe_secret_key, self.parameters())
    }

    pub fn new_decompression_key(
        &self,
        private_compression_key: &CompressionPrivateKeys,
    ) -> DecompressionKey {
        private_compression_key.new_decompression_key(&self.glwe_secret_key, self.parameters())
    }

    pub fn new_decompression_key_with_params(
        &self,
        private_compression_key: &CompressionPrivateKeys,
        compression_params: CompressionParameters,
    ) -> DecompressionKey {
        private_compression_key.new_decompression_key_with_params(
            &self.glwe_secret_key,
            self.parameters(),
            compression_params,
        )
    }

    pub fn new_decompression_key_with_params_and_engine(
        &self,
        private_compression_key: &CompressionPrivateKeys,
        compression_params: CompressionParameters,
        engine: &mut ShortintEngine,
    ) -> DecompressionKey {
        private_compression_key.new_decompression_key_with_params_and_engine(
            &self.glwe_secret_key,
            self.parameters(),
            compression_params,
            engine,
        )
    }

    pub fn new_compressed_decompression_key(
        &self,
        private_compression_key: &CompressionPrivateKeys,
    ) -> CompressedDecompressionKey {
        private_compression_key
            .new_compressed_decompression_key(&self.glwe_secret_key, self.parameters())
    }

    pub(crate) fn new_keyswitching_key_with_engine(
        &self,
        input_secret_key: &SecretEncryptionKeyView<'_>,
        params: ShortintKeySwitchingParameters,
        engine: &mut ShortintEngine,
    ) -> LweKeyswitchKeyOwned<u64> {
        match params.destination_key {
            EncryptionKeyChoice::Big => allocate_and_generate_new_lwe_keyswitch_key(
                &input_secret_key.lwe_secret_key,
                &self.large_lwe_secret_key(),
                params.ks_base_log,
                params.ks_level,
                self.parameters.glwe_noise_distribution(),
                self.parameters().ciphertext_modulus(),
                &mut engine.encryption_generator,
            ),
            EncryptionKeyChoice::Small => allocate_and_generate_new_lwe_keyswitch_key(
                &input_secret_key.lwe_secret_key,
                &self.small_lwe_secret_key(),
                params.ks_base_log,
                params.ks_level,
                self.parameters.lwe_noise_distribution(),
                self.parameters.ciphertext_modulus(),
                &mut engine.encryption_generator,
            ),
        }
    }

    pub(crate) fn new_seeded_keyswitching_key_with_engine(
        &self,
        input_secret_key: &SecretEncryptionKeyView<'_>,
        params: ShortintKeySwitchingParameters,
        engine: &mut ShortintEngine,
    ) -> SeededLweKeyswitchKeyOwned<u64> {
        match params.destination_key {
            EncryptionKeyChoice::Big => allocate_and_generate_new_seeded_lwe_keyswitch_key(
                &input_secret_key.lwe_secret_key,
                &self.large_lwe_secret_key(),
                params.ks_base_log,
                params.ks_level,
                self.parameters().glwe_noise_distribution(),
                self.parameters().ciphertext_modulus(),
                &mut engine.seeder,
            ),
            EncryptionKeyChoice::Small => allocate_and_generate_new_seeded_lwe_keyswitch_key(
                &input_secret_key.lwe_secret_key,
                &self.small_lwe_secret_key(),
                params.ks_base_log,
                params.ks_level,
                self.parameters().lwe_noise_distribution(),
                self.parameters().ciphertext_modulus(),
                &mut engine.seeder,
            ),
        }
    }
}

impl EncryptionAtomicPattern for StandardAtomicPatternClientKey {
    fn parameters(&self) -> ShortintParameterSet {
        self.parameters.into()
    }

    fn encryption_key(&self) -> LweSecretKeyView<'_, u64> {
        match self.parameters.encryption_key_choice() {
            EncryptionKeyChoice::Big => self.large_lwe_secret_key(),
            EncryptionKeyChoice::Small => self.small_lwe_secret_key(),
        }
    }

    fn encryption_noise(&self) -> DynamicDistribution<u64> {
        match self.parameters.encryption_key_choice() {
            EncryptionKeyChoice::Big => self.parameters.glwe_noise_distribution(),
            EncryptionKeyChoice::Small => self.parameters.lwe_noise_distribution(),
        }
    }

    fn kind(&self) -> AtomicPatternKind {
        AtomicPatternKind::Standard(self.parameters().encryption_key_choice().into())
    }
}
