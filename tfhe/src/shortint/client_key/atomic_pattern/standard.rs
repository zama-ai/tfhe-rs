use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

use crate::core_crypto::prelude::{
    allocate_and_generate_new_binary_glwe_secret_key,
    allocate_and_generate_new_binary_lwe_secret_key,
};
use crate::shortint::backward_compatibility::client_key::atomic_pattern::StandardAtomicPatternClientKeyVersions;
use crate::shortint::client_key::{GlweSecretKeyOwned, LweSecretKeyOwned, LweSecretKeyView};
use crate::shortint::engine::ShortintEngine;
use crate::shortint::parameters::{DynamicDistribution, ShortintKeySwitchingParameters};
use crate::shortint::{
    AtomicPatternKind, EncryptionKeyChoice, PBSParameters, ShortintParameterSet, WopbsParameters,
};

use super::EncryptionAtomicPattern;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(StandardAtomicPatternClientKeyVersions)]
pub struct StandardAtomicPatternClientKey {
    pub(crate) glwe_secret_key: GlweSecretKeyOwned<u64>,
    /// Key used as the output of the keyswitch operation
    pub(crate) lwe_secret_key: LweSecretKeyOwned<u64>,
    pub parameters: PBSParameters,
    pub wopbs_parameters: Option<WopbsParameters>,
}

impl StandardAtomicPatternClientKey {
    pub(crate) fn new_with_engine(
        parameters: PBSParameters,
        wopbs_parameters: Option<WopbsParameters>,
        engine: &mut ShortintEngine,
    ) -> Self {
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
            wopbs_parameters,
        }
    }

    pub fn new(parameters: PBSParameters, wopbs_parameters: Option<WopbsParameters>) -> Self {
        ShortintEngine::with_thread_local_mut(|engine| {
            Self::new_with_engine(parameters, wopbs_parameters, engine)
        })
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
    /// let cks = StandardAtomicPatternClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS.into(), None);
    ///
    /// let (glwe_secret_key, lwe_secret_key, parameters, wopbs_parameters) = cks.into_raw_parts();
    /// ```
    pub fn into_raw_parts(
        self,
    ) -> (
        GlweSecretKeyOwned<u64>,
        LweSecretKeyOwned<u64>,
        PBSParameters,
        Option<WopbsParameters>,
    ) {
        let Self {
            glwe_secret_key,
            lwe_secret_key,
            parameters,
            wopbs_parameters,
        } = self;

        (
            glwe_secret_key,
            lwe_secret_key,
            parameters,
            wopbs_parameters,
        )
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
    /// let cks = StandardAtomicPatternClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS.into(), None);
    ///
    /// let (glwe_secret_key, lwe_secret_key, parameters, wopbs_parameters) = cks.into_raw_parts();
    ///
    /// let cks = StandardAtomicPatternClientKey::from_raw_parts(
    ///     glwe_secret_key,
    ///     lwe_secret_key,
    ///     parameters,
    ///     wopbs_parameters,
    /// );
    /// ```
    pub fn from_raw_parts(
        glwe_secret_key: GlweSecretKeyOwned<u64>,
        lwe_secret_key: LweSecretKeyOwned<u64>,
        parameters: PBSParameters,
        wopbs_parameters: Option<WopbsParameters>,
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
            wopbs_parameters,
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
                    wopbs_parameters: None,
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
                    wopbs_parameters: None,
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
}

impl EncryptionAtomicPattern for StandardAtomicPatternClientKey {
    fn parameters(&self) -> ShortintParameterSet {
        self.wopbs_parameters.map_or_else(
            || self.parameters.into(),
            |wopbs_params| {
                ShortintParameterSet::try_new_pbs_and_wopbs_param_set((
                    self.parameters,
                    wopbs_params,
                ))
                .unwrap()
            },
        )
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
