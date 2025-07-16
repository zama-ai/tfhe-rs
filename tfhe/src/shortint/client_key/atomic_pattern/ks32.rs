use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

use crate::core_crypto::prelude::{
    allocate_and_generate_new_binary_glwe_secret_key,
    allocate_and_generate_new_binary_lwe_secret_key,
};
use crate::shortint::backward_compatibility::client_key::atomic_pattern::KS32AtomicPatternClientKeyVersions;
use crate::shortint::client_key::{GlweSecretKeyOwned, LweSecretKeyOwned, LweSecretKeyView};
use crate::shortint::engine::ShortintEngine;
use crate::shortint::parameters::{DynamicDistribution, KeySwitch32PBSParameters};
use crate::shortint::{AtomicPatternKind, EncryptionKeyChoice, ShortintParameterSet};

use super::EncryptionAtomicPattern;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(KS32AtomicPatternClientKeyVersions)]
pub struct KS32AtomicPatternClientKey {
    pub(crate) glwe_secret_key: GlweSecretKeyOwned<u64>,
    /// Key used as the output of the keyswitch operation
    pub(crate) lwe_secret_key: LweSecretKeyOwned<u32>,
    pub parameters: KeySwitch32PBSParameters,
}

impl KS32AtomicPatternClientKey {
    pub(crate) fn new_with_engine(
        parameters: KeySwitch32PBSParameters,
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
        }
    }

    pub fn new(parameters: KeySwitch32PBSParameters) -> Self {
        ShortintEngine::with_thread_local_mut(|engine| Self::new_with_engine(parameters, engine))
    }

    pub fn into_raw_parts(
        self,
    ) -> (
        GlweSecretKeyOwned<u64>,
        LweSecretKeyOwned<u32>,
        KeySwitch32PBSParameters,
    ) {
        let Self {
            glwe_secret_key,
            lwe_secret_key,
            parameters,
        } = self;

        (glwe_secret_key, lwe_secret_key, parameters)
    }

    pub fn from_raw_parts(
        glwe_secret_key: GlweSecretKeyOwned<u64>,
        lwe_secret_key: LweSecretKeyOwned<u32>,
        parameters: KeySwitch32PBSParameters,
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
        parameters: KeySwitch32PBSParameters,
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
        // we have to generate the other key. The KS32 ap only support KS-PBS order so we need to
        // generate the small key.
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

    pub fn large_lwe_secret_key(&self) -> LweSecretKeyView<'_, u64> {
        self.glwe_secret_key.as_lwe_secret_key()
    }

    pub fn small_lwe_secret_key(&self) -> LweSecretKeyView<'_, u32> {
        self.lwe_secret_key.as_view()
    }
}

impl EncryptionAtomicPattern for KS32AtomicPatternClientKey {
    fn parameters(&self) -> ShortintParameterSet {
        self.parameters.into()
    }

    fn encryption_key(&self) -> LweSecretKeyView<'_, u64> {
        // The KS32 atomic pattern is only supported with the KsPbs order
        self.glwe_secret_key.as_lwe_secret_key()
    }

    fn intermediate_encryption_key(&self) -> LweSecretKeyView<'_, u64> {
        panic!("KS32 AP does not support decrypting with the intermediate encryption key")
    }

    fn encryption_key_choice(&self) -> EncryptionKeyChoice {
        self.parameters.encryption_key_choice()
    }

    fn encryption_noise(&self) -> DynamicDistribution<u64> {
        // The KS32 atomic pattern is only supported with the KsPbs order
        self.parameters.glwe_noise_distribution()
    }

    fn kind(&self) -> AtomicPatternKind {
        AtomicPatternKind::KeySwitch32
    }
}
