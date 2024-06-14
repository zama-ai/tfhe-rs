use crate::core_crypto::algorithms::decompress_seeded_lwe_keyswitch_key;
use crate::core_crypto::commons::generators::DeterministicSeeder;
use crate::core_crypto::entities::LweKeyswitchKeyOwned;
use crate::core_crypto::prelude::ActivatedRandomGenerator;
use crate::integer::public_key::CompactPublicKey;
use crate::integer::CompressedCompactPublicKey;
use crate::shortint::{EncryptionKeyChoice, MessageModulus};
use crate::Error;
use concrete_csprng::seeders::Seed;
use serde::{Deserialize, Serialize};

// Clippy complained that fields end in _parameters, :roll_eyes:
#[allow(clippy::struct_field_names)]
#[derive(Copy, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct IntegerConfig {
    pub(crate) block_parameters: crate::shortint::PBSParameters,
    pub(crate) wopbs_block_parameters: Option<crate::shortint::WopbsParameters>,
    pub(crate) dedicated_compact_public_key_parameters: Option<(
        crate::shortint::parameters::CompactPublicKeyEncryptionParameters,
        crate::shortint::parameters::ShortintKeySwitchingParameters,
    )>,
}

impl IntegerConfig {
    pub(crate) fn new(
        block_parameters: crate::shortint::PBSParameters,
        wopbs_block_parameters: Option<crate::shortint::WopbsParameters>,
        dedicated_compact_public_key_parameters: Option<(
            crate::shortint::parameters::CompactPublicKeyEncryptionParameters,
            crate::shortint::parameters::ShortintKeySwitchingParameters,
        )>,
    ) -> Self {
        Self {
            block_parameters,
            wopbs_block_parameters,
            dedicated_compact_public_key_parameters,
        }
    }

    pub(in crate::high_level_api) fn default_big() -> Self {
        Self {
            block_parameters: crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS.into(),
            wopbs_block_parameters: None,
            dedicated_compact_public_key_parameters: None,
        }
    }

    pub(in crate::high_level_api) fn default_small() -> Self {
        Self {
            block_parameters: crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_PBS_KS.into(),
            wopbs_block_parameters: None,
            dedicated_compact_public_key_parameters: None,
        }
    }

    pub fn enable_wopbs(&mut self) {
        let wopbs_block_parameters = match self.block_parameters.encryption_key_choice() {
            EncryptionKeyChoice::Big => crate::shortint::parameters::parameters_wopbs_message_carry::WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            EncryptionKeyChoice::Small=> panic!("WOPBS only support KS_PBS parameters")
        };

        self.wopbs_block_parameters = Some(wopbs_block_parameters);
    }

    pub fn public_key_encryption_parameters(
        &self,
    ) -> Result<crate::shortint::parameters::CompactPublicKeyEncryptionParameters, crate::Error>
    {
        if let Some(p) = self.dedicated_compact_public_key_parameters {
            Ok(p.0)
        } else {
            Ok(self.block_parameters.try_into()?)
        }
    }
}

pub(crate) type CompactPrivateKey = (
    crate::integer::CompactPrivateKey<Vec<u64>>,
    crate::shortint::parameters::key_switching::ShortintKeySwitchingParameters,
);

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct IntegerClientKey {
    pub(crate) key: crate::integer::ClientKey,
    pub(crate) wopbs_block_parameters: Option<crate::shortint::WopbsParameters>,
    pub(crate) dedicated_compact_private_key: Option<CompactPrivateKey>,
}

impl IntegerClientKey {
    pub(crate) fn with_seed(config: IntegerConfig, seed: Seed) -> Self {
        assert!(
            (config.block_parameters.message_modulus().0) == 2 || config.block_parameters.message_modulus().0 == 4,
            "This API only supports parameters for which the MessageModulus is 2 or 4 (1 or 2 bits per block)",
        );
        let mut seeder = DeterministicSeeder::<ActivatedRandomGenerator>::new(seed);
        let cks = crate::shortint::engine::ShortintEngine::new_from_seeder(&mut seeder)
            .new_client_key(config.block_parameters.into());
        let key = crate::integer::ClientKey::from(cks);
        let dedicated_compact_private_key = config
            .dedicated_compact_public_key_parameters
            .map(|p| (crate::integer::CompactPrivateKey::new(p.0), p.1));
        Self {
            key,
            wopbs_block_parameters: config.wopbs_block_parameters,
            dedicated_compact_private_key,
        }
    }

    /// Deconstruct an [`IntegerClientKey`] into its constituents.
    pub fn into_raw_parts(
        self,
    ) -> (
        crate::integer::ClientKey,
        Option<crate::shortint::WopbsParameters>,
        Option<CompactPrivateKey>,
    ) {
        let Self {
            key,
            wopbs_block_parameters,
            dedicated_compact_private_key,
        } = self;
        (key, wopbs_block_parameters, dedicated_compact_private_key)
    }

    /// Construct a, [`IntegerClientKey`] from its constituents.
    ///
    /// # Panics
    ///
    /// Panics if the provided raw parts are not compatible with the provided parameters.
    pub fn from_raw_parts(
        key: crate::integer::ClientKey,
        wopbs_block_parameters: Option<crate::shortint::WopbsParameters>,
        dedicated_compact_private_key: Option<CompactPrivateKey>,
    ) -> Self {
        let shortint_cks: &crate::shortint::ClientKey = key.as_ref();
        if let Some(wop_params) = wopbs_block_parameters.as_ref() {
            assert_eq!(
                shortint_cks.parameters.message_modulus(),
                wop_params.message_modulus
            );
            assert_eq!(
                shortint_cks.parameters.carry_modulus(),
                wop_params.carry_modulus
            );
        }

        if let Some(dedicated_compact_private_key) = dedicated_compact_private_key.as_ref() {
            assert_eq!(
                shortint_cks.parameters.message_modulus(),
                dedicated_compact_private_key
                    .0
                    .key
                    .parameters()
                    .message_modulus,
            );
            assert_eq!(
                shortint_cks.parameters.carry_modulus(),
                dedicated_compact_private_key
                    .0
                    .key
                    .parameters()
                    .carry_modulus,
            );
        }

        Self {
            key,
            wopbs_block_parameters,
            dedicated_compact_private_key,
        }
    }

    pub(crate) fn block_parameters(&self) -> crate::shortint::parameters::PBSParameters {
        self.key.parameters()
    }
}

impl From<IntegerConfig> for IntegerClientKey {
    fn from(config: IntegerConfig) -> Self {
        assert!(
            (config.block_parameters.message_modulus().0) == 2 || config.block_parameters.message_modulus().0 == 4,
            "This API only supports parameters for which the MessageModulus is 2 or 4 (1 or 2 bits per block)",
        );
        let key = crate::integer::ClientKey::new(config.block_parameters);
        let dedicated_compact_private_key = config
            .dedicated_compact_public_key_parameters
            .map(|p| (crate::integer::CompactPrivateKey::new(p.0), p.1));
        Self {
            key,
            wopbs_block_parameters: config.wopbs_block_parameters,
            dedicated_compact_private_key,
        }
    }
}

pub(crate) type CastingKeyMaterial = (
    crate::core_crypto::entities::LweKeyswitchKeyOwned<u64>,
    i8,
    crate::shortint::EncryptionKeyChoice,
);

pub(crate) type CompressedCastingKeyMaterial = (
    crate::core_crypto::entities::SeededLweKeyswitchKeyOwned<u64>,
    i8,
    crate::shortint::EncryptionKeyChoice,
);

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct IntegerServerKey {
    pub(crate) key: crate::integer::ServerKey,
    pub(crate) wopbs_key: Option<crate::integer::wopbs::WopbsKey>,
    // Storing a KeySwitchingKeyView would require a self reference -> nightmare
    // Storing a KeySwitchingKey would mean cloning the ServerKey and means more memory traffic to
    // fetch the exact same key, so we store the part of the key that are not ServerKeys and we
    // will create views when required
    pub(crate) cpk_casting_key_material: Option<CastingKeyMaterial>,
}

impl IntegerServerKey {
    pub(in crate::high_level_api) fn new(client_key: &IntegerClientKey) -> Self {
        let cks = &client_key.key;
        let base_integer_key = crate::integer::ServerKey::new_radix_server_key(cks);
        let wopbs_key = client_key
            .wopbs_block_parameters
            .as_ref()
            .map(|wopbs_params| {
                crate::integer::wopbs::WopbsKey::new_wopbs_key(cks, &base_integer_key, wopbs_params)
            });
        let cpk_casting_key_material =
            client_key
                .dedicated_compact_private_key
                .as_ref()
                .map(|(private_key, ksk_params)| {
                    let build_helper =
                        crate::integer::key_switching_key::KeySwitchingKeyBuildHelper::new(
                            (private_key, None),
                            (cks, &base_integer_key),
                            *ksk_params,
                        );

                    (
                        build_helper.build_helper.key_switching_key,
                        build_helper.build_helper.cast_rshift,
                        build_helper.build_helper.destination_key,
                    )
                });
        Self {
            key: base_integer_key,
            wopbs_key,
            cpk_casting_key_material,
        }
    }

    pub(in crate::high_level_api) fn pbs_key(&self) -> &crate::integer::ServerKey {
        &self.key
    }

    pub(in crate::high_level_api) fn cpk_casting_key(
        &self,
    ) -> Option<crate::integer::key_switching_key::KeySwitchingKeyView> {
        if let Some((key_switching_key, cast_rshift, destination_key)) =
            &self.cpk_casting_key_material
        {
            Some(crate::integer::key_switching_key::KeySwitchingKeyView {
                key: crate::shortint::KeySwitchingKeyView::from_raw_parts(
                    key_switching_key,
                    self.key.as_ref(),
                    None,
                    *cast_rshift,
                    *destination_key,
                ),
            })
        } else {
            None
        }
    }

    pub(in crate::high_level_api) fn message_modulus(&self) -> MessageModulus {
        self.key.message_modulus()
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct IntegerCompressedServerKey {
    pub(crate) key: crate::integer::CompressedServerKey,
    pub(crate) cpk_casting_key_material: Option<CompressedCastingKeyMaterial>,
}

impl IntegerCompressedServerKey {
    pub(in crate::high_level_api) fn new(client_key: &IntegerClientKey) -> Self {
        let cks = &client_key.key;
        assert!(
            client_key.wopbs_block_parameters.is_none(),
            "The configuration used to create the ClientKey \
                   had function evaluation on integers enabled.
                   This feature requires an additional key that is not
                   compressible. Thus, It is not possible
                   to create a CompressedServerKey.
                   "
        );
        let key = crate::integer::CompressedServerKey::new_radix_compressed_server_key(cks);

        let cpk_casting_key_material =
            client_key
                .dedicated_compact_private_key
                .as_ref()
                .map(|(private_key, ksk_params)| {
                    let build_helper =
                    crate::integer::key_switching_key::CompressedKeySwitchingKeyBuildHelper::new(
                        (private_key, None),
                        (cks, &key),
                        *ksk_params,
                    );

                    (
                        build_helper.build_helper.key_switching_key,
                        build_helper.build_helper.cast_rshift,
                        build_helper.build_helper.destination_key,
                    )
                });

        Self {
            key,
            cpk_casting_key_material,
        }
    }

    pub fn into_raw_parts(
        self,
    ) -> (
        crate::integer::CompressedServerKey,
        Option<CompressedCastingKeyMaterial>,
    ) {
        (self.key, self.cpk_casting_key_material)
    }

    pub fn from_raw_parts(
        key: crate::integer::CompressedServerKey,
        cpk_casting_key_material: Option<CompressedCastingKeyMaterial>,
    ) -> Self {
        Self {
            key,
            cpk_casting_key_material,
        }
    }

    pub(in crate::high_level_api) fn decompress(&self) -> IntegerServerKey {
        IntegerServerKey {
            key: self.key.decompress(),
            wopbs_key: None,
            cpk_casting_key_material:
                self.cpk_casting_key_material.as_ref().map(
                    |(cksk, cast_rshift, destination_key)| {
                        (
                            {
                                let mut decompressed_ksk = LweKeyswitchKeyOwned::new(
                                    0u64,
                                    cksk.decomposition_base_log(),
                                    cksk.decomposition_level_count(),
                                    cksk.input_key_lwe_dimension(),
                                    cksk.output_key_lwe_dimension(),
                                    cksk.ciphertext_modulus(),
                                );
                                decompress_seeded_lwe_keyswitch_key::<
                                    _,
                                    _,
                                    _,
                                    ActivatedRandomGenerator,
                                >(&mut decompressed_ksk, cksk);
                                decompressed_ksk
                            },
                            *cast_rshift,
                            *destination_key,
                        )
                    },
                ),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(in crate::high_level_api) struct IntegerCompactPublicKey {
    pub(in crate::high_level_api) key: CompactPublicKey,
}

impl IntegerCompactPublicKey {
    pub(in crate::high_level_api) fn new(client_key: &IntegerClientKey) -> Self {
        Self::try_new(client_key).expect("Incompatible parameters")
    }

    pub(in crate::high_level_api) fn try_new(client_key: &IntegerClientKey) -> Result<Self, Error> {
        let key = match &client_key.dedicated_compact_private_key {
            Some(compact_private_key) => CompactPublicKey::try_new(&compact_private_key.0)?,
            None => CompactPublicKey::try_new(&client_key.key)?,
        };

        Ok(Self { key })
    }

    pub fn into_raw_parts(self) -> CompactPublicKey {
        self.key
    }

    pub fn from_raw_parts(key: CompactPublicKey) -> Self {
        Self { key }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(in crate::high_level_api) struct IntegerCompressedCompactPublicKey {
    pub(in crate::high_level_api) key: CompressedCompactPublicKey,
}

impl IntegerCompressedCompactPublicKey {
    pub(in crate::high_level_api) fn new(client_key: &IntegerClientKey) -> Self {
        Self::try_new(client_key).expect("Incompatible parameters")
    }

    pub(in crate::high_level_api) fn try_new(client_key: &IntegerClientKey) -> Result<Self, Error> {
        let key = match &client_key.dedicated_compact_private_key {
            Some(compact_private_key) => {
                CompressedCompactPublicKey::try_new(&compact_private_key.0)?
            }
            None => CompressedCompactPublicKey::try_new(&client_key.key)?,
        };

        Ok(Self { key })
    }

    /// Deconstruct a [`IntegerCompressedCompactPublicKey`] into its constituents.
    pub fn into_raw_parts(self) -> CompressedCompactPublicKey {
        self.key
    }

    /// Construct a [`IntegerCompressedCompactPublicKey`] from its constituents.
    pub fn from_raw_parts(key: CompressedCompactPublicKey) -> Self {
        Self { key }
    }

    pub(in crate::high_level_api) fn decompress(&self) -> IntegerCompactPublicKey {
        IntegerCompactPublicKey {
            key: CompressedCompactPublicKey::decompress(&self.key),
        }
    }
}
