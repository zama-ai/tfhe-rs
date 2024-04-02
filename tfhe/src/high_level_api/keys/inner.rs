use crate::core_crypto::commons::generators::DeterministicSeeder;
use crate::core_crypto::prelude::ActivatedRandomGenerator;
use crate::integer::ciphertext::CompactCiphertextList;
use crate::integer::public_key::CompactPublicKey;
use crate::integer::CompressedCompactPublicKey;
use crate::shortint::{EncryptionKeyChoice, MessageModulus};
use concrete_csprng::seeders::Seed;
use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct IntegerConfig {
    pub(crate) block_parameters: crate::shortint::PBSParameters,
    pub(crate) wopbs_block_parameters: Option<crate::shortint::WopbsParameters>,
}

impl IntegerConfig {
    pub(crate) fn new(
        block_parameters: crate::shortint::PBSParameters,
        wopbs_block_parameters: Option<crate::shortint::WopbsParameters>,
    ) -> Self {
        Self {
            block_parameters,
            wopbs_block_parameters,
        }
    }

    pub(in crate::high_level_api) fn default_big() -> Self {
        Self {
            block_parameters: crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS.into(),
            wopbs_block_parameters: None,
        }
    }

    pub(in crate::high_level_api) fn default_small() -> Self {
        Self {
            block_parameters: crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_PBS_KS.into(),
            wopbs_block_parameters: None,
        }
    }

    pub fn enable_wopbs(&mut self) {
        let wopbs_block_parameters = match self.block_parameters.encryption_key_choice() {
            EncryptionKeyChoice::Big => crate::shortint::parameters::parameters_wopbs_message_carry::WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            EncryptionKeyChoice::Small=> panic!("WOPBS only support KS_PBS parameters")
        };

        self.wopbs_block_parameters = Some(wopbs_block_parameters);
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct IntegerClientKey {
    pub(crate) key: crate::integer::ClientKey,
    pub(crate) wopbs_block_parameters: Option<crate::shortint::WopbsParameters>,
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
        Self {
            key,
            wopbs_block_parameters: config.wopbs_block_parameters,
        }
    }

    /// Deconstruct an [`IntegerClientKey`] into its constituents.
    pub fn into_raw_parts(
        self,
    ) -> (
        crate::integer::ClientKey,
        Option<crate::shortint::WopbsParameters>,
    ) {
        let Self {
            key,
            wopbs_block_parameters,
        } = self;
        (key, wopbs_block_parameters)
    }

    /// Construct a, [`IntegerClientKey`] from its constituents.
    ///
    /// # Panics
    ///
    /// Panics if the provided raw parts are not compatible with the provided parameters.
    pub fn from_raw_parts(
        key: crate::integer::ClientKey,
        wopbs_block_parameters: Option<crate::shortint::WopbsParameters>,
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

        Self {
            key,
            wopbs_block_parameters,
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
        Self {
            key,
            wopbs_block_parameters: config.wopbs_block_parameters,
        }
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct IntegerServerKey {
    pub(crate) key: crate::integer::ServerKey,
    pub(crate) wopbs_key: Option<crate::integer::wopbs::WopbsKey>,
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
        Self {
            key: base_integer_key,
            wopbs_key,
        }
    }

    pub(in crate::high_level_api) fn pbs_key(&self) -> &crate::integer::ServerKey {
        &self.key
    }

    pub(in crate::high_level_api) fn message_modulus(&self) -> MessageModulus {
        self.key.message_modulus()
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct IntegerCompressedServerKey {
    pub(crate) key: crate::integer::CompressedServerKey,
}

impl IntegerCompressedServerKey {
    pub(in crate::high_level_api) fn new(client_key: &IntegerClientKey) -> Self {
        let integer_key = &client_key.key;
        assert!(
            client_key.wopbs_block_parameters.is_none(),
            "The configuration used to create the ClientKey \
                   had function evaluation on integers enabled.
                   This feature requires an additional key that is not
                   compressible. Thus, It is not possible
                   to create a CompressedServerKey.
                   "
        );
        let key = crate::integer::CompressedServerKey::new_radix_compressed_server_key(integer_key);
        Self { key }
    }

    pub fn into_raw_parts(self) -> crate::integer::CompressedServerKey {
        self.key
    }

    pub fn from_raw_parts(key: crate::integer::CompressedServerKey) -> Self {
        Self { key }
    }

    pub(in crate::high_level_api) fn decompress(&self) -> IntegerServerKey {
        IntegerServerKey {
            key: self.key.decompress(),
            wopbs_key: None,
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

    pub(in crate::high_level_api) fn try_new(client_key: &IntegerClientKey) -> Option<Self> {
        let cks = &client_key.key;

        let key = CompactPublicKey::try_new(cks)?;

        Some(Self { key })
    }

    pub(in crate::high_level_api) fn try_encrypt_compact<T>(
        &self,
        values: &[T],
        num_blocks: usize,
    ) -> CompactCiphertextList
    where
        T: crate::integer::block_decomposition::DecomposableInto<u64>,
    {
        self.key.encrypt_slice_radix_compact(values, num_blocks)
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
        let cks = &client_key.key;

        let key = CompressedCompactPublicKey::new(cks);

        Self { key }
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
