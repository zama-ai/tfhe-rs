use concrete_csprng::seeders::Seed;
use serde::{Deserialize, Serialize};

use crate::core_crypto::commons::generators::DeterministicSeeder;
use crate::core_crypto::prelude::ActivatedRandomGenerator;
use crate::integer::ciphertext::{CompactCiphertextList, RadixCiphertext};
use crate::integer::public_key::CompactPublicKey;
use crate::integer::{CompressedCompactPublicKey, U256};
use crate::shortint::EncryptionKeyChoice;

#[derive(Copy, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct IntegerConfig {
    pub(crate) block_parameters: Option<crate::shortint::PBSParameters>,
    pub(crate) wopbs_block_parameters: Option<crate::shortint::WopbsParameters>,
}

impl IntegerConfig {
    pub(crate) fn new(
        block_parameters: Option<crate::shortint::PBSParameters>,
        wopbs_block_parameters: Option<crate::shortint::WopbsParameters>,
    ) -> Self {
        Self {
            block_parameters,
            wopbs_block_parameters,
        }
    }

    pub(in crate::high_level_api) fn all_default() -> Self {
        Self::default_big()
    }

    pub(in crate::high_level_api) fn all_none() -> Self {
        Self::new(None, None)
    }

    pub(in crate::high_level_api) fn default_big() -> Self {
        Self {
            block_parameters: Some(
                crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS.into(),
            ),
            wopbs_block_parameters: None,
        }
    }

    pub(in crate::high_level_api) fn default_small() -> Self {
        Self {
            block_parameters: Some(
                crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_PBS_KS.into(),
            ),
            wopbs_block_parameters: None,
        }
    }

    pub fn enable_wopbs(&mut self) {
        let block_parameter = self
            .block_parameters
            .get_or_insert(crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS.into());

        let wopbs_block_parameters = match block_parameter.encryption_key_choice() {
            EncryptionKeyChoice::Big => crate::shortint::parameters::parameters_wopbs_message_carry::WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            _ => panic!("WOPBS only support KS_PBS parameters")
        };

        self.wopbs_block_parameters = Some(wopbs_block_parameters);
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct IntegerClientKey {
    pub(crate) key: Option<crate::integer::ClientKey>,
    pub(crate) wopbs_block_parameters: Option<crate::shortint::WopbsParameters>,
}

impl IntegerClientKey {
    pub(crate) fn with_seed(config: IntegerConfig, seed: Seed) -> Self {
        let key = config.block_parameters.map(|params| {
            let mut seeder = DeterministicSeeder::<ActivatedRandomGenerator>::new(seed);
            let cks = crate::shortint::engine::ShortintEngine::new_from_seeder(&mut seeder)
                .new_client_key(params.into())
                .unwrap();
            crate::integer::ClientKey::from(cks)
        });
        Self {
            key,
            wopbs_block_parameters: config.wopbs_block_parameters,
        }
    }

    #[cfg(feature = "__wasm_api")]
    pub(crate) fn block_parameters(&self) -> Option<crate::shortint::parameters::PBSParameters> {
        self.key.as_ref().map(|key| key.parameters())
    }
}

impl From<IntegerConfig> for IntegerClientKey {
    fn from(config: IntegerConfig) -> Self {
        let key = match config.block_parameters {
            Some(params) => {
                let cks = crate::integer::ClientKey::new(params);
                Some(cks)
            }
            None => None,
        };
        Self {
            key,
            wopbs_block_parameters: config.wopbs_block_parameters,
        }
    }
}

#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct IntegerServerKey {
    pub(crate) key: Option<crate::integer::ServerKey>,
    pub(crate) wopbs_key: Option<crate::integer::wopbs::WopbsKey>,
}

impl IntegerServerKey {
    pub(in crate::high_level_api) fn new(client_key: &IntegerClientKey) -> Self {
        let Some(cks) = &client_key.key else {
            return Self::default();
        };
        let base_integer_key = crate::integer::ServerKey::new(cks);
        let wopbs_key = client_key
            .wopbs_block_parameters
            .as_ref()
            .map(|wopbs_params| {
                crate::integer::wopbs::WopbsKey::new_wopbs_key(cks, &base_integer_key, wopbs_params)
            });
        Self {
            key: Some(base_integer_key),
            wopbs_key,
        }
    }

    pub(in crate::high_level_api::integers) fn pbs_key(&self) -> &crate::integer::ServerKey {
        self.key
            .as_ref()
            .expect("Integer ServerKey is not initialized")
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct IntegerCompressedServerKey {
    pub(crate) key: Option<crate::integer::CompressedServerKey>,
}

impl IntegerCompressedServerKey {
    pub(in crate::high_level_api) fn new(client_key: &IntegerClientKey) -> Self {
        let Some(integer_key) = &client_key.key else {
            return Self {
                key: None,
            };
        };
        if client_key.wopbs_block_parameters.is_some() {
            panic!(
                "The configuration used to create the ClientKey \
                   had function evaluation on integers enabled.
                   This feature requires an additional key that is not
                   compressible. Thus, It is not possible
                   to create a CompressedServerKey.
                   "
            );
        }
        let key = crate::integer::CompressedServerKey::new(integer_key);
        Self { key: Some(key) }
    }

    pub(in crate::high_level_api) fn decompress(self) -> IntegerServerKey {
        IntegerServerKey {
            key: self.key.map(crate::integer::ServerKey::from),
            wopbs_key: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(in crate::high_level_api) struct IntegerCompactPublicKey {
    pub(in crate::high_level_api) key: Option<CompactPublicKey>,
}

impl IntegerCompactPublicKey {
    pub(in crate::high_level_api) fn new(client_key: &IntegerClientKey) -> Self {
        Self::try_new(client_key).expect("Incompatible parameters")
    }

    pub(in crate::high_level_api) fn try_new(client_key: &IntegerClientKey) -> Option<Self> {
        let Some(cks) = client_key.key.as_ref() else {
            return Some(Self {
                key: None,
            });
        };

        let key = CompactPublicKey::try_new(cks)?;

        Some(Self { key: Some(key) })
    }

    pub(in crate::high_level_api) fn try_encrypt<T>(
        &self,
        value: T,
        num_blocks: usize,
    ) -> Option<RadixCiphertext>
    where
        T: Into<U256>,
    {
        let Some(key) = self.key.as_ref() else {
            return None;
        };
        let value = value.into();
        let ct = key.encrypt_radix(value, num_blocks);
        Some(ct)
    }

    pub(in crate::high_level_api::integers) fn try_encrypt_compact<T>(
        &self,
        values: &[T],
        num_blocks: usize,
    ) -> Option<CompactCiphertextList>
    where
        T: crate::integer::block_decomposition::DecomposableInto<u64>,
    {
        let Some(key) = self.key.as_ref() else {
            return None;
        };
        let ct = key.encrypt_slice_radix_compact(values, num_blocks);
        Some(ct)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(in crate::high_level_api) struct IntegerCompressedCompactPublicKey {
    pub(in crate::high_level_api) key: Option<CompressedCompactPublicKey>,
}

impl IntegerCompressedCompactPublicKey {
    pub(in crate::high_level_api) fn new(client_key: &IntegerClientKey) -> Self {
        let Some(cks) = client_key.key.as_ref() else {
            return Self {
                key: None,
            };
        };

        let key = CompressedCompactPublicKey::new(cks);

        Self { key: Some(key) }
    }

    pub(in crate::high_level_api) fn decompress(self) -> IntegerCompactPublicKey {
        IntegerCompactPublicKey {
            key: self.key.map(CompressedCompactPublicKey::decompress),
        }
    }
}
