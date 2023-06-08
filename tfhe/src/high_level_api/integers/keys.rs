use concrete_csprng::seeders::Seed;
use serde::{Deserialize, Serialize};

use crate::core_crypto::commons::generators::DeterministicSeeder;
use crate::core_crypto::prelude::ActivatedRandomGenerator;
use crate::integer::U256;
use crate::shortint::EncryptionKeyChoice;

use super::server_key::RadixCiphertextDyn;
use super::types::compact::CompactCiphertextListDyn;

#[derive(Copy, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct IntegerConfig {
    pub(crate) block_parameters: Option<crate::shortint::ClassicPBSParameters>,
    pub(crate) wopbs_block_parameters: Option<crate::shortint::WopbsParameters>,
}

impl IntegerConfig {
    pub(crate) fn new(
        block_parameters: Option<crate::shortint::ClassicPBSParameters>,
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
            block_parameters: Some(crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2),
            wopbs_block_parameters: None,
        }
    }

    pub(in crate::high_level_api) fn default_small() -> Self {
        Self {
            block_parameters: Some(crate::shortint::parameters::PARAM_SMALL_MESSAGE_2_CARRY_2),
            wopbs_block_parameters: None,
        }
    }

    pub fn enable_wopbs(&mut self) {
        let block_parameter = self
            .block_parameters
            .get_or_insert(crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2);

        let wopbs_block_parameters = match block_parameter.encryption_key_choice {
            EncryptionKeyChoice::Big => crate::shortint::parameters::parameters_wopbs_message_carry::WOPBS_PARAM_MESSAGE_2_CARRY_2,
            EncryptionKeyChoice::Small => crate::shortint::parameters::parameters_wopbs_message_carry::WOPBS_PARAM_MESSAGE_2_CARRY_2,
        };

        self.wopbs_block_parameters = Some(wopbs_block_parameters);
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct IntegerClientKey {
    pub(crate) key: Option<crate::integer::ClientKey>,
    pub(crate) wopbs_block_parameters: Option<crate::shortint::WopbsParameters>,
    pub(crate) encryption_type: EncryptionKeyChoice,
}

impl IntegerClientKey {
    pub(crate) fn with_seed(config: IntegerConfig, seed: Seed) -> Self {
        let (key, encryption_type) = match config.block_parameters {
            Some(params) => {
                let encryption_type = params.encryption_key_choice;
                let mut seeder = DeterministicSeeder::<ActivatedRandomGenerator>::new(seed);
                let cks = crate::shortint::engine::ShortintEngine::new_from_seeder(&mut seeder)
                    .new_client_key(params.into())
                    .unwrap();
                let cks = crate::integer::ClientKey::from(cks);
                (Some(cks), encryption_type)
            }
            None => (None, EncryptionKeyChoice::Big),
        };
        Self {
            key,
            wopbs_block_parameters: config.wopbs_block_parameters,
            encryption_type,
        }
    }

    pub(crate) fn encryption_type(&self) -> EncryptionKeyChoice {
        self.encryption_type
    }
}

impl From<IntegerConfig> for IntegerClientKey {
    fn from(config: IntegerConfig) -> Self {
        let (key, encryption_type) = match config.block_parameters {
            Some(params) => {
                let encryption_type = params.encryption_key_choice;
                let cks = crate::integer::ClientKey::new(params);
                (Some(cks), encryption_type)
            }
            // setting a default value to encryption_type
            // when block parameters is none (ie integers not activated)
            // is fine, as since the key will be none, no risk of
            // mismatch
            None => (None, EncryptionKeyChoice::Big),
        };
        Self {
            key,
            wopbs_block_parameters: config.wopbs_block_parameters,
            encryption_type,
        }
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct IntegerServerKey {
    pub(crate) key: Option<crate::integer::ServerKey>,
    pub(crate) wopbs_key: Option<crate::integer::wopbs::WopbsKey>,
    // Needed to encrypt trivial ciphertexts
    pub(crate) encryption_type: crate::shortint::EncryptionKeyChoice,
}

impl Default for IntegerServerKey {
    fn default() -> Self {
        Self {
            encryption_type: EncryptionKeyChoice::Big,
            key: None,
            wopbs_key: None,
        }
    }
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
            encryption_type: client_key.encryption_type(),
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
    pub(crate) encryption_type: crate::shortint::EncryptionKeyChoice,
}

impl IntegerCompressedServerKey {
    pub(in crate::high_level_api) fn new(client_key: &IntegerClientKey) -> Self {
        let Some(integer_key) = &client_key.key else {
            return Self {
                key: None,
                encryption_type: EncryptionKeyChoice::Big,
            };
        };
        if client_key.wopbs_block_parameters.is_some() {
            panic!(
                "The configuration used to create the ClientKey \
                   had function evaluation on integers enabled.
                   This feature requires an additional that is not
                   compressible. Thus, It is not possible
                   to create a CompressedServerKey.
                   "
            );
        }
        let key = crate::integer::CompressedServerKey::new(integer_key);
        Self {
            key: Some(key),
            encryption_type: client_key.encryption_type(),
        }
    }

    pub(in crate::high_level_api) fn decompress(self) -> IntegerServerKey {
        IntegerServerKey {
            key: self.key.map(crate::integer::ServerKey::from),
            wopbs_key: None,
            encryption_type: self.encryption_type,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(in crate::high_level_api) enum CompactPublicKeyDyn {
    Big(crate::integer::CompactPublicKeyBig),
    Small(crate::integer::CompactPublicKeySmall),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(in crate::high_level_api) struct IntegerCompactPublicKey {
    pub(in crate::high_level_api) key: Option<CompactPublicKeyDyn>,
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

        let key = match client_key.encryption_type {
            crate::shortint::EncryptionKeyChoice::Big => {
                CompactPublicKeyDyn::Big(crate::integer::CompactPublicKeyBig::try_new(cks)?)
            }
            crate::shortint::EncryptionKeyChoice::Small => {
                CompactPublicKeyDyn::Small(crate::integer::CompactPublicKeySmall::try_new(cks)?)
            }
        };

        Some(Self { key: Some(key) })
    }

    pub(in crate::high_level_api) fn try_encrypt<T>(
        &self,
        value: T,
        num_blocks: usize,
    ) -> Option<RadixCiphertextDyn>
    where
        T: Into<U256>,
    {
        let Some(key) = self.key.as_ref() else {
            return None;
        };
        let value = value.into();
        let ct = match key {
            CompactPublicKeyDyn::Big(pk) => {
                RadixCiphertextDyn::Big(pk.encrypt_radix(value, num_blocks))
            }
            CompactPublicKeyDyn::Small(pk) => {
                RadixCiphertextDyn::Small(pk.encrypt_radix(value, num_blocks))
            }
        };
        Some(ct)
    }

    pub(in crate::high_level_api::integers) fn try_encrypt_compact<T>(
        &self,
        values: &[T],
        num_blocks: usize,
    ) -> Option<CompactCiphertextListDyn>
    where
        T: crate::integer::block_decomposition::DecomposableInto<u64>,
    {
        let Some(key) = self.key.as_ref() else {
            return None;
        };
        let ct = match key {
            CompactPublicKeyDyn::Big(pk) => {
                CompactCiphertextListDyn::Big(pk.encrypt_slice_radix_compact(values, num_blocks))
            }
            CompactPublicKeyDyn::Small(pk) => {
                CompactCiphertextListDyn::Small(pk.encrypt_slice_radix_compact(values, num_blocks))
            }
        };
        Some(ct)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(in crate::high_level_api) enum CompressedCompactPublicKeyDyn {
    Big(crate::integer::CompressedCompactPublicKeyBig),
    Small(crate::integer::CompressedCompactPublicKeySmall),
}

impl CompressedCompactPublicKeyDyn {
    fn decompress(self) -> CompactPublicKeyDyn {
        match self {
            CompressedCompactPublicKeyDyn::Big(big) => CompactPublicKeyDyn::Big(big.decompress()),
            CompressedCompactPublicKeyDyn::Small(small) => {
                CompactPublicKeyDyn::Small(small.decompress())
            }
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(in crate::high_level_api) struct IntegerCompressedCompactPublicKey {
    pub(in crate::high_level_api) key: Option<CompressedCompactPublicKeyDyn>,
}

impl IntegerCompressedCompactPublicKey {
    pub(in crate::high_level_api) fn new(client_key: &IntegerClientKey) -> Self {
        let Some(cks) = client_key.key.as_ref() else {
            return Self {
                key: None,
            };
        };

        let key = match client_key.encryption_type {
            crate::shortint::EncryptionKeyChoice::Big => CompressedCompactPublicKeyDyn::Big(
                crate::integer::CompressedCompactPublicKeyBig::new(cks),
            ),
            crate::shortint::EncryptionKeyChoice::Small => CompressedCompactPublicKeyDyn::Small(
                crate::integer::CompressedCompactPublicKeySmall::new(cks),
            ),
        };

        Self { key: Some(key) }
    }

    pub(in crate::high_level_api) fn decompress(self) -> IntegerCompactPublicKey {
        IntegerCompactPublicKey {
            key: self.key.map(CompressedCompactPublicKeyDyn::decompress),
        }
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct IntegerCastingKey {
    pub(crate) key: Option<crate::integer::CastingKey>,
}

impl IntegerCastingKey {
    pub(in crate::high_level_api) fn new(
        key_pair_1: (&IntegerClientKey, &IntegerServerKey),
        key_pair_2: (&IntegerClientKey, &IntegerServerKey),
    ) -> Self {
        Self {
            key: match (
                &key_pair_1.0.key,
                &key_pair_1.1.key,
                &key_pair_2.0.key,
                &key_pair_2.1.key,
            ) {
                (Some(ck1), Some(sk1), Some(ck2), Some(sk2)) => {
                    Some(crate::integer::CastingKey::new((ck1, sk1), (ck2, sk2)))
                }
                _ => None,
            },
        }
    }
}
