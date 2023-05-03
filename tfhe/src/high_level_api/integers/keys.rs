#[derive(Copy, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct IntegerConfig {
    pub(crate) block_parameters: crate::shortint::PBSParameters,
    pub(crate) wopbs_block_parameters: crate::shortint::WopbsParameters,
}

impl IntegerConfig {
    pub(crate) fn new(
        block_parameters: crate::shortint::PBSParameters,
        wopbs_block_parameters: crate::shortint::WopbsParameters,
    ) -> Self {
        Self {
            block_parameters,
            wopbs_block_parameters,
        }
    }

    pub(in crate::high_level_api) fn all_default() -> Self {
        Self::default_big()
    }

    pub(in crate::high_level_api) fn default_big() -> Self {
        Self {
            block_parameters: crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2,
            wopbs_block_parameters: crate::shortint::parameters::parameters_wopbs_message_carry::WOPBS_PARAM_MESSAGE_2_CARRY_2,
        }
    }

    pub(in crate::high_level_api) fn default_small() -> Self {
        Self {
            block_parameters: crate::shortint::parameters::PARAM_SMALL_MESSAGE_2_CARRY_2,
            wopbs_block_parameters: crate::shortint::parameters::parameters_wopbs_message_carry::WOPBS_PARAM_MESSAGE_2_CARRY_2,
        }
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct IntegerClientKey {
    pub(crate) key: crate::integer::ClientKey,
    // We need to keep the encryption_type and wopbs parameters
    // so its easier to keep the whole config
    pub(crate) config: IntegerConfig,
}

impl IntegerClientKey {
    pub(crate) fn encryption_type(&self) -> crate::shortint::EncryptionKeyChoice {
        self.config.block_parameters.encryption_key_choice
    }
}

impl From<IntegerConfig> for IntegerClientKey {
    fn from(config: IntegerConfig) -> Self {
        Self {
            key: crate::integer::ClientKey::new(config.block_parameters),
            config,
        }
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct IntegerServerKey {
    pub(crate) key: crate::integer::ServerKey,
    pub(crate) wopbs_key: crate::integer::wopbs::WopbsKey,
    // Needed to encrypt trivial ciphertexts
    pub(crate) encryption_type: crate::shortint::EncryptionKeyChoice,
}

impl IntegerServerKey {
    pub(in crate::high_level_api) fn new(client_key: &IntegerClientKey) -> Self {
        let base_integer_key = crate::integer::ServerKey::new(&client_key.key);
        let wopbs_key = crate::integer::wopbs::WopbsKey::new_wopbs_key(
            &client_key.key,
            &base_integer_key,
            &client_key.config.wopbs_block_parameters,
        );
        Self {
            key: base_integer_key,
            wopbs_key,
            encryption_type: client_key.config.block_parameters.encryption_key_choice,
        }
    }
}
