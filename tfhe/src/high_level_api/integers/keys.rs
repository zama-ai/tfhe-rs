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
