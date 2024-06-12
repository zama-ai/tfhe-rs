use tfhe_versionable::Versionize;

use crate::backward_compatibility::config::ConfigVersions;
use crate::high_level_api::keys::IntegerConfig;
use crate::shortint::parameters::list_compression::CompressionParameters;

/// The config type
#[derive(Copy, Clone, Debug, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(ConfigVersions)]
pub struct Config {
    pub(crate) inner: IntegerConfig,
}

impl Config {
    pub fn public_key_encryption_parameters(
        &self,
    ) -> Result<crate::shortint::parameters::CompactPublicKeyEncryptionParameters, crate::Error>
    {
        self.inner.public_key_encryption_parameters()
    }
}

/// The builder to create your config
///
/// The configuration is needed to select parameters you wish to use for these types
/// (whether it is the default parameters or some custom parameters).
#[derive(Clone)]
pub struct ConfigBuilder {
    config: Config,
}

impl Default for ConfigBuilder {
    fn default() -> Self {
        Self::default_with_big_encryption()
    }
}

impl ConfigBuilder {
    #[doc(hidden)]
    pub fn enable_function_evaluation(mut self) -> Self {
        self.config.inner.enable_wopbs();
        self
    }

    pub fn enable_compression(mut self, compression_parameters: CompressionParameters) -> Self {
        self.config.inner.enable_compression(compression_parameters);

        self
    }

    /// Use default parameters with big encryption
    ///
    /// For more information see [crate::core_crypto::prelude::PBSOrder::KeyswitchBootstrap]
    pub fn default_with_big_encryption() -> Self {
        Self {
            config: Config {
                inner: IntegerConfig::default_big(),
            },
        }
    }

    /// Use default parameters with small encryption
    ///
    /// For more information see [crate::core_crypto::prelude::PBSOrder::BootstrapKeyswitch]
    pub fn default_with_small_encryption() -> Self {
        Self {
            config: Config {
                inner: IntegerConfig::default_small(),
            },
        }
    }

    pub fn with_custom_parameters<P>(
        block_parameters: P,
        wopbs_block_parameters: Option<crate::shortint::WopbsParameters>,
    ) -> Self
    where
        P: Into<crate::shortint::PBSParameters>,
    {
        Self {
            config: Config {
                inner: IntegerConfig::new(block_parameters.into(), wopbs_block_parameters, None),
            },
        }
    }

    pub fn use_dedicated_compact_public_key_parameters(
        mut self,
        dedicated_compact_public_key_parameters: (
            crate::shortint::parameters::CompactPublicKeyEncryptionParameters,
            crate::shortint::parameters::ShortintKeySwitchingParameters,
        ),
    ) -> Self {
        self.config.inner.dedicated_compact_public_key_parameters =
            Some(dedicated_compact_public_key_parameters);
        self
    }

    pub fn use_custom_parameters<P>(
        mut self,
        block_parameters: P,
        wopbs_block_parameters: Option<crate::shortint::WopbsParameters>,
    ) -> Self
    where
        P: Into<crate::shortint::PBSParameters>,
    {
        self.config.inner =
            IntegerConfig::new(block_parameters.into(), wopbs_block_parameters, None);
        self
    }

    pub fn build(self) -> Config {
        self.config
    }
}

impl From<ConfigBuilder> for Config {
    fn from(builder: ConfigBuilder) -> Self {
        builder.build()
    }
}
