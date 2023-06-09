#[cfg(feature = "boolean")]
use crate::high_level_api::booleans::{BooleanConfig, FheBoolParameters};
#[cfg(feature = "integer")]
use crate::high_level_api::integers::IntegerConfig;
#[cfg(feature = "shortint")]
use crate::high_level_api::shortints::ShortIntConfig;

/// The config type
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Config {
    #[cfg(feature = "boolean")]
    pub(crate) boolean_config: BooleanConfig,
    #[cfg(feature = "shortint")]
    pub(crate) shortint_config: ShortIntConfig,
    #[cfg(feature = "integer")]
    pub(crate) integer_config: IntegerConfig,
}

/// The builder to create your config
///
/// This struct is what you will to use to build your
/// configuration.
///
/// # Why ?
///
/// The configuration is needed to select which types you are going to use or not
/// and which parameters you wish to use for these types (whether it is the default parameters or
/// some custom parameters).
///
/// To be able to configure a type, its "cargo feature kind" must be enabled (see the [table]).
///
/// The configuration is needed for the crate to be able to initialize and generate
/// all the needed client and server keys as well as other internal details.
///
/// As generating these keys and details for types that you are not going to use would be
/// a waste of time and space (both memory and disk if you serialize), generating a config is an
/// important step.
///
/// [table]: index.html#data-types
#[derive(Clone)]
pub struct ConfigBuilder {
    config: Config,
}

impl ConfigBuilder {
    /// Create a new builder with all the data types activated with their default parameters
    pub fn all_enabled() -> Self {
        Self {
            config: Config {
                #[cfg(feature = "boolean")]
                boolean_config: BooleanConfig::all_default(),
                #[cfg(feature = "shortint")]
                shortint_config: ShortIntConfig::all_default(),
                #[cfg(feature = "integer")]
                integer_config: IntegerConfig::all_default(),
            },
        }
    }

    /// Create a new builder with all the data types disabled
    pub fn all_disabled() -> Self {
        Self {
            config: Config {
                #[cfg(feature = "boolean")]
                boolean_config: BooleanConfig::all_none(),
                #[cfg(feature = "shortint")]
                shortint_config: ShortIntConfig::all_none(),
                #[cfg(feature = "integer")]
                integer_config: IntegerConfig::all_none(),
            },
        }
    }

    #[cfg(feature = "boolean")]
    pub fn enable_default_bool(mut self) -> Self {
        self.config.boolean_config.bool_params = Some(Default::default());
        self
    }

    #[cfg(feature = "boolean")]
    pub fn enable_custom_bool(mut self, params: FheBoolParameters) -> Self {
        self.config.boolean_config.bool_params = Some(params);
        self
    }

    #[cfg(feature = "boolean")]
    pub fn disable_bool(mut self) -> Self {
        self.config.boolean_config.bool_params = None;
        self
    }

    #[cfg(feature = "shortint")]
    pub fn enable_default_uint2(mut self) -> Self {
        self.config.shortint_config.uint2_params = Some(Default::default());
        self
    }

    #[cfg(feature = "shortint")]
    pub fn enable_default_uint3(mut self) -> Self {
        self.config.shortint_config.uint3_params = Some(Default::default());
        self
    }

    #[cfg(feature = "shortint")]
    pub fn enable_default_uint4(mut self) -> Self {
        self.config.shortint_config.uint4_params = Some(Default::default());
        self
    }

    #[cfg(feature = "integer")]
    pub fn enable_default_integers(mut self) -> Self {
        self.config.integer_config = IntegerConfig::default_big();
        self
    }

    #[cfg(feature = "integer")]
    pub fn enable_default_integers_small(mut self) -> Self {
        self.config.integer_config = IntegerConfig::default_small();
        self
    }

    #[doc(hidden)]
    #[cfg(feature = "integer")]
    pub fn enable_function_evaluation_integers(mut self) -> Self {
        self.config.integer_config.enable_wopbs();
        self
    }

    #[cfg(feature = "integer")]
    pub fn enable_custom_integers<P>(
        mut self,
        block_parameters: P,
        wopbs_block_parameters: Option<crate::shortint::WopbsParameters>,
    ) -> Self
    where
        P: Into<crate::shortint::PBSParameters>,
    {
        self.config.integer_config =
            IntegerConfig::new(Some(block_parameters.into()), wopbs_block_parameters);
        self
    }

    #[cfg(feature = "integer")]
    pub fn disable_integers(mut self) -> Self {
        self.config.integer_config = IntegerConfig::all_none();
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
