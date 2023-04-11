#[cfg(feature = "boolean")]
use crate::typed_api::booleans::{BooleanConfig, FheBoolParameters};
#[cfg(feature = "integer")]
use crate::typed_api::integers::IntegerConfig;
#[cfg(feature = "shortint")]
use crate::typed_api::shortints::ShortIntConfig;

/// The config type
#[derive(Clone, Debug)]
pub struct Config {
    #[cfg(feature = "boolean")]
    pub(crate) boolean_config: BooleanConfig,
    #[cfg(feature = "integer")]
    pub(crate) integer_config: IntegerConfig,
    #[cfg(feature = "shortint")]
    pub(crate) shortint_config: ShortIntConfig,
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
                #[cfg(feature = "integer")]
                integer_config: IntegerConfig::all_default(),
                #[cfg(feature = "shortint")]
                shortint_config: ShortIntConfig::all_default(),
            },
        }
    }

    /// Create a new builder with all the data types disabled
    pub fn all_disabled() -> Self {
        Self {
            config: Config {
                #[cfg(feature = "boolean")]
                boolean_config: BooleanConfig::all_none(),
                #[cfg(feature = "integer")]
                integer_config: IntegerConfig::all_none(),
                #[cfg(feature = "shortint")]
                shortint_config: ShortIntConfig::all_none(),
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
    pub fn enable_default_uint8(mut self) -> Self {
        self.config.integer_config.uint8_params = Some(Default::default());
        self
    }

    #[cfg(feature = "integer")]
    pub fn enable_default_uint8_small(mut self) -> Self {
        let params = crate::typed_api::integers::FheUint8Parameters::small();
        self.config.integer_config.uint8_params = Some(params);
        self
    }

    #[cfg(feature = "integer")]
    pub fn disable_uint8(mut self) -> Self {
        self.config.integer_config.uint8_params = None;
        self
    }

    #[cfg(feature = "integer")]
    pub fn enable_default_uint10(mut self) -> Self {
        self.config.integer_config.uint10_params = Some(Default::default());
        self
    }

    #[cfg(feature = "integer")]
    pub fn enable_default_uint10_small(mut self) -> Self {
        let params = crate::typed_api::integers::FheUint10Parameters::small();
        self.config.integer_config.uint10_params = Some(params);
        self
    }

    #[cfg(feature = "integer")]
    pub fn disable_uint10(mut self) -> Self {
        self.config.integer_config.uint10_params = None;
        self
    }

    #[cfg(feature = "integer")]
    pub fn enable_default_uint12(mut self) -> Self {
        self.config.integer_config.uint12_params = Some(Default::default());
        self
    }

    #[cfg(feature = "integer")]
    pub fn enable_default_uint12_small(mut self) -> Self {
        let params = crate::typed_api::integers::FheUint12Parameters::small();
        self.config.integer_config.uint12_params = Some(params);
        self
    }

    #[cfg(feature = "integer")]
    pub fn disable_uint12(mut self) -> Self {
        self.config.integer_config.uint12_params = None;
        self
    }

    #[cfg(feature = "integer")]
    pub fn enable_default_uint14(mut self) -> Self {
        self.config.integer_config.uint14_params = Some(Default::default());
        self
    }

    #[cfg(feature = "integer")]
    pub fn enable_default_uint14_small(mut self) -> Self {
        let params = crate::typed_api::integers::FheUint14Parameters::small();
        self.config.integer_config.uint14_params = Some(params);
        self
    }

    #[cfg(feature = "integer")]
    pub fn disable_uint14(mut self) -> Self {
        self.config.integer_config.uint14_params = None;
        self
    }

    #[cfg(feature = "integer")]
    pub fn enable_default_uint16(mut self) -> Self {
        self.config.integer_config.uint16_params = Some(Default::default());
        self
    }

    #[cfg(feature = "integer")]
    pub fn enable_default_uint16_small(mut self) -> Self {
        let params = crate::typed_api::integers::FheUint16Parameters::small();
        self.config.integer_config.uint16_params = Some(params);
        self
    }

    #[cfg(feature = "integer")]
    pub fn disable_uint16(mut self) -> Self {
        self.config.integer_config.uint16_params = None;
        self
    }

    #[cfg(feature = "integer")]
    pub fn enable_default_uint32(mut self) -> Self {
        self.config.integer_config.uint32_params = Some(Default::default());
        self
    }

    #[cfg(feature = "integer")]
    pub fn enable_default_uint32_small(mut self) -> Self {
        let params = crate::typed_api::integers::FheUint32Parameters::small();
        self.config.integer_config.uint32_params = Some(params);
        self
    }

    #[cfg(feature = "integer")]
    pub fn enable_default_uint64(mut self) -> Self {
        self.config.integer_config.uint64_params = Some(Default::default());
        self
    }

    #[cfg(feature = "integer")]
    pub fn enable_default_uint64_small(mut self) -> Self {
        let params = crate::typed_api::integers::FheUint64Parameters::small();
        self.config.integer_config.uint64_params = Some(params);
        self
    }

    #[cfg(feature = "integer")]
    pub fn enable_default_uint128(mut self) -> Self {
        self.config.integer_config.uint128_params = Some(Default::default());
        self
    }

    #[cfg(feature = "integer")]
    pub fn enable_default_uint128_small(mut self) -> Self {
        let params = crate::typed_api::integers::FheUint128Parameters::small();
        self.config.integer_config.uint128_params = Some(params);
        self
    }

    #[cfg(feature = "integer")]
    pub fn enable_default_uint256(mut self) -> Self {
        self.config.integer_config.uint256_params = Some(Default::default());
        self
    }

    #[cfg(feature = "integer")]
    pub fn enable_default_uint256_small(mut self) -> Self {
        let params = crate::typed_api::integers::FheUint256Parameters::small();
        self.config.integer_config.uint256_params = Some(params);
        self
    }

    #[cfg(feature = "integer")]
    pub fn disable_uint256(mut self) -> Self {
        self.config.integer_config.uint256_params = None;
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
