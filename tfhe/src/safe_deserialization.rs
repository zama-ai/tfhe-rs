use std::borrow::Cow;
use std::fmt::Display;

use crate::conformance::ParameterSetConformant;
use crate::named::Named;
use bincode::Options;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tfhe_versionable::{Unversionize, Versionize};

/// This is the global version of the serialization scheme that is used. This should be updated when
/// the SerializationHeader is updated.
const SERIALIZATION_VERSION: &str = "0.5";

/// This is the version of the versioning scheme used to add backward compatibibility on tfhe-rs
/// types. Similar to SERIALIZATION_VERSION, this number should be increased when the versioning
/// scheme is upgraded.
const VERSIONING_VERSION: &str = "0.1";

/// This is the current version of this crate. This is used to be able to reject unversioned data
/// if they come from a previous version.
const CRATE_VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION_MAJOR"),
    ".",
    env!("CARGO_PKG_VERSION_MINOR")
);

/// Tells if this serialized object is versioned or not
#[derive(Serialize, Deserialize, Copy, Clone, PartialEq, Eq)]
// This type should not be versioned because it is part of a wrapper of versioned messages.
#[cfg_attr(tfhe_lints, allow(tfhe_lints::serialize_without_versionize))]
enum SerializationVersioningMode {
    /// Serialize with type versioning for backward compatibility
    Versioned,
    /// Serialize the type without versioning information
    Unversioned,
}

impl Display for SerializationVersioningMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Versioned => write!(f, "versioned"),
            Self::Unversioned => write!(f, "unversioned"),
        }
    }
}

/// `HEADER_LENGTH_LIMIT` is the maximum `SerializationHeader` size which
/// `DeserializationConfig::deserialize_from` is going to try to read (it returns an error if
/// it's too big).
/// It helps prevent an attacker passing a very long header to exhaust memory.
const HEADER_LENGTH_LIMIT: u64 = 1000;

/// Header with global metadata about the serialized object. This help checking that we are not
/// deserializing data that we can't handle.
#[derive(Serialize, Deserialize)]
// This type should not be versioned because it is part of a wrapper of versioned messages.
#[cfg_attr(tfhe_lints, allow(tfhe_lints::serialize_without_versionize))]
struct SerializationHeader {
    header_version: Cow<'static, str>,
    versioning_mode: SerializationVersioningMode,
    versioning_version: Cow<'static, str>,
    name: Cow<'static, str>,
}

impl SerializationHeader {
    /// Creates a new header for a versioned message
    fn new_versioned<T: Named>() -> Self {
        Self {
            header_version: Cow::Borrowed(SERIALIZATION_VERSION),
            versioning_mode: SerializationVersioningMode::Versioned,
            versioning_version: Cow::Borrowed(VERSIONING_VERSION),
            name: Cow::Borrowed(T::NAME),
        }
    }

    /// Creates a new header for an unversioned message
    fn new_unversioned<T: Named>() -> Self {
        Self {
            header_version: Cow::Borrowed(SERIALIZATION_VERSION),
            versioning_mode: SerializationVersioningMode::Unversioned,
            versioning_version: Cow::Borrowed(CRATE_VERSION),
            name: Cow::Borrowed(T::NAME),
        }
    }

    /// Checks the validity of the header
    fn validate<T: Named>(&self) -> Result<(), String> {
        if self.versioning_mode == SerializationVersioningMode::Versioned {
            // For the moment there is only one versioning scheme, so another value is
            // a hard error. But maybe if we upgrade it we will be able to automatically convert
            // it.
            if self.versioning_version != VERSIONING_VERSION {
                return Err(format!(
                    "On deserialization, expected versioning scheme version {VERSIONING_VERSION}, \
got version {}",
                    self.versioning_version
                ));
            }
        } else if self.versioning_version != CRATE_VERSION {
            return Err(format!(
                "This {} has been saved from TFHE-rs v{}, without versioning informations. \
Please use the versioned serialization mode for backward compatibility.",
                self.name, self.versioning_version
            ));
        }

        if self.name != T::NAME {
            return Err(format!(
                "On deserialization, expected type {}, got type {}",
                T::NAME,
                self.name
            ));
        }

        Ok(())
    }
}

/// A configuration used to Serialize *TFHE-rs* objects. This configuration decides
/// if the object will be versioned and holds the max byte size of the written data.
#[derive(Copy, Clone)]
pub struct SerializationConfig {
    versioned: SerializationVersioningMode,
    serialized_size_limit: u64,
}

impl SerializationConfig {
    /// Creates a new serialization config. The default configuration will serialize the object
    /// with versioning information for backward compatibility.
    /// `serialized_size_limit` is the size limit (in number of byte) of the serialized object
    /// (excluding the header).
    pub fn new(serialized_size_limit: u64) -> Self {
        Self {
            versioned: SerializationVersioningMode::Versioned,
            serialized_size_limit,
        }
    }

    /// Creates a new serialization config without any size check.
    pub fn new_with_unlimited_size() -> Self {
        Self {
            versioned: SerializationVersioningMode::Versioned,
            serialized_size_limit: 0,
        }
    }

    /// Disables the size limit for serialized objects
    pub fn disable_size_limit(self) -> Self {
        Self {
            serialized_size_limit: 0,
            ..self
        }
    }

    /// Disable the versioning of serializd objects
    pub fn disable_versioning(self) -> Self {
        Self {
            versioned: SerializationVersioningMode::Unversioned,
            ..self
        }
    }

    /// Create a serialization header based on the current config
    fn create_header<T: Named>(&self) -> SerializationHeader {
        match self.versioned {
            SerializationVersioningMode::Versioned => SerializationHeader::new_versioned::<T>(),
            SerializationVersioningMode::Unversioned => SerializationHeader::new_unversioned::<T>(),
        }
    }

    /// Returns the max length of the serialized header
    fn header_length_limit(&self) -> u64 {
        if self.serialized_size_limit == 0 {
            0
        } else {
            HEADER_LENGTH_LIMIT
        }
    }

    /// Serializes an object into a [writer](std::io::Write), based on the current config.
    /// The written bytes can be deserialized using [`DeserializationConfig::deserialize_from`].
    pub fn serialize_into<T: Serialize + Versionize + Named>(
        self,
        object: &T,
        mut writer: impl std::io::Write,
    ) -> bincode::Result<()> {
        let options = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(0);

        let header = self.create_header::<T>();
        options
            .with_limit(self.header_length_limit())
            .serialize_into(&mut writer, &header)?;

        match self.versioned {
            SerializationVersioningMode::Versioned => options
                .with_limit(self.serialized_size_limit)
                .serialize_into(&mut writer, &object.versionize())?,
            SerializationVersioningMode::Unversioned => options
                .with_limit(self.serialized_size_limit)
                .serialize_into(&mut writer, &object)?,
        };

        Ok(())
    }
}

/// Tells if the deserialization should also check conformance.
#[derive(Copy, Clone)]
enum ConformanceMode<Params> {
    Checked(Params),
    Unchecked,
}

/// A configuration used to Serialize *TFHE-rs* objects. This configuration decides
/// the various sanity checks that will be performed during deserialization.
#[derive(Copy, Clone)]
pub struct DeserializationConfig<Params> {
    serialized_size_limit: u64,
    validate_header: bool,
    conformance: ConformanceMode<Params>,
}

impl<Params: Copy> DeserializationConfig<Params> {
    /// Creates a new deserialization config.
    /// By default, it will check that the serialization version and the name of the
    /// deserialized type are correct.
    /// `serialized_size_limit` is the size limit (in number of byte) of the serialized object
    /// (excluding version and name serialization).
    /// It will also check that the object is conformant with the parameter set given in
    /// `conformance_params`. Finally, it will check the compatibility of the loaded data with
    /// the current *TFHE-rs* version.
    pub fn new(serialized_size_limit: u64, conformance_params: &Params) -> Self {
        Self {
            serialized_size_limit,
            validate_header: true,
            conformance: ConformanceMode::Checked(*conformance_params),
        }
    }

    /// Creates a new config without any size limit for the deserialized objects.
    pub fn new_with_unlimited_size(conformance_params: &Params) -> Self {
        Self {
            serialized_size_limit: 0,
            validate_header: true,
            conformance: ConformanceMode::Checked(*conformance_params),
        }
    }

    /// Disables the size limit for the serialized objects.
    pub fn disable_size_limit(self) -> Self {
        Self {
            serialized_size_limit: 0,
            ..self
        }
    }

    /// Disables the header validation on the object. This header validations
    /// checks that the serialized object is the one that is supposed to be loaded
    /// and is compatible with this version of *TFHE-rs*.
    pub fn disable_header_validation(self) -> Self {
        Self {
            validate_header: false,
            ..self
        }
    }

    /// Creates a config with conformance checks disabled. The conformance is used
    /// to validate that the loaded object is compatible with the given parameters.
    pub fn new_without_conformance(serialized_size_limit: u64) -> Self {
        Self {
            serialized_size_limit,
            validate_header: true,
            conformance: ConformanceMode::Unchecked,
        }
    }

    /// Disables the conformance check on an existing config.
    pub fn disable_conformance_check(self) -> Self {
        Self {
            conformance: ConformanceMode::Unchecked,
            ..self
        }
    }

    /// Creates a new config without any sanity check.
    pub fn new_unsafe() -> Self {
        Self {
            serialized_size_limit: 0,
            validate_header: false,
            conformance: ConformanceMode::Unchecked,
        }
    }

    fn header_length_limit(&self) -> u64 {
        if self.serialized_size_limit == 0 {
            0
        } else {
            HEADER_LENGTH_LIMIT
        }
    }

    /// Deserializes an object serialized by [`SerializationConfig::serialize_into`] from a
    /// [reader](std::io::Read). Performs various sanity checks based on the deserialization config.
    pub fn deserialize_from<
        T: DeserializeOwned + Unversionize + Named + ParameterSetConformant<ParameterSet = Params>,
    >(
        self,
        mut reader: impl std::io::Read,
    ) -> Result<T, String> {
        let options = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(0);

        let deserialized_header: SerializationHeader = options
            .with_limit(self.header_length_limit())
            .deserialize_from(&mut reader)
            .map_err(|err| err.to_string())?;

        if self.validate_header {
            deserialized_header.validate::<T>()?;
        }

        let deser = if deserialized_header.versioning_mode == SerializationVersioningMode::Versioned
        {
            let deser_versioned = options
                .with_limit(self.serialized_size_limit - self.header_length_limit())
                .deserialize_from(&mut reader)
                .map_err(|err| err.to_string())?;

            T::unversionize(deser_versioned).map_err(|e| e.to_string())?
        } else {
            options
                .with_limit(self.serialized_size_limit - self.header_length_limit())
                .deserialize_from(&mut reader)
                .map_err(|err| err.to_string())?
        };

        if let ConformanceMode::Checked(parameter_set) = self.conformance {
            if !deser.is_conformant(&parameter_set) {
                return Err(format!(
                    "Deserialized object of type {} not conformant with given parameter set",
                    T::NAME
                ));
            }
        }

        Ok(deser)
    }
}

#[cfg(all(test, feature = "shortint"))]
mod test_shortint {
    use crate::safe_deserialization::{DeserializationConfig, SerializationConfig};
    use crate::shortint::parameters::{
        PARAM_MESSAGE_2_CARRY_2_KS_PBS, PARAM_MESSAGE_3_CARRY_3_KS_PBS,
    };
    use crate::shortint::{gen_keys, Ciphertext};

    #[test]
    fn safe_deserialization_ct() {
        let (ck, _sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);

        let msg = 2_u64;

        let ct = ck.encrypt(msg);

        let mut buffer = vec![];

        SerializationConfig::new(1 << 40)
            .disable_versioning()
            .serialize_into(&ct, &mut buffer)
            .unwrap();

        assert!(DeserializationConfig::new(
            1 << 20,
            &PARAM_MESSAGE_3_CARRY_3_KS_PBS.to_shortint_conformance_param()
        )
        .deserialize_from::<Ciphertext>(buffer.as_slice())
        .is_err());

        let ct2 = DeserializationConfig::new(
            1 << 20,
            &PARAM_MESSAGE_2_CARRY_2_KS_PBS.to_shortint_conformance_param(),
        )
        .deserialize_from::<Ciphertext>(buffer.as_slice())
        .unwrap();

        let dec = ck.decrypt(&ct2);
        assert_eq!(msg, dec);
    }

    #[test]
    fn safe_deserialization_ct_versioned() {
        let (ck, _sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);

        let msg = 2_u64;

        let ct = ck.encrypt(msg);

        let mut buffer = vec![];

        SerializationConfig::new(1 << 40)
            .serialize_into(&ct, &mut buffer)
            .unwrap();

        assert!(DeserializationConfig::new(
            1 << 20,
            &PARAM_MESSAGE_3_CARRY_3_KS_PBS.to_shortint_conformance_param()
        )
        .deserialize_from::<Ciphertext>(buffer.as_slice())
        .is_err());

        let ct2 = DeserializationConfig::new(
            1 << 20,
            &PARAM_MESSAGE_2_CARRY_2_KS_PBS.to_shortint_conformance_param(),
        )
        .deserialize_from::<Ciphertext>(buffer.as_slice())
        .unwrap();

        let dec = ck.decrypt(&ct2);
        assert_eq!(msg, dec);
    }
}

#[cfg(all(test, feature = "integer"))]
mod test_integer {
    use crate::conformance::ListSizeConstraint;
    use crate::high_level_api::{generate_keys, ConfigBuilder};
    use crate::prelude::*;
    use crate::safe_deserialization::{DeserializationConfig, SerializationConfig};
    use crate::shortint::parameters::{
        PARAM_MESSAGE_2_CARRY_2_KS_PBS, PARAM_MESSAGE_3_CARRY_3_KS_PBS,
    };
    use crate::{
        set_server_key, CompactCiphertextList, CompactCiphertextListConformanceParams,
        CompactPublicKey, FheUint8,
    };

    #[test]
    fn safe_deserialization_ct_list() {
        let (client_key, sks) = generate_keys(ConfigBuilder::default().build());
        set_server_key(sks);

        let public_key = CompactPublicKey::new(&client_key);

        let msg = [27u8, 10, 3];

        let ct_list = CompactCiphertextList::builder(&public_key)
            .push(27u8)
            .push(10u8)
            .push(3u8)
            .build();

        let mut buffer = vec![];

        SerializationConfig::new(1 << 40)
            .disable_versioning()
            .serialize_into(&ct_list, &mut buffer)
            .unwrap();

        let to_param_set = |list_size_constraint| CompactCiphertextListConformanceParams {
            shortint_params: PARAM_MESSAGE_2_CARRY_2_KS_PBS.to_shortint_conformance_param(),
            num_elements_constraint: list_size_constraint,
        };

        for param_set in [
            CompactCiphertextListConformanceParams {
                shortint_params: PARAM_MESSAGE_3_CARRY_3_KS_PBS.to_shortint_conformance_param(),
                num_elements_constraint: ListSizeConstraint::exact_size(3),
            },
            to_param_set(ListSizeConstraint::exact_size(2)),
            to_param_set(ListSizeConstraint::exact_size(4)),
            to_param_set(ListSizeConstraint::try_size_in_range(1, 2).unwrap()),
            to_param_set(ListSizeConstraint::try_size_in_range(4, 5).unwrap()),
        ] {
            assert!(DeserializationConfig::new(1 << 20, &param_set)
                .deserialize_from::<CompactCiphertextList>(buffer.as_slice())
                .is_err());
        }

        for len_constraint in [
            ListSizeConstraint::exact_size(3),
            ListSizeConstraint::try_size_in_range(2, 3).unwrap(),
            ListSizeConstraint::try_size_in_range(3, 4).unwrap(),
            ListSizeConstraint::try_size_in_range(2, 4).unwrap(),
        ] {
            let params = CompactCiphertextListConformanceParams {
                shortint_params: PARAM_MESSAGE_2_CARRY_2_KS_PBS.to_shortint_conformance_param(),
                num_elements_constraint: len_constraint,
            };
            assert!(DeserializationConfig::new(1 << 20, &params)
                .deserialize_from::<CompactCiphertextList>(buffer.as_slice())
                .is_ok());
        }

        let params = CompactCiphertextListConformanceParams {
            shortint_params: PARAM_MESSAGE_2_CARRY_2_KS_PBS.to_shortint_conformance_param(),
            num_elements_constraint: ListSizeConstraint::exact_size(3),
        };
        let ct2 = DeserializationConfig::new(1 << 20, &params)
            .deserialize_from::<CompactCiphertextList>(buffer.as_slice())
            .unwrap();

        let mut cts = Vec::with_capacity(3);
        let expander = ct2.expand().unwrap();
        for i in 0..3 {
            cts.push(expander.get::<FheUint8>(i).unwrap().unwrap());
        }

        let dec: Vec<u8> = cts.iter().map(|a| a.decrypt(&client_key)).collect();

        assert_eq!(&msg[..], &dec);
    }

    #[test]
    fn safe_deserialization_ct_list_versioned() {
        let (client_key, sks) = generate_keys(ConfigBuilder::default().build());
        set_server_key(sks);

        let public_key = CompactPublicKey::new(&client_key);

        let msg = [27u8, 10, 3];

        let ct_list = CompactCiphertextList::builder(&public_key)
            .push(27u8)
            .push(10u8)
            .push(3u8)
            .build();

        let mut buffer = vec![];

        SerializationConfig::new(1 << 40)
            .serialize_into(&ct_list, &mut buffer)
            .unwrap();

        let to_param_set = |list_size_constraint| CompactCiphertextListConformanceParams {
            shortint_params: PARAM_MESSAGE_2_CARRY_2_KS_PBS.to_shortint_conformance_param(),
            num_elements_constraint: list_size_constraint,
        };

        for param_set in [
            CompactCiphertextListConformanceParams {
                shortint_params: PARAM_MESSAGE_3_CARRY_3_KS_PBS.to_shortint_conformance_param(),
                num_elements_constraint: ListSizeConstraint::exact_size(3),
            },
            to_param_set(ListSizeConstraint::exact_size(2)),
            to_param_set(ListSizeConstraint::exact_size(4)),
            to_param_set(ListSizeConstraint::try_size_in_range(1, 2).unwrap()),
            to_param_set(ListSizeConstraint::try_size_in_range(4, 5).unwrap()),
        ] {
            assert!(DeserializationConfig::new(1 << 20, &param_set)
                .deserialize_from::<CompactCiphertextList>(buffer.as_slice())
                .is_err());
        }

        for len_constraint in [
            ListSizeConstraint::exact_size(3),
            ListSizeConstraint::try_size_in_range(2, 3).unwrap(),
            ListSizeConstraint::try_size_in_range(3, 4).unwrap(),
            ListSizeConstraint::try_size_in_range(2, 4).unwrap(),
        ] {
            let params = CompactCiphertextListConformanceParams {
                shortint_params: PARAM_MESSAGE_2_CARRY_2_KS_PBS.to_shortint_conformance_param(),
                num_elements_constraint: len_constraint,
            };
            assert!(DeserializationConfig::new(1 << 20, &params)
                .deserialize_from::<CompactCiphertextList>(buffer.as_slice())
                .is_ok());
        }

        let params = CompactCiphertextListConformanceParams {
            shortint_params: PARAM_MESSAGE_2_CARRY_2_KS_PBS.to_shortint_conformance_param(),
            num_elements_constraint: ListSizeConstraint::exact_size(3),
        };
        let ct2 = DeserializationConfig::new(1 << 20, &params)
            .deserialize_from::<CompactCiphertextList>(buffer.as_slice())
            .unwrap();

        let mut cts = Vec::with_capacity(3);
        let expander = ct2.expand().unwrap();
        for i in 0..3 {
            cts.push(expander.get::<FheUint8>(i).unwrap().unwrap());
        }

        let dec: Vec<u8> = cts.iter().map(|a| a.decrypt(&client_key)).collect();

        assert_eq!(&msg[..], &dec);
    }
}
